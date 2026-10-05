#!/usr/bin/env python3
"""
yarxsh NetPulse Monitor
=======================
Интерактивный терминальный мониторинг сети и доступности хостов в реальном времени.

Автор / владелец: yarxsh

Возможности:
  * параллельный (asyncio) опрос хостов — интерфейс не зависает;
  * ICMP-пинг (через системную утилиту ping, root не нужен) и TCP-пинг;
  * текущий / средний / мин / макс пинг, процент потерь, статус с цветом;
  * мини-график (спарклайн) истории пинга прямо в таблице;
  * горячие клавиши: q — выход, p — пауза, r — сброс статистики.

Запуск:  python netpulse.py [-c config.yaml]
"""

from __future__ import annotations

import argparse
import asyncio
import math
import os
import re
import shutil
import socket
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

APP_TITLE = "yarxsh NetPulse Monitor"
AUTHOR = "yarxsh"

IS_WINDOWS = os.name == "nt"
SPARK_CHARS = "▁▂▃▄▅▆▇█"
LOST_CHAR = "×"

# ----------------------------------------------------------------------------
# Конфигурация
# ----------------------------------------------------------------------------

DEFAULT_SETTINGS = {
    "interval": 1.0,
    "timeout": 2.0,
    "history": 180,
    "sparkline_width": 40,
    "warn_ms": 100.0,
    "crit_ms": 250.0,
    "fail_threshold": 2,
}

DEFAULT_HOSTS = [
    {"name": "Gateway", "address": "auto", "method": "icmp"},
    {"name": "Google DNS", "address": "8.8.8.8", "method": "icmp"},
    {"name": "Cloudflare DNS", "address": "1.1.1.1", "method": "icmp"},
    {"name": "Google HTTPS", "address": "google.com", "method": "tcp", "port": 443},
]


def detect_gateway() -> Optional[str]:
    """Определяет шлюз по умолчанию (только Linux, через /proc/net/route)."""
    try:
        with open("/proc/net/route") as f:
            next(f)  # пропускаем заголовок
            for line in f:
                fields = line.split()
                # Destination == 0 и флаг RTF_GATEWAY (0x2)
                if fields[1] == "00000000" and int(fields[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except (OSError, StopIteration, ValueError, IndexError):
        pass
    return None


def load_config(path: Optional[str]) -> tuple[dict, list[dict]]:
    """Читает YAML-конфиг; если файла нет — используются значения по умолчанию."""
    settings = dict(DEFAULT_SETTINGS)
    hosts = list(DEFAULT_HOSTS)

    if path and os.path.exists(path):
        try:
            import yaml  # type: ignore
        except ImportError:
            sys.exit("Для чтения config.yaml установите PyYAML:  pip install pyyaml")
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        settings.update(data.get("settings") or {})
        hosts = data.get("hosts") or hosts
    elif path and path != "config.yaml":
        sys.exit(f"Файл конфигурации не найден: {path}")

    # Нормализация списка хостов
    normalized = []
    for h in hosts:
        if "address" not in h:
            sys.exit(f"В записи хоста нет поля 'address': {h}")
        addr = str(h["address"])
        if addr.lower() == "auto":
            addr = detect_gateway() or "192.168.1.1"
        method = str(h.get("method", "icmp")).lower()
        if method not in ("icmp", "tcp"):
            sys.exit(f"Неизвестный method '{method}' у хоста {addr} (допустимо: icmp, tcp)")
        normalized.append({
            "name": str(h.get("name", addr)),
            "address": addr,
            "method": method,
            "port": int(h.get("port", 443)),
        })
    return settings, normalized


# ----------------------------------------------------------------------------
# Пробы (ICMP / TCP)
# ----------------------------------------------------------------------------

_TIME_RE = re.compile(r"time\s*[=<]\s*([\d.,]+)\s*ms", re.IGNORECASE)


async def icmp_probe(address: str, timeout: float) -> Optional[float]:
    """Один ICMP-пинг через системную утилиту ping. Возвращает RTT в мс или None."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), address]
    elif sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), address]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout))), address]

    start = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout + 1.5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None
    except OSError:
        return None

    wall_ms = (time.perf_counter() - start) * 1000
    text = out.decode(errors="ignore")
    if proc.returncode != 0:
        return None
    # Windows возвращает код 0 даже при "Destination host unreachable" — ищем TTL
    if IS_WINDOWS and "TTL" not in text.upper():
        return None
    m = _TIME_RE.search(text)
    if m:
        return float(m.group(1).replace(",", "."))
    return wall_ms  # запасной вариант (например, локализованный вывод)


async def tcp_probe(address: str, port: int, timeout: float) -> Optional[float]:
    """TCP-пинг: время установки соединения в мс или None."""
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    rtt = (time.perf_counter() - start) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return rtt


# ----------------------------------------------------------------------------
# Статистика по хосту
# ----------------------------------------------------------------------------

@dataclass
class HostStats:
    name: str
    address: str
    method: str
    port: int
    history_size: int
    history: deque = field(init=False)
    sent: int = 0
    received: int = 0
    total_rtt: float = 0.0
    last: Optional[float] = None
    min_rtt: Optional[float] = None
    max_rtt: Optional[float] = None
    consecutive_fails: int = 0

    def __post_init__(self) -> None:
        self.history = deque(maxlen=self.history_size)  # None = потерянный пакет

    def reset(self) -> None:
        self.history.clear()
        self.sent = self.received = self.consecutive_fails = 0
        self.total_rtt = 0.0
        self.last = self.min_rtt = self.max_rtt = None

    def record(self, rtt: Optional[float]) -> None:
        """Добавляет результат одного замера."""
        self.sent += 1
        self.history.append(rtt)
        self.last = rtt
        if rtt is None:
            self.consecutive_fails += 1
            return
        self.consecutive_fails = 0
        self.received += 1
        self.total_rtt += rtt
        self.min_rtt = rtt if self.min_rtt is None else min(self.min_rtt, rtt)
        self.max_rtt = rtt if self.max_rtt is None else max(self.max_rtt, rtt)

    @property
    def avg(self) -> Optional[float]:
        return self.total_rtt / self.received if self.received else None

    @property
    def loss_pct(self) -> float:
        return (self.sent - self.received) / self.sent * 100 if self.sent else 0.0

    @property
    def target(self) -> str:
        return f"{self.address}:{self.port}" if self.method == "tcp" else self.address


# ----------------------------------------------------------------------------
# Состояние приложения и ввод с клавиатуры
# ----------------------------------------------------------------------------

class AppState:
    def __init__(self) -> None:
        self.paused = False
        self.reset_requested = False
        self.quit = asyncio.Event()
        self.started = time.monotonic()


def start_key_listener(state: AppState, loop: asyncio.AbstractEventLoop):
    """Запускает поток чтения клавиш (q / p / r). Возвращает (thread, stop_event)."""
    stop = threading.Event()
    if not sys.stdin.isatty():
        return None, stop

    def handle(ch: str) -> None:
        ch = ch.lower()
        if ch in ("q", "й", "\x03"):          # q / й (рус. раскладка) / Ctrl+C
            loop.call_soon_threadsafe(state.quit.set)
        elif ch in ("p", "з"):
            state.paused = not state.paused
        elif ch in ("r", "к"):
            state.reset_requested = True

    def worker_windows() -> None:
        import msvcrt
        while not stop.is_set():
            if msvcrt.kbhit():
                handle(msvcrt.getwch())
            else:
                time.sleep(0.05)

    def worker_unix() -> None:
        import select
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)  # читаем символы без Enter
            while not stop.is_set():
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    handle(sys.stdin.read(1))
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)  # возвращаем терминал в норму

    thread = threading.Thread(target=worker_windows if IS_WINDOWS else worker_unix, daemon=True)
    thread.start()
    return thread, stop


# ----------------------------------------------------------------------------
# Опрос хостов
# ----------------------------------------------------------------------------

async def poll_host(stats: HostStats, state: AppState, interval: float, timeout: float) -> None:
    """Бесконечный цикл опроса одного хоста (каждый хост — отдельная задача)."""
    while True:
        if state.paused:
            await asyncio.sleep(0.2)
            continue
        t0 = time.monotonic()
        if stats.method == "tcp":
            rtt = await tcp_probe(stats.address, stats.port, timeout)
        else:
            rtt = await icmp_probe(stats.address, timeout)
        if not state.paused:
            stats.record(rtt)
        await asyncio.sleep(max(0.05, interval - (time.monotonic() - t0)))


# ----------------------------------------------------------------------------
# Отрисовка
# ----------------------------------------------------------------------------

class Renderer:
    def __init__(self, console: Console, hosts: list[HostStats], state: AppState, cfg: dict) -> None:
        self.console, self.hosts, self.state, self.cfg = console, hosts, state, cfg

    # --- цвета и статусы -----------------------------------------------------

    def latency_color(self, ms: Optional[float]) -> str:
        if ms is None:
            return "red"
        if ms < self.cfg["warn_ms"]:
            return "green"
        if ms < self.cfg["crit_ms"]:
            return "yellow"
        return "red"

    def status_of(self, h: HostStats) -> Text:
        if h.sent == 0:
            return Text("◌ PENDING", style="dim")
        if h.consecutive_fails >= self.cfg["fail_threshold"]:
            return Text("● OFFLINE", style="bold white on red")
        recent = list(h.history)[-10:]
        recent_loss = recent.count(None) / len(recent) * 100
        if h.consecutive_fails > 0 or recent_loss >= 20 or (h.last or 0) >= self.cfg["crit_ms"]:
            return Text("● UNSTABLE", style="bold black on yellow")
        return Text("● ONLINE", style="bold black on green")

    # --- спарклайн -----------------------------------------------------------

    def sparkline(self, values: list[Optional[float]], width: int) -> Text:
        """Мини-график: высота символа — пинг, цвет — порог, красный × — потеря."""
        if len(values) > width:  # сжимаем историю в `width` корзин (среднее по корзине)
            n = len(values)
            buckets = []
            for i in range(width):
                chunk = [v for v in values[i * n // width:(i + 1) * n // width] if v is not None]
                buckets.append(sum(chunk) / len(chunk) if chunk else None)
            values = buckets

        ok = [v for v in values if v is not None]
        text = Text(" " * (width - len(values)))  # график "растёт" справа налево
        if not ok:
            text.append(LOST_CHAR * len(values), style="red")
            return text
        lo, hi = min(ok), max(ok)
        span = max(hi - lo, 5.0)  # минимум 5 мс, чтобы мелкий джиттер не раздувался
        for v in values:
            if v is None:
                text.append(LOST_CHAR, style="bold red")
            else:
                idx = min(len(SPARK_CHARS) - 1, int((v - lo) / span * (len(SPARK_CHARS) - 1)))
                text.append(SPARK_CHARS[idx], style=self.latency_color(v))
        return text

    # --- блоки интерфейса ----------------------------------------------------

    def header(self) -> Panel:
        title = Text(justify="center")
        title.append("◉ ", style="bold green")
        title.append(APP_TITLE, style="bold bright_cyan")
        sub = Text(justify="center", style="dim")
        up = int(time.monotonic() - self.state.started)
        sub.append(f"by {AUTHOR}  •  {time.strftime('%Y-%m-%d %H:%M:%S')}  •  "
                   f"аптайм {up // 3600:02d}:{up % 3600 // 60:02d}:{up % 60:02d}")
        if self.state.paused:
            sub.append("  •  ПАУЗА", style="bold yellow")
        return Panel(Group(Align.center(title), Align.center(sub)),
                     border_style="cyan", title=f"[bold]{AUTHOR}[/] · NetPulse")

    def summary(self) -> Text:
        total = len(self.hosts)
        online = sum(1 for h in self.hosts
                     if h.sent and h.consecutive_fails < self.cfg["fail_threshold"])
        sent = sum(h.sent for h in self.hosts)
        lost = sum(h.sent - h.received for h in self.hosts)
        avgs = [h.avg for h in self.hosts if h.avg is not None]

        bar_w = 24
        filled = round(bar_w * online / total) if total else 0
        color = "green" if online == total else ("yellow" if online else "red")

        t = Text("  Доступность  ")
        t.append("█" * filled, style=color)
        t.append("░" * (bar_w - filled), style="grey37")
        t.append(f"  {online}/{total} онлайн", style=f"bold {color}")
        t.append("   │   Средний пинг: ")
        t.append(f"{sum(avgs) / len(avgs):.1f} мс" if avgs else "—", style="bold")
        t.append("   │   Потери: ")
        loss = lost / sent * 100 if sent else 0
        t.append(f"{loss:.1f}%", style="bold green" if loss < 1 else "bold red")
        return t

    def table(self) -> Table:
        # Ширина графика подстраивается под ширину терминала
        spark_w = max(10, min(self.cfg["sparkline_width"], self.console.width - 100))

        table = Table(expand=False, header_style="bold bright_white",
                      border_style="grey50", row_styles=["", "on grey11"])
        table.add_column("Хост", min_width=22, no_wrap=True)
        table.add_column("Метод", justify="center")
        table.add_column("Статус", justify="center")
        table.add_column("Сейчас", justify="right")
        table.add_column("Средний", justify="right")
        table.add_column("Мин / Макс", justify="right")
        table.add_column("Потери", justify="right")
        table.add_column("История пинга", no_wrap=True)

        for h in self.hosts:
            name = Text(h.name, style="bold")
            name.append(f"\n{h.target}", style="dim")

            now = Text("—" if h.last is None else f"{h.last:.1f} мс", style=self.latency_color(h.last))
            if h.sent == 0:
                now = Text("…", style="dim")
            avg = Text("—" if h.avg is None else f"{h.avg:.1f} мс",
                       style=self.latency_color(h.avg) if h.avg is not None else "dim")
            mm = Text("—" if h.min_rtt is None else f"{h.min_rtt:.0f} / {h.max_rtt:.0f} мс", style="cyan")
            loss = Text(f"{h.loss_pct:.1f}%",
                        style="green" if h.loss_pct == 0 else ("yellow" if h.loss_pct < 5 else "bold red"))
            method = Text(h.method.upper(), style="magenta")

            table.add_row(name, method, self.status_of(h), now, avg, mm, loss,
                          self.sparkline(list(h.history), spark_w))
        return table

    def footer(self) -> Text:
        t = Text(justify="center", style="dim")
        t.append("[q]", style="bold").append(" выход   ")
        t.append("[p]", style="bold").append(" пауза   ")
        t.append("[r]", style="bold").append(" сброс статистики   ")
        t.append("│  ").append("▁▂▃▅▇", style="green")
        t.append(f" < {self.cfg['warn_ms']:.0f} мс  ")
        t.append("▅▆", style="yellow").append(f" < {self.cfg['crit_ms']:.0f} мс  ")
        t.append("▇", style="red").append(" выше  ")
        t.append(LOST_CHAR, style="bold red").append(" потеря")
        return t

    def __rich__(self) -> Group:
        return Group(self.header(), self.summary(), self.table(), Align.center(self.footer()))


# ----------------------------------------------------------------------------
# Точка входа
# ----------------------------------------------------------------------------

async def main_async(settings: dict, host_cfgs: list[dict]) -> None:
    console = Console()
    state = AppState()
    loop = asyncio.get_running_loop()

    hosts = [HostStats(h["name"], h["address"], h["method"], h["port"], int(settings["history"]))
             for h in host_cfgs]
    renderer = Renderer(console, hosts, state, settings)

    tasks = [asyncio.create_task(poll_host(h, state, float(settings["interval"]),
                                           float(settings["timeout"]))) for h in hosts]
    thread, stop = start_key_listener(state, loop)

    try:
        with Live(renderer, console=console, screen=True, auto_refresh=False) as live:
            while not state.quit.is_set():
                if state.reset_requested:
                    state.reset_requested = False
                    for h in hosts:
                        h.reset()
                live.update(renderer, refresh=True)
                try:
                    await asyncio.wait_for(state.quit.wait(), timeout=0.25)
                except asyncio.TimeoutError:
                    pass
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        stop.set()
        if thread:
            thread.join(timeout=1)  # поток вернёт настройки терминала


def main() -> None:
    parser = argparse.ArgumentParser(description=f"{APP_TITLE} — мониторинг сети в терминале")
    parser.add_argument("-c", "--config", default="config.yaml", help="путь к YAML-конфигу")
    parser.add_argument("-i", "--interval", type=float, help="интервал опроса, сек (перекрывает конфиг)")
    args = parser.parse_args()

    settings, hosts = load_config(args.config)
    if args.interval:
        settings["interval"] = args.interval

    if any(h["method"] == "icmp" for h in hosts) and not shutil.which("ping"):
        sys.exit("Утилита 'ping' не найдена. Установите её или используйте method: tcp в конфиге.")

    try:
        asyncio.run(main_async(settings, hosts))
    except KeyboardInterrupt:
        pass
    print(f"{APP_TITLE} завершён. До встречи! — {AUTHOR}")


if __name__ == "__main__":
    main()
