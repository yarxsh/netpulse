# NetPulse

A small terminal tool that pings a list of hosts and shows how they're doing in real time. Latency, packet loss, online/offline status, and a little sparkline graph for each host so you can see at a glance when something starts to go sideways.

I wanted something lighter than a full monitoring stack for those "is it my Wi-Fi or is it the internet?" moments, so this is just one Python file and a config.

<!-- Drop a screenshot here: ![NetPulse screenshot](screenshot.png) -->

## What it does

- Pings all hosts in parallel (asyncio), so one dead host doesn't freeze the rest
- Shows current, average, min and max latency, plus packet loss
- Status per host: ONLINE, UNSTABLE or OFFLINE
- A sparkline of recent history in every row (red `×` means a lost packet)
- ICMP ping or TCP connect time, chosen per host
- Keys: `q` quit, `p` pause, `r` reset stats

## Install

You need Python 3.9 or newer.

```bash
git clone https://github.com/yarxsh/netpulse.git
cd netpulse
pip install -r requirements.txt
```

That pulls in `rich` for the UI and `PyYAML` for the config file.

## Run

```bash
python netpulse.py
```

Use another config or change the interval:

```bash
python netpulse.py -c my-hosts.yaml -i 0.5
```

On Windows, if `python` isn't recognized, try `py netpulse.py`. The Windows Terminal app renders it much better than the old cmd window.

## Config

Everything lives in `config.yaml`:

```yaml
settings:
  interval: 1.0        # seconds between pings per host
  timeout: 2.0
  history: 180         # samples kept (about 3 min at 1s)
  sparkline_width: 40
  warn_ms: 100         # yellow above this
  crit_ms: 250         # red above this
  fail_threshold: 2    # lost pings in a row before OFFLINE

hosts:
  - name: Gateway
    address: auto      # tries to find your gateway (Linux only)
    method: icmp
  - name: Google DNS
    address: 8.8.8.8
    method: icmp
  - name: Web server
    address: example.com
    method: tcp
    port: 443
```

If there's no config file, it falls back to a short default list (gateway, 8.8.8.8, 1.1.1.1 and google.com over TCP).

## Good to know

- **ICMP uses the system `ping` command**, so no admin rights are needed. If `ping` isn't installed (some minimal Docker images), use `method: tcp` instead.
- **Gateway auto-detection only works on Linux.** On Windows or macOS, put your router's IP in the config by hand. On Windows, `ipconfig` shows it as "Default Gateway".
- If a host always shows OFFLINE but a normal `ping` works, check for a firewall in the way, or switch that host to TCP with a port you know is open.
- Average, loss and min/max are for the whole session. The sparkline only shows the last `history` samples. Press `r` to reset both.

## License

MIT, see [LICENSE](LICENSE).
