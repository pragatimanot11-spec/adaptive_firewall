# Adaptive Network Firewall

A single-computer academic prototype for a Computer Networks course. It decides
whether each packet should be **ALLOW**ed, **ALERT**ed or **BLOCK**ed by combining
static rules with per-host behaviour analysis.

> **BLOCK is a logged decision plus an entry in the prototype's temporary block
> list. It does NOT block packets at the operating-system level.**

## Overview

* Static IP / port / protocol rules (for example a blacklist).
* Per-host behavioural profiling with sliding time windows.
* Anomaly detection with moving averages and z-scores (no machine learning).
* Risk levels `LOW`, `MEDIUM`, `HIGH`; decisions `ALLOW`, `ALERT`, `BLOCK`.
* SQLite logging and a Streamlit dashboard.
* Synthetic traffic simulation by default. Scapy live capture is optional.

## Architecture

```
simulator.py --(packet dicts)--> firewall_engine.process_packet() --> database.py (SQLite)
                                                                  \--> app.py (Streamlit)
Optional: Scapy live capture --(packet dicts)--^
```

| File | Owner | Purpose |
|------|-------|---------|
| `simulator.py` | simulator/test developer | Deterministic synthetic traffic, six scenarios |
| `tests/` | simulator/test developer | pytest tests |
| `README.md`, `requirements.txt` | simulator/test developer | Docs and dependencies |
| `firewall_engine.py` | engine developer | Detection and decisions |
| `database.py` | database developer | SQLite logging |
| `app.py` | dashboard developer | Streamlit dashboard |

### Shared interface

A packet is a dict: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `flags`,
`size`, `timestamp`. The engine exposes `process_packet(packet: dict) -> dict`, which
returns the packet fields plus `action` (`ALLOW`/`ALERT`/`BLOCK`), `risk`
(`LOW`/`MEDIUM`/`HIGH`), `anomaly_score` and `reason`.

## Installation

Requires Python 3.9+ on Windows. No administrator rights are needed.

### Windows / VS Code setup

1. Install Python from python.org (tick "Add Python to PATH") and VS Code with the
   Microsoft *Python* extension.
2. Open the project folder in VS Code (File > Open Folder).
3. Open a terminal (Terminal > New Terminal, PowerShell) and run:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If activation is blocked, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
In VS Code press `Ctrl+Shift+P`, choose *Python: Select Interpreter*, pick `.venv`.

`simulator.py` uses only the standard library. Scapy is needed only for optional live
capture; Streamlit only for the dashboard.

## Run commands

```powershell
python simulator.py --list                              # show scenarios
python simulator.py --scenario port_scan                # preview packets only
python simulator.py --scenario all --run                # run all through the engine
python simulator.py --scenario traffic_spike --run --verbose
python simulator.py --scenario all --json               # raw packets as JSON
python simulator.py --scenario normal --seed 7
```

Scenarios: `normal`, `port_scan`, `traffic_spike`, `syn_attempts`, `blacklisted_ip`,
`unexpected_port`. Output is identical for the same `--seed`.

All traffic is synthetic Python dictionaries using private/loopback example addresses
(`192.168.1.x`, `10.66.66.66`). **No packet is ever sent on any network.**

## Test commands

```powershell
python -m pytest tests -v                      # everything
python -m pytest tests\test_simulator.py -v    # simulator only (no engine needed)
python -m pytest tests\test_engine_decisions.py -v
```

`tests/test_engine_decisions.py` calls only `firewall_engine.process_packet()`. It
fails (it is not skipped) if the engine cannot be imported.

## Demo instructions

1. `python simulator.py --scenario normal --run` shows mostly `ALLOW` / `LOW`.
2. `python simulator.py --scenario blacklisted_ip --run --verbose` shows `BLOCK` / `HIGH`
   from the first packet (static rule wins).
3. Run `port_scan`, `traffic_spike`, `syn_attempts` and `unexpected_port` the same way
   and compare the reasons.
4. `python simulator.py --scenario all --run`, then start the dashboard (if the
   dashboard developer provides it): `streamlit run app.py`.

## Integration assumptions

* The engine uses `packet["timestamp"]` (not the wall clock) for sliding windows.
* The engine's static blacklist contains `10.66.66.66` (override the simulator with
  the `FW_BLACKLISTED_IP` environment variable).
* Ports 80, 443 and 53 are expected; 31337, 4444 and 6667 are not.
* `protocol` is `"TCP"`/`"UDP"`/`"ICMP"`; TCP `flags` are short strings (`"S"`, `"A"`, `"PA"`).
* Tests use a distinct source IP per test; if the engine has a public `reset_state()`,
  `reset_engine()` or `reset()`, it is called before each test.
* Thresholds in the tests are deliberately loose (for example "some packet is ALERT or
  BLOCK"). If the engine's thresholds differ a lot, adjust scenario sizes in
  `simulator.py` rather than the engine.

## Limitations

* Prototype only: no real OS-level blocking, no packet reassembly, IPv4 focus.
* Simulated scenarios are simple and do not model real attacker behaviour.
* The "port scan" scenario probes many ports on one host (a vertical scan).
* Test outcomes depend on the engine's thresholds and conventions listed above.

## Future enhancements

* Optional Windows Firewall integration (separate, explicit, needs administrator rights).
* IPv6, more protocols, configurable rules file.
* More scenarios (slow scans, distributed sources, mixed traffic).
* Replay of recorded `.pcap` files offline.
