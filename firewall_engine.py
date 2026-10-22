"""
firewall_engine.py - Core decision engine for the Adaptive Network Firewall.

Standard library only. No Streamlit, no SQLite, no Scapy, no admin rights.

IMPORTANT: BLOCK is a *logged decision* plus an entry in this prototype's
temporary in-memory block list. Nothing here blocks packets at the operating
system level.

Shared contract
---------------
Input packet (dict):
    src_ip, dst_ip, src_port, dst_port, protocol, flags, size, timestamp

Output (dict) = every input field, plus exactly four new keys:
    action        : "ALLOW" | "ALERT" | "BLOCK"
    risk          : "LOW"   | "MEDIUM" | "HIGH"
    anomaly_score : float   (largest z-score-like value across the metrics;
                             0.0 when a static rule decided the packet)
    reason        : human-readable explanation

Decision order (first match wins)
---------------------------------
 1. Static rules  : blacklisted IP/CIDR, disallowed protocol, restricted port.
                    These ALWAYS override behaviour (BLOCK / HIGH).
 2. Temporary block list : source already blocked and not yet expired.
 3. Behavioural analysis : per-source-IP sliding window + adaptive baseline.

Behavioural metrics (per source IP, over the last `window_seconds`)
-------------------------------------------------------------------
    packet_rate    packets per second
    distinct_ports distinct destination ports (TCP/UDP)
    byte_rate      bytes per second
    syn_count      TCP SYN-only packets (SYN set, ACK not set)

Scoring
-------
 * Baseline: exponentially weighted moving average (EWMA) and variance per
   metric, per host.
 * z = (value - mean) / effective_std. effective_std is never smaller than a
   configured floor, so zero variance can never cause division by zero.
 * Until a host has `min_observations` baseline samples, z-scores are NOT
   trusted; only fixed hard limits are used ("learning mode").
 * Hard limits (alert/block) are converted to the same z-like scale so that
   alert limit == z_medium and block limit == z_high. The final per-metric
   score is the larger of the statistical and hard-limit scores.
 * Risk: score >= z_high -> HIGH, >= z_medium -> MEDIUM, else LOW.
 * Action: LOW -> ALLOW, MEDIUM -> ALERT, HIGH -> BLOCK (or ALERT if
   response.block_on_high is false).

Baseline contamination protection
---------------------------------
The baseline is updated only when the packet was judged LOW *and* its score is
below baseline.max_update_score, at most once per sample_interval_seconds, and
never from blocked hosts. Abnormal traffic therefore does not teach the
engine that "abnormal is normal". (Limitation: a very slow ramp-up that stays
under max_update_score can still drift the baseline slightly; the hard limits
are the safety net for that.)

Clock
-----
The engine uses packet timestamps as its clock (epoch seconds, ISO string, or
datetime), so simulated traffic is deterministic and can run faster than real
time. A missing/invalid timestamp falls back to time.time().

Public API
----------
    process_packet(packet)            -> dict   (module-level, default engine)
    FirewallEngine(config=None, config_path=None)
        .process_packet(packet)       -> dict
        .get_block_list(now=None)     -> list[dict]  active temporary blocks
        .is_blocked(ip, now=None)     -> bool
        .unblock(ip)                  -> bool
        .get_host_snapshot(ip)        -> dict | None  current window + baseline
        .reset()                      -> None  clear all state
    get_default_engine()              -> FirewallEngine
    configure(config=None, config_path=None) -> FirewallEngine  (replace default)
    get_block_list(now=None) / unblock(ip) / reset_engine()      (default engine)
    DEFAULT_CONFIG                    -> dict of all default settings
"""

from __future__ import annotations

import copy
import ipaddress
import json
import math
import re
import threading
import time
import warnings
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Constants shared with the other components
# --------------------------------------------------------------------------
ACTION_ALLOW = "ALLOW"
ACTION_ALERT = "ALERT"
ACTION_BLOCK = "BLOCK"

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

METRICS = ("packet_rate", "distinct_ports", "byte_rate", "syn_count")

_METRIC_LABELS = {
    "packet_rate": ("High packet rate", " pkts/s"),
    "distinct_ports": ("Many distinct destination ports (possible port scan)", " ports"),
    "byte_rate": ("High traffic volume", " bytes/s"),
    "syn_count": ("Repeated TCP SYN attempts (possible SYN flood/scan)", " SYNs"),
}

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().with_name("config.json")

# --------------------------------------------------------------------------
# Default configuration (every value can be overridden via config.json or a
# dict passed to FirewallEngine). Overrides are merged key by key.
# --------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "static_rules": {
        "blacklisted_ips": [],                      # IPs or CIDR, e.g. "10.9.9.0/24"
        "restricted_ports": [23, 135, 139, 445, 3389],   # destination ports
        "allowed_protocols": ["TCP", "UDP", "ICMP"],
    },
    "window_seconds": 10.0,                         # sliding window length
    "baseline": {
        "alpha": 0.1,                               # EWMA smoothing (0 < alpha <= 1)
        "min_observations": 20,                     # samples before z-scores are trusted
        "sample_interval_seconds": 1.0,             # max one baseline update per host per this
        "max_update_score": 2.0,                    # only learn from clearly normal samples
        "relative_min_std": 0.10,                   # std floor as a fraction of the mean
        "min_std": {                                # absolute std floors
            "packet_rate": 2.0,
            "distinct_ports": 2.0,
            "byte_rate": 2000.0,
            "syn_count": 2.0,
        },
    },
    "thresholds": {
        "z_medium": 3.0,                            # score >= this -> MEDIUM
        "z_high": 5.0,                              # score >= this -> HIGH
        "stat_min_values": {                        # z-scores ignored below these values
            "packet_rate": 10.0,
            "distinct_ports": 8.0,
            "byte_rate": 20000.0,
            "syn_count": 8.0,
        },
        "hard_limits": {                            # fixed limits (per window)
            "packet_rate": {"alert": 50.0, "block": 200.0},
            "distinct_ports": {"alert": 15.0, "block": 40.0},
            "byte_rate": {"alert": 200000.0, "block": 1000000.0},
            "syn_count": {"alert": 20.0, "block": 60.0},
        },
    },
    "response": {
        "block_on_high": True,                      # HIGH risk -> BLOCK (else ALERT)
        "block_duration_seconds": 60.0,             # temporary block list expiry
    },
    "housekeeping": {
        "host_idle_seconds": 3600.0,                # forget hosts idle this long
        "cleanup_every_packets": 1000,
    },
}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _deep_merge(base: dict, override: dict) -> dict:
    """Return base updated recursively with override (neither is mutated)."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _validate_config(cfg: dict) -> None:
    """Raise ValueError with a clear message if the configuration is unusable."""
    if not (_is_number(cfg["window_seconds"]) and cfg["window_seconds"] > 0):
        raise ValueError("window_seconds must be a positive number")

    b = cfg["baseline"]
    if not (_is_number(b["alpha"]) and 0 < b["alpha"] <= 1):
        raise ValueError("baseline.alpha must be in (0, 1]")
    if not (isinstance(b["min_observations"], int) and b["min_observations"] >= 1):
        raise ValueError("baseline.min_observations must be an integer >= 1")
    for key in ("sample_interval_seconds", "max_update_score", "relative_min_std"):
        if not (_is_number(b[key]) and b[key] >= 0):
            raise ValueError(f"baseline.{key} must be a number >= 0")

    t = cfg["thresholds"]
    if not (_is_number(t["z_medium"]) and _is_number(t["z_high"]) and 0 < t["z_medium"] < t["z_high"]):
        raise ValueError("thresholds must satisfy 0 < z_medium < z_high")

    for metric in METRICS:
        if not (_is_number(b["min_std"].get(metric)) and b["min_std"][metric] > 0):
            raise ValueError(f"baseline.min_std.{metric} must be a positive number")
        if not (_is_number(t["stat_min_values"].get(metric)) and t["stat_min_values"][metric] >= 0):
            raise ValueError(f"thresholds.stat_min_values.{metric} must be a number >= 0")
        limits = t["hard_limits"].get(metric, {})
        alert, block = limits.get("alert"), limits.get("block")
        if not (_is_number(alert) and _is_number(block) and 0 < alert < block):
            raise ValueError(f"thresholds.hard_limits.{metric} needs 0 < alert < block")

    r = cfg["response"]
    if not (_is_number(r["block_duration_seconds"]) and r["block_duration_seconds"] > 0):
        raise ValueError("response.block_duration_seconds must be a positive number")

    s = cfg["static_rules"]
    for key in ("blacklisted_ips", "restricted_ports", "allowed_protocols"):
        if not isinstance(s[key], list):
            raise ValueError(f"static_rules.{key} must be a list")


def _parse_timestamp(value) -> float:
    """Convert epoch seconds / numeric string / ISO string / datetime to epoch float."""
    try:
        if isinstance(value, bool):
            raise ValueError
        if isinstance(value, (int, float)):
            if math.isfinite(value):
                return float(value)
            raise ValueError
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, str):
            text = value.strip()
            try:
                return float(text)
            except ValueError:
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        else:
            raise ValueError
        if dt.tzinfo is None:
            return dt.timestamp()                    # naive -> local time
        return dt.astimezone(timezone.utc).timestamp()
    except (ValueError, OverflowError, OSError):
        return time.time()


def _to_port(value):
    """Return an int port 0..65535, or None (e.g. ICMP or missing)."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _to_size(value) -> int:
    try:
        return max(0, int(float(value)))
    except (TypeError, ValueError):
        return 0


def _is_syn_only(flags) -> bool:
    """True if the TCP flags have SYN set and ACK not set (a new connection attempt).

    Accepts "S", "SYN", "SA", "SYN-ACK", ["SYN", "ACK"], or an int bitmask.
    """
    if flags is None:
        return False
    if isinstance(flags, int) and not isinstance(flags, bool):
        return bool(flags & 0x02) and not (flags & 0x10)
    if isinstance(flags, (list, tuple, set, frozenset)):
        text = " ".join(str(f) for f in flags)
    else:
        text = str(flags)
    words = [w for w in re.split(r"[^A-Z]+", text.upper()) if w]
    named = {"SYN", "ACK", "FIN", "RST", "PSH", "URG"}
    if any(w in named for w in words):
        return "SYN" in words and "ACK" not in words
    letters = set("".join(words))                    # letter style: "S", "SA", "PA"
    return "S" in letters and "A" not in letters


def _limit_score(x: float, alert: float, block: float, z_med: float, z_high: float) -> float:
    """Map a raw value to the z-like scale using the fixed hard limits.

    x == alert -> z_med, x == block -> z_high, continuous and increasing.
    """
    if x <= 0:
        return 0.0
    if x < alert:
        return z_med * x / alert
    if x < block:
        return z_med + (z_high - z_med) * (x - alert) / (block - alert)
    return z_high * x / block


# --------------------------------------------------------------------------
# Per-host state
# --------------------------------------------------------------------------
class _HostState:
    """Sliding-window counters and adaptive baseline for one source IP."""

    def __init__(self) -> None:
        self.events = deque()            # (ts, dst_port or None, size, is_syn)
        self.port_counts = Counter()
        self.bytes_total = 0
        self.syn_total = 0
        self.last_seen = None
        self.last_sample_ts = None
        self.observations = 0
        self.mean = {m: 0.0 for m in METRICS}
        self.var = {m: 0.0 for m in METRICS}

    def add(self, ts, port, size, is_syn) -> None:
        self.events.append((ts, port, size, is_syn))
        if port is not None:
            self.port_counts[port] += 1
        self.bytes_total += size
        self.syn_total += 1 if is_syn else 0
        self.last_seen = ts

    def prune(self, now, window) -> None:
        cutoff = now - window
        while self.events and self.events[0][0] <= cutoff:
            _, port, size, is_syn = self.events.popleft()
            if port is not None:
                self.port_counts[port] -= 1
                if self.port_counts[port] <= 0:
                    del self.port_counts[port]
            self.bytes_total -= size
            self.syn_total -= 1 if is_syn else 0

    def clear_window(self) -> None:
        self.events.clear()
        self.port_counts.clear()
        self.bytes_total = 0
        self.syn_total = 0

    def metrics(self, window) -> dict:
        return {
            "packet_rate": len(self.events) / window,
            "distinct_ports": float(len(self.port_counts)),
            "byte_rate": self.bytes_total / window,
            "syn_count": float(self.syn_total),
        }

    def update_baseline(self, values: dict, alpha: float) -> None:
        """EWMA mean and variance (West / Finch recursive form)."""
        for m in METRICS:
            x = values[m]
            if self.observations == 0:
                self.mean[m], self.var[m] = x, 0.0
            else:
                diff = x - self.mean[m]
                incr = alpha * diff
                self.mean[m] += incr
                self.var[m] = (1.0 - alpha) * (self.var[m] + diff * incr)
        self.observations += 1


# --------------------------------------------------------------------------
# The engine
# --------------------------------------------------------------------------
class FirewallEngine:
    """Adaptive firewall decision engine. Thread-safe (one internal lock)."""

    def __init__(self, config: dict | None = None, config_path: str | Path | None = None) -> None:
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        if config_path is not None:
            with open(config_path, "r", encoding="utf-8") as fh:
                file_cfg = json.load(fh)
            if not isinstance(file_cfg, dict):
                raise ValueError("config file must contain a JSON object")
            cfg = _deep_merge(cfg, file_cfg)
        if config:
            cfg = _deep_merge(cfg, config)
        _validate_config(cfg)
        self.config = cfg

        rules = cfg["static_rules"]
        self._blacklist = [(str(e), ipaddress.ip_network(str(e).strip(), strict=False))
                           for e in rules["blacklisted_ips"]]       # ValueError if invalid
        self._restricted_ports = {int(p) for p in rules["restricted_ports"]}
        self._allowed_protocols = {str(p).upper() for p in rules["allowed_protocols"]}

        self._lock = threading.RLock()
        self.reset()

    # ----------------------------------------------------------- public API
    def reset(self) -> None:
        """Forget all hosts, baselines and blocks."""
        with getattr(self, "_lock", threading.RLock()):
            self._hosts: dict[str, _HostState] = {}
            self._blocks: dict[str, dict] = {}
            self._latest_ts = None
            self._packet_counter = 0

    def process_packet(self, packet: dict) -> dict:
        """Analyse one packet and return it with action/risk/anomaly_score/reason."""
        if not isinstance(packet, dict):
            raise TypeError("packet must be a dict")
        with self._lock:
            return self._process(packet)

    def get_block_list(self, now: float | None = None) -> list:
        """Active temporary blocks (a prototype list, NOT an OS firewall rule)."""
        with self._lock:
            now = self._now(now)
            self._expire_blocks(now)
            return [
                {
                    "ip": ip,
                    "reason": e["reason"],
                    "blocked_at": e["blocked_at"],
                    "expires_at": e["expires_at"],
                    "seconds_remaining": round(max(0.0, e["expires_at"] - now), 3),
                }
                for ip, e in self._blocks.items()
            ]

    def is_blocked(self, ip: str, now: float | None = None) -> bool:
        with self._lock:
            self._expire_blocks(self._now(now))
            return ip in self._blocks

    def unblock(self, ip: str) -> bool:
        """Remove an IP from the temporary block list. Returns True if it was there."""
        with self._lock:
            host = self._hosts.get(ip)
            if host:
                host.clear_window()
            return self._blocks.pop(ip, None) is not None

    def get_host_snapshot(self, ip: str) -> dict | None:
        """Current window metrics and baseline for a host (useful for debugging/UI)."""
        with self._lock:
            host = self._hosts.get(ip)
            if host is None:
                return None
            window = self.config["window_seconds"]
            if host.last_seen is not None:
                host.prune(host.last_seen, window)
            return {
                "observations": host.observations,
                "learning": host.observations < self.config["baseline"]["min_observations"],
                "window_metrics": host.metrics(window),
                "baseline_mean": dict(host.mean),
                "baseline_std": {m: math.sqrt(max(host.var[m], 0.0)) for m in METRICS},
            }

    # ------------------------------------------------------------- internals
    def _now(self, now):
        if now is not None:
            return float(now)
        return self._latest_ts if self._latest_ts is not None else time.time()

    @staticmethod
    def _finish(result: dict, action: str, risk: str, score: float, reason: str) -> dict:
        result["action"] = action
        result["risk"] = risk
        result["anomaly_score"] = round(float(score), 3)
        result["reason"] = reason
        return result

    def _expire_blocks(self, now: float) -> None:
        for ip in [ip for ip, e in self._blocks.items() if e["expires_at"] <= now]:
            del self._blocks[ip]
            host = self._hosts.get(ip)
            if host:
                host.clear_window()      # don't re-trigger on stale attack data

    def _blacklist_match(self, ip_text: str):
        try:
            addr = ipaddress.ip_address(ip_text)
        except ValueError:
            return None
        for label, network in self._blacklist:
            if addr.version == network.version and addr in network:
                return label
        return None

    def _process(self, packet: dict) -> dict:
        result = dict(packet)
        ts = _parse_timestamp(packet.get("timestamp"))
        src = str(packet.get("src_ip") or "").strip()
        dst = str(packet.get("dst_ip") or "").strip()
        if not src:
            return self._finish(result, ACTION_ALERT, RISK_MEDIUM, 0.0,
                                "Malformed packet: missing src_ip")

        proto = str(packet.get("protocol") or "").strip().upper()
        dst_port = _to_port(packet.get("dst_port"))
        size = _to_size(packet.get("size"))

        self._latest_ts = ts if self._latest_ts is None else max(self._latest_ts, ts)
        self._expire_blocks(ts)

        # ---- 1. Static rules (always override behaviour) -------------------
        hit = self._blacklist_match(src)
        if hit:
            return self._finish(result, ACTION_BLOCK, RISK_HIGH, 0.0,
                                f"Static rule: source IP {src} is blacklisted ({hit})")
        hit = self._blacklist_match(dst) if dst else None
        if hit:
            return self._finish(result, ACTION_BLOCK, RISK_HIGH, 0.0,
                                f"Static rule: destination IP {dst} is blacklisted ({hit})")
        if proto not in self._allowed_protocols:
            return self._finish(result, ACTION_BLOCK, RISK_HIGH, 0.0,
                                f"Static rule: protocol '{proto or 'unknown'}' is not allowed")
        if proto in ("TCP", "UDP") and dst_port in self._restricted_ports:
            return self._finish(result, ACTION_BLOCK, RISK_HIGH, 0.0,
                                f"Static rule: destination port {dst_port} is restricted")

        # ---- 2. Temporary block list --------------------------------------
        entry = self._blocks.get(src)
        if entry:
            remaining = entry["expires_at"] - ts
            return self._finish(
                result, ACTION_BLOCK, RISK_HIGH, entry["score"],
                f"Source {src} is on the temporary block list ({remaining:.0f}s left; "
                f"logged decision only, no OS-level blocking). Original reason: {entry['reason']}")

        # ---- 3. Behavioural analysis --------------------------------------
        cfg = self.config
        window = float(cfg["window_seconds"])
        host = self._hosts.get(src)
        if host is None:
            host = self._hosts[src] = _HostState()
        if host.last_seen is not None and ts < host.last_seen:
            ts = host.last_seen                       # tolerate out-of-order packets

        is_syn = proto == "TCP" and _is_syn_only(packet.get("flags"))
        port_for_stats = dst_port if proto in ("TCP", "UDP") else None
        host.add(ts, port_for_stats, size, is_syn)
        host.prune(ts, window)
        values = host.metrics(window)

        learning = host.observations < cfg["baseline"]["min_observations"]
        scores = self._score(host, values, learning)
        top_metric = max(scores, key=scores.get)
        top_score = scores[top_metric]

        z_med, z_high = cfg["thresholds"]["z_medium"], cfg["thresholds"]["z_high"]
        if top_score >= z_high:
            risk = RISK_HIGH
        elif top_score >= z_med:
            risk = RISK_MEDIUM
        else:
            risk = RISK_LOW

        if risk == RISK_HIGH and cfg["response"]["block_on_high"]:
            action = ACTION_BLOCK
        elif risk == RISK_LOW:
            action = ACTION_ALLOW
        else:
            action = ACTION_ALERT

        reason = self._explain(host, values, scores, risk, learning)

        if action == ACTION_BLOCK:
            duration = float(cfg["response"]["block_duration_seconds"])
            self._blocks[src] = {"reason": reason, "blocked_at": ts,
                                 "expires_at": ts + duration, "score": top_score}

        # Learn only from clearly normal samples (baseline contamination guard).
        base = cfg["baseline"]
        if (risk == RISK_LOW and top_score < base["max_update_score"]
                and (host.last_sample_ts is None
                     or ts - host.last_sample_ts >= base["sample_interval_seconds"])):
            host.update_baseline(values, base["alpha"])
            host.last_sample_ts = ts

        self._packet_counter += 1
        if self._packet_counter % int(cfg["housekeeping"]["cleanup_every_packets"]) == 0:
            self._evict_idle_hosts(ts)

        return self._finish(result, action, risk, top_score, reason)

    def _effective_std(self, host: _HostState, metric: str) -> float:
        base = self.config["baseline"]
        std = math.sqrt(max(host.var[metric], 0.0))
        floor = max(base["min_std"][metric], base["relative_min_std"] * abs(host.mean[metric]))
        return max(std, floor)               # always > 0 -> no divide-by-zero

    def _score(self, host: _HostState, values: dict, learning: bool) -> dict:
        t = self.config["thresholds"]
        scores = {}
        for m in METRICS:
            x = values[m]
            lim = t["hard_limits"][m]
            score = _limit_score(x, lim["alert"], lim["block"], t["z_medium"], t["z_high"])
            if not learning and x >= t["stat_min_values"][m]:
                z = (x - host.mean[m]) / self._effective_std(host, m)
                score = max(score, z)        # one-sided: only increases are suspicious
            scores[m] = max(0.0, score)
        return scores

    def _explain(self, host, values, scores, risk, learning) -> str:
        min_obs = self.config["baseline"]["min_observations"]
        if risk == RISK_LOW:
            if learning:
                return (f"Within fixed limits (baseline learning "
                        f"{host.observations}/{min_obs} samples)")
            return "Within learned baseline"

        z_med = self.config["thresholds"]["z_medium"]
        window = self.config["window_seconds"]
        triggered = sorted((m for m in METRICS if scores[m] >= z_med),
                           key=lambda m: scores[m], reverse=True)[:3]
        parts = []
        for m in triggered:
            label, unit = _METRIC_LABELS[m]
            text = f"{label}: {values[m]:.1f}{unit} in {window:g}s window (score {scores[m]:.1f}"
            if not learning:
                text += f", baseline avg {host.mean[m]:.1f}"
            parts.append(text + ")")
        suffix = " [learning mode: fixed limits only]" if learning else ""
        return "; ".join(parts) + suffix

    def _evict_idle_hosts(self, now: float) -> None:
        idle = float(self.config["housekeeping"]["host_idle_seconds"])
        stale = [ip for ip, h in self._hosts.items()
                 if h.last_seen is not None and now - h.last_seen > idle and ip not in self._blocks]
        for ip in stale:
            del self._hosts[ip]


# --------------------------------------------------------------------------
# Module-level convenience API (what the other components should call)
# --------------------------------------------------------------------------
_default_engine = None
_default_lock = threading.Lock()


def get_default_engine() -> FirewallEngine:
    """Shared engine. Reads config.json next to this file if it exists and is valid."""
    global _default_engine
    with _default_lock:
        if _default_engine is None:
            try:
                path = _DEFAULT_CONFIG_PATH if _DEFAULT_CONFIG_PATH.exists() else None
                _default_engine = FirewallEngine(config_path=path)
            except (OSError, ValueError) as exc:     # includes JSON errors
                warnings.warn(f"Could not use config.json ({exc}); using built-in defaults.")
                _default_engine = FirewallEngine()
        return _default_engine


def configure(config: dict | None = None, config_path: str | Path | None = None) -> FirewallEngine:
    """Replace the shared engine with a freshly configured one (state is reset)."""
    global _default_engine
    engine = FirewallEngine(config=config, config_path=config_path)
    with _default_lock:
        _default_engine = engine
    return engine


def process_packet(packet: dict) -> dict:
    """Shared-contract entry point. See module docstring."""
    return get_default_engine().process_packet(packet)


def get_block_list(now: float | None = None) -> list:
    return get_default_engine().get_block_list(now)


def unblock(ip: str) -> bool:
    return get_default_engine().unblock(ip)


def reset_engine() -> None:
    get_default_engine().reset()


# --------------------------------------------------------------------------
# Demo:  python firewall_engine.py        (purely local, synthetic packets)
# --------------------------------------------------------------------------
def _demo() -> None:
    engine = FirewallEngine()        # built-in defaults; ignores config.json
    t0 = 1_700_000_000.0

    def pkt(src, dport, t, flags="ACK", size=600, dst="10.0.0.5", proto="TCP"):
        return {"src_ip": src, "dst_ip": dst, "src_port": 40000, "dst_port": dport,
                "protocol": proto, "flags": flags, "size": size, "timestamp": t}

    def show(label, r):
        print(f"{label:<24} {r['action']:<5} {r['risk']:<6} score={r['anomaly_score']:<7} {r['reason']}")

    print("--- Normal traffic: 192.168.1.10 sends 2 packets/s for 60 s ---")
    r = None
    for i in range(120):
        r = engine.process_packet(pkt("192.168.1.10", 443, t0 + i * 0.5))
    show("normal (last packet)", r)

    print("\n--- Port scan (simulated locally): 192.168.1.66 SYNs to ports 1000-1059 ---")
    t = t0 + 61
    shown = set()
    for i, port in enumerate(range(1000, 1060)):
        r = engine.process_packet(pkt("192.168.1.66", port, t + i * 0.02, flags="S", size=60))
        if r["action"] not in shown:
            shown.add(r["action"])
            show(f"scan packet #{i + 1}", r)
    show("scan, after block", engine.process_packet(pkt("192.168.1.66", 80, t + 2.0)))

    print("\n--- Traffic burst from the trained host 192.168.1.10 ---")
    t = t0 + 61
    shown = set()
    for i in range(400):
        r = engine.process_packet(pkt("192.168.1.10", 443, t + i * 0.005, size=1200))
        if r["action"] not in shown:
            shown.add(r["action"])
            show(f"burst packet #{i + 1}", r)
    snap = engine.get_host_snapshot("192.168.1.10")
    print(f"baseline avg packet_rate stayed at {snap['baseline_mean']['packet_rate']:.2f} pkts/s "
          f"(burst did not contaminate it)")

    print("\n--- Static rules always win ---")
    show("restricted port 3389", engine.process_packet(pkt("192.168.1.20", 3389, t0 + 70)))
    show("disallowed protocol", engine.process_packet(pkt("192.168.1.20", 0, t0 + 70, proto="GRE")))

    print("\nTemporary block list (logged decisions only, not OS-level):")
    for entry in engine.get_block_list():
        print(f"  {entry['ip']}  expires in {entry['seconds_remaining']:.0f}s")


if __name__ == "__main__":
    _demo()
