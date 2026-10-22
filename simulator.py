"""
simulator.py - Deterministic synthetic traffic for the Adaptive Network Firewall.

Everything here is SYNTHETIC. No sockets are opened and nothing is ever sent
on a network. Each "packet" is just a Python dictionary that follows the shared
interface:

    src_ip, dst_ip, src_port, dst_port, protocol, flags, size, timestamp

Only the standard library is used, and no administrator rights are needed.

Examples (Windows, from the project folder):
    python simulator.py --list
    python simulator.py --scenario port_scan
    python simulator.py --scenario all --run
    python simulator.py --scenario traffic_spike --run --verbose
"""

import argparse
import json
import os
import random
import sys
from collections import Counter

# --------------------------------------------------------------------------
# Constants (all addresses are loopback/private example addresses)
# --------------------------------------------------------------------------
DEFAULT_SEED = 42
BASE_TIMESTAMP = 1_700_000_000.0   # fixed start time -> deterministic output
SCENARIO_GAP = 120.0               # seconds of silence between scenarios in "all"

SERVER_IP = "192.168.1.100"        # the pretend protected server
# The static blacklist lives in the engine. This simulator assumes the engine
# blacklists this address. Override with the FW_BLACKLISTED_IP environment
# variable if your engine uses a different one.
BLACKLISTED_IP = os.environ.get("FW_BLACKLISTED_IP", "10.66.66.66")

NORMAL_PORTS = (80, 443, 53)           # assumed to be allowed by the engine
UNEXPECTED_PORTS = (31337, 4444, 6667)  # assumed NOT in the engine's allowed list

DEFAULT_SOURCES = {
    "normal": "192.168.1.10",
    "traffic_spike": "192.168.1.20",
    "syn_attempts": "192.168.1.30",
    "unexpected_port": "192.168.1.40",
    "port_scan": "192.168.1.50",
    "blacklisted_ip": BLACKLISTED_IP,
}


def make_packet(src_ip, dst_ip, src_port, dst_port, protocol, flags, size, timestamp):
    """Build one packet dictionary using the exact shared-interface keys."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "protocol": protocol,
        "flags": flags,
        "size": int(size),
        "timestamp": round(float(timestamp), 3),
    }


# --------------------------------------------------------------------------
# Scenarios. Each returns a list of packets sorted by timestamp.
# Signature: scenario(seed, start, src_ip)
# --------------------------------------------------------------------------
def normal_traffic(seed=DEFAULT_SEED, start=BASE_TIMESTAMP, src_ip=None):
    """40 ordinary web/DNS packets, roughly one per second."""
    rng = random.Random(seed)
    src_ip = src_ip or DEFAULT_SOURCES["normal"]
    packets, t = [], start
    for _ in range(40):
        dst_port = rng.choice(NORMAL_PORTS)
        if dst_port == 53:
            protocol, flags = "UDP", ""
        else:
            protocol, flags = "TCP", rng.choice(["A", "PA"])
        packets.append(make_packet(src_ip, SERVER_IP, rng.randint(40000, 60000),
                                   dst_port, protocol, flags,
                                   rng.randint(100, 900), t))
        t += rng.uniform(0.8, 1.2)
    return packets


def port_scan(seed=DEFAULT_SEED, start=BASE_TIMESTAMP, src_ip=None):
    """One source probing 40 different destination ports with SYNs, 0.1 s apart.

    Note: a simulated probe of many ports on ONE target host is usually called a
    "vertical" scan; many hosts on one port is "horizontal". The engine measures
    distinct destination ports per source (port diversity), so that is what
    this scenario produces. Only synthetic dicts; nothing is sent anywhere.
    """
    rng = random.Random(seed)
    src_ip = src_ip or DEFAULT_SOURCES["port_scan"]
    packets, t = [], start
    for port in range(1, 41):
        packets.append(make_packet(src_ip, SERVER_IP, rng.randint(40000, 60000),
                                   port, "TCP", "S", 60, t))
        t += 0.1
    return packets


def traffic_spike(seed=DEFAULT_SEED, start=BASE_TIMESTAMP, src_ip=None):
    """30 calm packets (1 per second) followed by a 300-packet burst in ~3 s."""
    rng = random.Random(seed)
    src_ip = src_ip or DEFAULT_SOURCES["traffic_spike"]
    packets, t = [], start
    for _ in range(30):                      # baseline
        packets.append(make_packet(src_ip, SERVER_IP, rng.randint(40000, 60000),
                                   443, "TCP", "A", rng.randint(300, 700), t))
        t += 1.0
    for _ in range(300):                     # burst
        packets.append(make_packet(src_ip, SERVER_IP, rng.randint(40000, 60000),
                                   443, "TCP", "A", 1400, t))
        t += 0.01
    return packets


def syn_attempts(seed=DEFAULT_SEED, start=BASE_TIMESTAMP, src_ip=None):
    """60 TCP SYN packets to one port, 0.1 s apart, never completing a handshake."""
    rng = random.Random(seed)
    src_ip = src_ip or DEFAULT_SOURCES["syn_attempts"]
    packets, t = [], start
    for _ in range(60):
        packets.append(make_packet(src_ip, SERVER_IP, rng.randint(40000, 60000),
                                   443, "TCP", "S", 60, t))
        t += 0.1
    return packets


def blacklisted_ip(seed=DEFAULT_SEED, start=BASE_TIMESTAMP, src_ip=None):
    """5 harmless-looking packets from the blacklisted address."""
    rng = random.Random(seed)
    src_ip = src_ip or DEFAULT_SOURCES["blacklisted_ip"]
    packets, t = [], start
    for _ in range(5):
        packets.append(make_packet(src_ip, SERVER_IP, rng.randint(40000, 60000),
                                   80, "TCP", "PA", 300, t))
        t += 1.0
    return packets


def unexpected_port(seed=DEFAULT_SEED, start=BASE_TIMESTAMP, src_ip=None):
    """6 packets to ports that are not in the normal allowed set."""
    rng = random.Random(seed)
    src_ip = src_ip or DEFAULT_SOURCES["unexpected_port"]
    packets, t = [], start
    for i in range(6):
        packets.append(make_packet(src_ip, SERVER_IP, rng.randint(40000, 60000),
                                   UNEXPECTED_PORTS[i % len(UNEXPECTED_PORTS)],
                                   "TCP", "PA", 200, t))
        t += 1.0
    return packets


SCENARIOS = {
    "normal": normal_traffic,
    "port_scan": port_scan,
    "traffic_spike": traffic_spike,
    "syn_attempts": syn_attempts,
    "blacklisted_ip": blacklisted_ip,
    "unexpected_port": unexpected_port,
}


# --------------------------------------------------------------------------
# Public helpers
# --------------------------------------------------------------------------
def generate_scenario(name, seed=DEFAULT_SEED, start=BASE_TIMESTAMP, src_ip=None):
    """Return the packet list for one scenario name."""
    if name not in SCENARIOS:
        raise ValueError("Unknown scenario %r. Choose from: %s"
                         % (name, ", ".join(SCENARIOS)))
    return SCENARIOS[name](seed=seed, start=start, src_ip=src_ip)


def generate_all(seed=DEFAULT_SEED, start=BASE_TIMESTAMP):
    """Return [(name, packets), ...] with scenarios placed one after another in time."""
    result, t = [], start
    for name in SCENARIOS:
        packets = generate_scenario(name, seed=seed, start=t)
        result.append((name, packets))
        t = packets[-1]["timestamp"] + SCENARIO_GAP
    return result


def run_through_engine(packets, process_packet=None):
    """Feed packets to the engine's public process_packet() and return the results.

    The engine is imported lazily so the simulator works on its own.
    Copies are passed in so the engine can never change our originals.
    """
    if process_packet is None:
        from firewall_engine import process_packet  # owned by another developer
    return [process_packet(dict(p)) for p in packets]


def summarize(results):
    """Small summary dict for printing: counts of actions/risks, max score, example reason."""
    flagged = [r for r in results if r["action"] != "ALLOW"]
    return {
        "packets": len(results),
        "actions": dict(Counter(r["action"] for r in results)),
        "risks": dict(Counter(r["risk"] for r in results)),
        "max_anomaly_score": max((r["anomaly_score"] for r in results), default=0),
        "first_flagged_reason": flagged[0]["reason"] if flagged else "",
    }


# --------------------------------------------------------------------------
# Command line interface
# --------------------------------------------------------------------------
def _print_packets(packets, limit):
    for p in packets[:limit]:
        print("  %.3f %s:%d -> %s:%d %s flags=%s size=%d" % (
            p["timestamp"], p["src_ip"], p["src_port"], p["dst_ip"],
            p["dst_port"], p["protocol"], p["flags"] or "-", p["size"]))
    if len(packets) > limit:
        print("  ... (%d more packets)" % (len(packets) - limit))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate synthetic traffic for the Adaptive Network Firewall "
                    "(local only, nothing is sent on a network).")
    parser.add_argument("--scenario", default="all",
                        choices=["all"] + list(SCENARIOS),
                        help="scenario name, or 'all' (default)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED,
                        help="random seed (default %d)" % DEFAULT_SEED)
    parser.add_argument("--run", action="store_true",
                        help="feed packets to firewall_engine.process_packet and summarize")
    parser.add_argument("--verbose", action="store_true",
                        help="with --run, print one line per decision")
    parser.add_argument("--json", action="store_true",
                        help="print raw packets (or results with --run) as JSON")
    parser.add_argument("--limit", type=int, default=5,
                        help="packets to preview per scenario (default 5)")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = parser.parse_args(argv)

    if args.list:
        for name, fn in SCENARIOS.items():
            print("%-16s %s" % (name, fn.__doc__.strip().splitlines()[0]))
        return 0

    if args.scenario == "all":
        batches = generate_all(seed=args.seed)
    else:
        batches = [(args.scenario, generate_scenario(args.scenario, seed=args.seed))]

    if args.run:
        try:
            from firewall_engine import process_packet
        except ImportError as exc:
            print("Could not import firewall_engine.process_packet: %s" % exc,
                  file=sys.stderr)
            print("Run without --run to just view the generated packets.",
                  file=sys.stderr)
            return 1

    output = {}
    for name, packets in batches:
        if args.run:
            results = run_through_engine(packets, process_packet)
            output[name] = results
            if not args.json:
                print("== %s ==" % name)
                if args.verbose:
                    for r in results:
                        print("  %.3f %-15s dport=%-5d %-5s %-6s score=%-6s %s" % (
                            r["timestamp"], r["src_ip"], r["dst_port"], r["action"],
                            r["risk"], r["anomaly_score"], r["reason"]))
                s = summarize(results)
                print("  packets=%d actions=%s risks=%s max_score=%s"
                      % (s["packets"], s["actions"], s["risks"], s["max_anomaly_score"]))
                if s["first_flagged_reason"]:
                    print("  first flagged reason: %s" % s["first_flagged_reason"])
        else:
            output[name] = packets
            if not args.json:
                print("== %s (%d packets) ==" % (name, len(packets)))
                _print_packets(packets, args.limit)

    if args.json:
        print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
