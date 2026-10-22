"""Tests for simulator.py only. These do NOT need firewall_engine.py."""
import ipaddress
import json
import os
import subprocess
import sys

import simulator

ROOT = os.path.dirname(os.path.abspath(__file__))
KEYS = {"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flags", "size", "timestamp"}
EXPECTED = {"normal", "port_scan", "traffic_spike", "syn_attempts",
            "blacklisted_ip", "unexpected_port"}


def test_six_scenarios_exist():
    assert set(simulator.SCENARIOS) == EXPECTED


def test_packets_match_interface():
    for name in EXPECTED:
        packets = simulator.generate_scenario(name)
        assert packets, name
        for p in packets:
            assert set(p) == KEYS
            assert isinstance(p["src_port"], int) and isinstance(p["dst_port"], int)
            assert isinstance(p["size"], int) and isinstance(p["timestamp"], float)
            assert p["protocol"] in ("TCP", "UDP", "ICMP")


def test_output_is_deterministic():
    assert simulator.generate_all(seed=7) == simulator.generate_all(seed=7)
    assert simulator.generate_scenario("normal", seed=1) != \
        simulator.generate_scenario("normal", seed=2)


def test_only_private_or_loopback_addresses():
    for _, packets in simulator.generate_all():
        for p in packets:
            for addr in (p["src_ip"], p["dst_ip"]):
                assert ipaddress.ip_address(addr).is_private, addr


def test_timestamps_never_go_backwards():
    for _, packets in simulator.generate_all():
        times = [p["timestamp"] for p in packets]
        assert times == sorted(times)
    merged = [p["timestamp"] for _, ps in simulator.generate_all() for p in ps]
    assert merged == sorted(merged)


def test_scenario_shapes():
    scan = simulator.generate_scenario("port_scan")
    assert len({p["dst_port"] for p in scan}) >= 30
    syn = simulator.generate_scenario("syn_attempts")
    assert all(p["flags"] == "S" for p in syn)
    bad = simulator.generate_scenario("blacklisted_ip")
    assert all(p["src_ip"] == simulator.BLACKLISTED_IP for p in bad)
    odd = simulator.generate_scenario("unexpected_port")
    assert all(p["dst_port"] in simulator.UNEXPECTED_PORTS for p in odd)


def test_unknown_scenario_rejected():
    try:
        simulator.generate_scenario("nope")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_cli_prints_json_without_engine():
    out = subprocess.run([sys.executable, "simulator.py", "--scenario", "normal", "--json"],
                         cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert "normal" in json.loads(out.stdout)
