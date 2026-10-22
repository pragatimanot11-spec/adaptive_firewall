"""
Tests for the shared engine interface and expected decisions.

They call ONLY the public function firewall_engine.process_packet() and use
packets from simulator.py. They do not copy or re-implement any detection logic.

Assumptions about the engine (see README "Integration assumptions"):
  * it reads packet["timestamp"] for its sliding windows (not the wall clock)
  * its static blacklist contains simulator.BLACKLISTED_IP
  * ports 80, 443, 53 are expected; 31337, 4444, 6667 are not
Each test uses its own source IP so per-host history does not leak between tests.
"""
import pytest

import simulator

PACKET_KEYS = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flags", "size", "timestamp")
ACTIONS = {"ALLOW", "ALERT", "BLOCK"}
RISKS = {"LOW", "MEDIUM", "HIGH"}


@pytest.fixture(scope="module")
def engine():
    try:
        import firewall_engine
    except ImportError as exc:  # fail loudly: a skipped test would hide the problem
        pytest.fail("Cannot import firewall_engine.py from the project root: %s" % exc)
    if not callable(getattr(firewall_engine, "process_packet", None)):
        pytest.fail("firewall_engine.process_packet is missing or not callable")
    return firewall_engine


@pytest.fixture(autouse=True)
def fresh_state(engine):
    """If the engine offers a public reset function, call it before each test."""
    for name in ("reset_state", "reset_engine", "reset"):
        fn = getattr(engine, name, None)
        if callable(fn):
            try:
                fn()
            except TypeError:
                continue
            break


def run(engine, packets):
    return [engine.process_packet(dict(p)) for p in packets]


# ---------------- shared interface ----------------
def test_result_contains_contract_fields(engine):
    result = run(engine, simulator.normal_traffic(src_ip="192.168.1.11")[:1])[0]
    for key in PACKET_KEYS + ("action", "risk", "anomaly_score", "reason"):
        assert key in result, "missing key: " + key


def test_result_preserves_packet_fields(engine):
    packets = simulator.normal_traffic(src_ip="192.168.1.12")[:5]
    for packet, result in zip(packets, run(engine, packets)):
        for key in PACKET_KEYS:
            assert result[key] == packet[key]


def test_values_use_exact_names_and_types(engine):
    for name in simulator.SCENARIOS:
        for i, r in enumerate(run(engine, simulator.generate_scenario(name))):
            assert r["action"] in ACTIONS
            assert r["risk"] in RISKS
            assert isinstance(r["anomaly_score"], (int, float))
            assert not isinstance(r["anomaly_score"], bool)
            assert isinstance(r["reason"], str)
        engine_reset = getattr(engine, "reset_state", None)
        if callable(engine_reset):
            try:
                engine_reset()
            except TypeError:
                pass


# ---------------- expected decisions ----------------
def test_normal_traffic_is_allowed_and_low_risk(engine):
    results = run(engine, simulator.normal_traffic(src_ip="192.168.1.13"))
    assert all(r["action"] == "ALLOW" for r in results)
    assert all(r["risk"] == "LOW" for r in results)


def test_static_deny_blocks_blacklisted_ip_immediately(engine):
    results = run(engine, simulator.blacklisted_ip())
    assert results[0]["action"] == "BLOCK"      # first packet: no history needed
    assert all(r["action"] == "BLOCK" for r in results)
    assert all(r["risk"] == "HIGH" for r in results)
    assert all(r["reason"].strip() for r in results)


def test_static_deny_takes_precedence_over_behavior(engine):
    """Same harmless packet: normal host is ALLOWed, blacklisted host is BLOCKed.
    A blacklisted host hitting an unexpected port is still BLOCKed (deny wins)."""
    ok = simulator.make_packet("192.168.1.14", simulator.SERVER_IP, 50000, 80, "TCP", "PA", 300, 1_700_100_000.0)
    bad = dict(ok, src_ip=simulator.BLACKLISTED_IP)
    odd = dict(bad, dst_port=simulator.UNEXPECTED_PORTS[0])
    r_ok, r_bad, r_odd = run(engine, [ok, bad, odd])
    assert r_ok["action"] == "ALLOW"
    assert r_bad["action"] == "BLOCK"
    assert r_odd["action"] == "BLOCK"


def test_port_diversity_escalates_to_alert_or_block(engine):
    results = run(engine, simulator.port_scan(src_ip="192.168.1.51"))
    assert any(r["action"] in ("ALERT", "BLOCK") for r in results)
    assert results[-1]["action"] in ("ALERT", "BLOCK")
    assert results[-1]["risk"] in ("MEDIUM", "HIGH")
    assert results[-1]["reason"].strip()


def test_traffic_spike_is_flagged_after_calm_baseline(engine):
    packets = simulator.traffic_spike(src_ip="192.168.1.21")
    results = run(engine, packets)
    baseline, burst = results[:30], results[30:]
    assert all(r["action"] == "ALLOW" for r in baseline)
    assert any(r["action"] in ("ALERT", "BLOCK") for r in burst)
    assert max(r["anomaly_score"] for r in burst) > max(r["anomaly_score"] for r in baseline)


def test_repeated_syn_attempts_are_flagged(engine):
    results = run(engine, simulator.syn_attempts(src_ip="192.168.1.31"))
    assert any(r["action"] in ("ALERT", "BLOCK") for r in results)
    assert results[-1]["action"] in ("ALERT", "BLOCK")
    assert results[-1]["risk"] in ("MEDIUM", "HIGH")


def test_unexpected_destination_port_is_not_allowed(engine):
    results = run(engine, simulator.unexpected_port(src_ip="192.168.1.41"))
    assert all(r["action"] in ("ALERT", "BLOCK") for r in results)
    assert all(r["risk"] != "LOW" for r in results)
    assert all(r["reason"].strip() for r in results)
