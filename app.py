"""
app.py - Streamlit dashboard for the Adaptive Network Firewall (college prototype).

Run with:   streamlit run app.py

What this file does
  * Generates SYNTHETIC packets locally (no network, no admin rights, nothing is sent).
  * Sends every packet to the core engine through the shared interface:
        process_packet(packet: dict) -> dict
    The engine returns the packet fields plus: action, risk, anomaly_score, reason.
  * Saves each result with database.py and shows it in an interactive dashboard.
  * It does NOT contain any detection logic - that lives in firewall_engine.py.

Important: BLOCK is a logged decision (plus the engine's temporary block list).
This dashboard never creates operating-system firewall rules.

Packet conventions used by the simulated scenarios (the documented contract):
  timestamp = epoch seconds (float), protocol = "TCP"/"UDP"/"ICMP",
  flags = Scapy-style TCP flag letters ("S" = SYN, "SA", "A", "PA"), "" for UDP/ICMP.
All IP addresses used are private (192.168.x.x) or documentation-only ranges
(198.51.100.x / 203.0.113.x, RFC 5737), so they can never reach a real system.
"""

import ipaddress
import random
import time
from collections import Counter

import altair as alt
import pandas as pd
import streamlit as st

import database

# st.set_page_config must be the first Streamlit call.
st.set_page_config(page_title="Adaptive Network Firewall", page_icon="🛡️", layout="wide")

# The core engine is owned by another developer. Import it defensively so the
# dashboard still opens (and shows a helpful message) if it is missing or broken.
try:
    import firewall_engine
    from firewall_engine import process_packet

    ENGINE_ERROR = None
except Exception as exc:  # noqa: BLE001 - show any import problem in the UI
    firewall_engine = None
    process_packet = None
    ENGINE_ERROR = f"{type(exc).__name__}: {exc}"

# --------------------------------------------------------------------------- #
# Theme
# --------------------------------------------------------------------------- #
NAVY, PANEL, BORDER = "#0a1628", "#0f2040", "#1c3a63"
BLUE, CYAN = "#3b82f6", "#38bdf8"
TEXT, MUTED = "#e2e8f0", "#94a3b8"
GREEN, AMBER, RED = "#22c55e", "#f59e0b", "#ef4444"

ACTION_COLORS = {"ALLOW": GREEN, "ALERT": AMBER, "BLOCK": RED}
RISK_COLORS = {"LOW": GREEN, "MEDIUM": AMBER, "HIGH": RED}
_CELL_STYLE = {
    "ALLOW": "background-color:#14532d;color:#bbf7d0;font-weight:600",
    "LOW": "background-color:#14532d;color:#bbf7d0;font-weight:600",
    "ALERT": "background-color:#78350f;color:#fde68a;font-weight:600",
    "MEDIUM": "background-color:#78350f;color:#fde68a;font-weight:600",
    "BLOCK": "background-color:#7f1d1d;color:#fecaca;font-weight:600",
    "HIGH": "background-color:#7f1d1d;color:#fecaca;font-weight:600",
}

CSS = f"""
<style>
.stApp {{ background: linear-gradient(180deg, #07101f 0%, {NAVY} 100%); color: {TEXT}; }}
header[data-testid="stHeader"] {{ background: transparent; }}
section[data-testid="stSidebar"] {{ background: #0c1b33; border-right: 1px solid {BORDER}; }}
h1, h2, h3, h4 {{ color: {TEXT} !important; }}
.stApp [data-testid="stMarkdownContainer"] {{ color: #cbd5e1; }}
[data-testid="stWidgetLabel"] * {{ color: #cbd5e1 !important; }}
[data-testid="stCaptionContainer"] {{ color: #8ba3c4; }}
button[data-baseweb="tab"] {{ color: #9fb3c8; }}
button[data-baseweb="tab"][aria-selected="true"] {{ color: #60a5fa; }}
.stButton > button {{
    width: 100%; background: #12305a; color: {TEXT}; font-weight: 600;
    border: 1px solid {BLUE}; border-radius: 8px;
}}
.stButton > button:hover {{ background: #1d4ed8; border-color: #60a5fa; color: #fff; }}
.stButton > button:disabled {{ opacity: 0.45; }}
.st-key-btn_normal button {{ border-color: {GREEN}; }}
.st-key-btn_scan button, .st-key-btn_spike button, .st-key-btn_syn button {{ border-color: {AMBER}; }}
.st-key-btn_blacklist button, .st-key-btn_port button {{ border-color: {RED}; }}
.fw-header {{ display:flex; justify-content:space-between; align-items:center;
    padding: 6px 0 2px 0; }}
.fw-title {{ font-size: 2rem; font-weight: 700; color: {TEXT}; margin: 0; }}
.fw-sub {{ color: {MUTED}; margin: 2px 0 0 0; }}
.fw-badge {{ background:#0b2a4a; color:{CYAN}; border:1px solid {BLUE}; border-radius:999px;
    padding: 4px 14px; font-size: 0.8rem; font-weight: 700; letter-spacing: 1px; }}
.fw-card {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 12px;
    padding: 14px 18px; }}
.fw-label {{ color: {MUTED}; font-size: 0.78rem; font-weight: 600; letter-spacing: 1px;
    text-transform: uppercase; }}
.fw-value {{ font-size: 2.1rem; font-weight: 700; line-height: 1.2; }}
.fw-note {{ color: {MUTED}; font-size: 0.8rem; }}
</style>
"""

# --------------------------------------------------------------------------- #
# Synthetic traffic generators (simulation only - nothing leaves this process)
# --------------------------------------------------------------------------- #
INTERNAL_HOSTS = [f"192.168.1.{n}" for n in (10, 11, 12, 13, 14, 15, 16, 17)]
WEB_SERVERS = ["198.51.100.10", "198.51.100.20", "198.51.100.30"]  # RFC 5737 documentation range
DNS_SERVER = "192.168.1.1"
INTERNAL_SERVER = "192.168.1.100"  # victim of the simulated attacks
SCAN_ATTACKER = "198.51.100.77"
SYN_ATTACKER = "198.51.100.88"
SPIKE_HOST = "192.168.1.12"
PORT_ATTACKER = "198.51.100.55"
FALLBACK_BLACKLISTED_IP = "203.0.113.66"
FALLBACK_UNEXPECTED_PORT = 4444


@st.cache_resource
def get_sim_clock() -> dict:
    """Shared simulation clock so timestamps always move forward between clicks."""
    return {"last_ts": 0.0}


def _start_time() -> float:
    return max(time.time(), get_sim_clock()["last_ts"] + 0.5)


def _packet(src_ip, dst_ip, src_port, dst_port, protocol, flags, size, ts) -> dict:
    """Build one packet dictionary exactly as the shared contract describes."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "flags": flags,
        "size": size,
        "timestamp": round(ts, 4),
    }


def _ephemeral_port() -> int:
    return random.randint(49152, 65535)


def build_normal_traffic(settings: dict) -> list:
    """Low-rate everyday traffic from several internal hosts (builds the baseline)."""
    packets, ts = [], _start_time()
    for _ in range(settings["n_normal"]):
        ts += random.uniform(0.2, 0.8)
        src, roll = random.choice(INTERNAL_HOSTS), random.random()
        if roll < 0.25:  # DNS lookup
            packets.append(_packet(src, DNS_SERVER, _ephemeral_port(), 53, "UDP", "",
                                   random.randint(70, 120), ts))
        else:  # web browsing
            port = 443 if roll < 0.70 else 80
            flags = "S" if random.random() < 0.10 else random.choice(["A", "PA", "PA"])
            size = 60 if flags == "S" else random.randint(200, 1400)
            packets.append(_packet(src, random.choice(WEB_SERVERS), _ephemeral_port(), port,
                                   "TCP", flags, size, ts))
    return packets


def build_port_scan(settings: dict) -> list:
    """One host probes many different ports on one target (simulated locally)."""
    ports = sorted(random.sample(range(1, 1025), settings["n_ports"]))
    src_port, packets, ts = random.randint(40000, 60000), [], _start_time()
    for port in ports:
        ts += random.uniform(0.03, 0.08)
        packets.append(_packet(SCAN_ATTACKER, INTERNAL_SERVER, src_port, port, "TCP", "S", 60, ts))
    return packets


def build_traffic_spike(settings: dict) -> list:
    """A normally quiet host suddenly sends a large burst of big packets."""
    packets, ts = [], _start_time()
    for _ in range(settings["n_spike"]):
        ts += random.uniform(0.005, 0.02)
        packets.append(_packet(SPIKE_HOST, WEB_SERVERS[0], _ephemeral_port(), 443, "TCP", "PA",
                               random.randint(1200, 1500), ts))
    return packets


def build_syn_attempts(settings: dict) -> list:
    """Many SYN packets from one host to the same service port, no handshake completion."""
    packets, ts = [], _start_time()
    for _ in range(settings["n_syn"]):
        ts += random.uniform(0.03, 0.08)
        packets.append(_packet(SYN_ATTACKER, INTERNAL_SERVER, _ephemeral_port(), 80, "TCP", "S", 60, ts))
    return packets


def build_blacklisted_event(settings: dict) -> list:
    """A few packets from an IP address that should be on the static blacklist."""
    packets, ts = [], _start_time()
    for _ in range(3):
        ts += 0.5
        packets.append(_packet(settings["blacklisted_ip"], INTERNAL_SERVER, _ephemeral_port(), 443,
                               "TCP", "S", 60, ts))
    return packets


def build_unexpected_port_event(settings: dict) -> list:
    """A few packets to a port that is not normally used."""
    packets, ts = [], _start_time()
    for _ in range(3):
        ts += 0.5
        packets.append(_packet(PORT_ATTACKER, INTERNAL_SERVER, _ephemeral_port(),
                               settings["unexpected_port"], "TCP", "S", 60, ts))
    return packets


SCENARIOS = [
    {"key": "normal", "label": "Normal traffic", "build": build_normal_traffic,
     "help": "Everyday web/DNS traffic from several internal hosts. Run this first to build baselines."},
    {"key": "scan", "label": "Port scan", "build": build_port_scan,
     "help": "One host sends SYN packets to many different ports (simulated locally)."},
    {"key": "spike", "label": "Traffic spike", "build": build_traffic_spike,
     "help": "One normally quiet host suddenly sends a burst of large packets."},
    {"key": "syn", "label": "Repeated SYN", "build": build_syn_attempts,
     "help": "Many SYN packets from one host to the same port."},
    {"key": "blacklist", "label": "Blacklisted IP", "build": build_blacklisted_event,
     "help": "Packets from the blacklisted IP set in the sidebar."},
    {"key": "port", "label": "Unexpected port", "build": build_unexpected_port_event,
     "help": "Packets to the unexpected destination port set in the sidebar."},
]


# --------------------------------------------------------------------------- #
# Engine integration
# --------------------------------------------------------------------------- #
def run_scenario(label: str, packets: list) -> None:
    """Send packets through process_packet(), store the results, remember a summary."""
    results, errors, first_error = [], 0, None
    for packet in packets:
        try:
            result = process_packet(dict(packet))
            if not isinstance(result, dict):
                raise TypeError(f"process_packet returned {type(result).__name__}, expected dict")
            results.append({**packet, **result})  # contract: packet fields + decision fields
        except Exception as exc:  # noqa: BLE001 - one bad packet must not stop the demo
            errors += 1
            first_error = first_error or f"{type(exc).__name__}: {exc}"

    if packets:  # keep simulated time moving forward even if some packets failed
        get_sim_clock()["last_ts"] = max(get_sim_clock()["last_ts"], packets[-1]["timestamp"])

    saved = 0
    try:
        saved = database.insert_packets(results)
    except database.DatabaseError as exc:
        first_error = first_error or str(exc)

    counts = Counter(str(r.get("action")).upper() for r in results)
    st.session_state["last_run"] = {
        "label": label, "generated": len(packets), "saved": saved, "errors": errors,
        "first_error": first_error,
        "ALLOW": counts.get("ALLOW", 0), "ALERT": counts.get("ALERT", 0), "BLOCK": counts.get("BLOCK", 0),
    }
    st.toast(f"{label}: {saved} packets processed", icon="🛡️")


def default_blacklisted_ip() -> str:
    try:
        engine = firewall_engine.get_default_engine()
        blacklist = engine.config["static_rules"]["blacklisted_ips"]
        if blacklist:
            return str(blacklist[0]).split("/")[0]
    except (AttributeError, KeyError, TypeError):
        pass
    return "10.66.66.66"


# --------------------------------------------------------------------------- #
# UI helpers
# --------------------------------------------------------------------------- #
def metric_card(label: str, value: int, color: str, note: str) -> str:
    return (
        f'<div class="fw-card" style="border-top:3px solid {color}">'
        f'<div class="fw-label">{label}</div>'
        f'<div class="fw-value" style="color:{color}">{value:,}</div>'
        f'<div class="fw-note">{note}</div></div>'
    )


def style_chart(chart: alt.Chart) -> alt.Chart:
    """Dark-navy styling so charts match the theme."""
    return (
        chart.configure(background="transparent")
        .configure_view(strokeWidth=0)
        .configure_axis(labelColor="#9fb3c8", titleColor="#9fb3c8", gridColor="#1c3a63",
                        domainColor="#1c3a63", tickColor="#1c3a63")
        .configure_legend(labelColor="#cbd5e1", titleColor="#9fb3c8")
    )


def render_sidebar() -> dict:
    st.sidebar.markdown("### 🔎 Filters")
    st.sidebar.caption("Leave a filter empty to include everything. "
                       "Filters apply to the charts and tables (the summary cards show overall totals).")
    actions = st.sidebar.multiselect("Action", list(database.VALID_ACTIONS), placeholder="All actions")
    protocols = st.sidebar.multiselect("Protocol", database.get_protocols(), placeholder="All protocols")
    src_ip = st.sidebar.text_input("Source IP contains", placeholder="e.g. 198.51.100")
    limit = st.sidebar.select_slider("Rows to show", options=[100, 250, 500, 1000], value=250)
    bucket_label = st.sidebar.selectbox(
        "Trend bucket size", ["1 second", "5 seconds", "10 seconds", "30 seconds", "1 minute"], index=1)
    bucket = {"1 second": 1, "5 seconds": 5, "10 seconds": 10, "30 seconds": 30, "1 minute": 60}[bucket_label]

    st.sidebar.markdown("### ⚙️ Scenario settings")
    n_normal = st.sidebar.number_input("Normal packets", 10, 200, 30, step=10)
    n_ports = st.sidebar.number_input("Ports scanned", 5, 200, 30, step=5)
    n_spike = st.sidebar.number_input("Spike packets", 30, 400, 120, step=10)
    n_syn = st.sidebar.number_input("SYN attempts", 5, 200, 40, step=5)

    default_ip = default_blacklisted_ip() if firewall_engine else FALLBACK_BLACKLISTED_IP
    bl_text = st.sidebar.text_input("Blacklisted IP to simulate", value=default_ip,
                                    help="Should match an address on the engine's static blacklist.")
    try:
        blacklisted_ip = str(ipaddress.ip_address(bl_text.strip()))
    except ValueError:
        st.sidebar.warning("Not a valid IP address - using the default instead.")
        blacklisted_ip = default_ip
    unexpected_port = st.sidebar.number_input("Unexpected port", 1, 65535, FALLBACK_UNEXPECTED_PORT,
                                              help="Should be a port the engine's static rules do not expect.")

    st.sidebar.markdown("### 🧹 Data")
    with st.sidebar.expander("Clear logged packets"):
        confirm = st.checkbox("Yes, delete all logged packets")
        if st.button("Clear database", disabled=not confirm, key="btn_clear"):
            try:
                removed = database.clear_packets()
                st.session_state.pop("last_run", None)
                st.success(f"Removed {removed:,} records.")
            except database.DatabaseError as exc:
                st.error(str(exc))
        st.caption("Engine profiles are kept in memory; restart Streamlit to reset them as well.")

    st.sidebar.caption(f"Engine: {'connected' if firewall_engine else 'unavailable'}  \n"
                       f"Database: {database.DB_PATH.name}")

    return {
        "actions": actions or None, "protocols": protocols or None, "src_ip": src_ip.strip() or None,
        "limit": limit, "bucket": bucket,
        "settings": {"n_normal": int(n_normal), "n_ports": int(n_ports), "n_spike": int(n_spike),
                     "n_syn": int(n_syn), "blacklisted_ip": blacklisted_ip,
                     "unexpected_port": int(unexpected_port)},
    }


def render_header() -> None:
    st.markdown(
        '<div class="fw-header"><div><p class="fw-title">🛡️ Adaptive Network Firewall</p>'
        '<p class="fw-sub">Static rules · behavioural profiling · statistical anomaly detection</p></div>'
        '<span class="fw-badge">SIMULATION MODE</span></div>',
        unsafe_allow_html=True,
    )
    st.caption("All traffic is synthetic and generated locally - nothing is sent over a network. "
               "BLOCK means a logged decision and an entry in the prototype's temporary block list; "
               "no operating-system firewall rules are created.")


def render_controls(settings: dict) -> None:
    st.markdown("#### Traffic simulator")
    if ENGINE_ERROR:
        st.error(f"Could not import `process_packet` from firewall_engine.py - {ENGINE_ERROR}. "
                 "Simulation buttons are disabled until the engine imports correctly.")

    clicked = None
    for col, scenario in zip(st.columns(len(SCENARIOS)), SCENARIOS):
        with col:
            if st.button(scenario["label"], key=f"btn_{scenario['key']}", help=scenario["help"],
                         disabled=ENGINE_ERROR is not None):
                clicked = scenario
    if clicked:
        with st.spinner(f"Simulating: {clicked['label']}..."):
            run_scenario(clicked["label"], clicked["build"](settings))

    last = st.session_state.get("last_run")
    if last:
        message = (f"**{last['label']}** - {last['saved']} of {last['generated']} packets processed and saved: "
                   f"ALLOW {last['ALLOW']} · ALERT {last['ALERT']} · BLOCK {last['BLOCK']}")
        if last["errors"] or last["first_error"]:
            st.warning(f"{message}\n\n{last['errors']} packet(s) failed. First error: {last['first_error']}")
        else:
            st.info(message)


def render_cards(counts: dict) -> None:
    total = counts["total"]

    def pct(n):
        return f"{(n / total * 100):.1f}% of traffic" if total else "no traffic yet"

    cards = [
        ("Packets processed", total, CYAN, "all time"),
        ("Allow", counts["ALLOW"], GREEN, pct(counts["ALLOW"])),
        ("Alert", counts["ALERT"], AMBER, pct(counts["ALERT"])),
        ("Block", counts["BLOCK"], RED, pct(counts["BLOCK"])),
    ]
    for col, (label, value, color, note) in zip(st.columns(4), cards):
        col.markdown(metric_card(label, value, color, note), unsafe_allow_html=True)


def render_charts(f: dict) -> None:
    left, right = st.columns([1, 2])

    with left:
        st.markdown("#### Risk distribution")
        dist = database.get_risk_distribution(f["actions"], f["protocols"], f["src_ip"])
        risk_df = pd.DataFrame({"risk": list(dist), "packets": list(dist.values())})
        if risk_df["packets"].sum() == 0:
            st.info("No packets match the current filters.")
        else:
            chart = (
                alt.Chart(risk_df)
                .mark_bar(cornerRadiusTopLeft=5, cornerRadiusTopRight=5)
                .encode(
                    x=alt.X("risk:N", sort=list(RISK_COLORS), title=None, axis=alt.Axis(labelAngle=0)),
                    y=alt.Y("packets:Q", title="Packets"),
                    color=alt.Color("risk:N", legend=None,
                                    scale=alt.Scale(domain=list(RISK_COLORS), range=list(RISK_COLORS.values()))),
                    tooltip=["risk", "packets"],
                )
                .properties(height=300, width="container")
            )
            st.altair_chart(style_chart(chart), theme=None)

    with right:
        st.markdown("#### Traffic trend")
        trend = database.get_traffic_trend(f["bucket"], 60, f["actions"], f["protocols"], f["src_ip"])
        if trend.empty:
            st.info("No traffic to plot yet - click **Normal traffic** above to get started.")
        else:
            order = list(dict.fromkeys(trend.sort_values("bucket")["bucket_label"]))
            chart = (
                alt.Chart(trend)
                .mark_bar()
                .encode(
                    x=alt.X("bucket_label:O", sort=order, title="Time", axis=alt.Axis(labelAngle=-45)),
                    y=alt.Y("packets:Q", title="Packets", stack="zero"),
                    color=alt.Color("action:N", title="Action",
                                    scale=alt.Scale(domain=list(ACTION_COLORS), range=list(ACTION_COLORS.values()))),
                    tooltip=["bucket_label", "action", "packets"],
                )
                .properties(height=300, width="container")
            )
            st.altair_chart(style_chart(chart), theme=None)


DISPLAY_COLUMNS = {
    "time": "Time", "src_ip": "Source IP", "src_port": "Src Port", "dst_ip": "Destination IP",
    "dst_port": "Dst Port", "protocol": "Protocol", "flags": "Flags", "size": "Size (B)",
    "risk": "Risk", "anomaly_score": "Anomaly Score", "action": "Action", "reason": "Reason",
}


def show_table(df: pd.DataFrame, file_name: str, empty_message: str) -> None:
    """Render a packet DataFrame with coloured Action/Risk cells and a CSV download."""
    if df.empty:
        st.info(empty_message)
        return

    table = df[list(DISPLAY_COLUMNS)].rename(columns=DISPLAY_COLUMNS)
    styler = table.style.format(na_rep="-").format({"Anomaly Score": "{:.2f}"}, na_rep="-")
    apply_cell = getattr(styler, "map", None) or styler.applymap  # pandas >= 2.1 renamed applymap
    apply_cell(lambda v: _CELL_STYLE.get(v, ""), subset=["Action", "Risk"])

    st.caption(f"Showing {len(table):,} most recent matching records.")
    st.dataframe(styler, hide_index=True, height=420,
                 column_config={"Reason": st.column_config.TextColumn("Reason", width="large")})
    st.download_button("Download CSV", table.to_csv(index=False).encode("utf-8"),
                       file_name=file_name, mime="text/csv", key=f"dl_{file_name}")


def render_tables(f: dict) -> None:
    traffic_tab, alert_tab = st.tabs(["📋 Traffic table", "🚨 Alert history"])

    with traffic_tab:
        df = database.get_packets(f["limit"], f["actions"], f["protocols"], f["src_ip"])
        show_table(df, "firewall_traffic.csv",
                   "No packets match the current filters. Use the simulator buttons to generate traffic.")

    with alert_tab:
        st.caption("Every ALERT and BLOCK decision (protocol and source filters apply).")
        alerts = database.get_alerts(f["limit"], f["protocols"], f["src_ip"])
        show_table(alerts, "firewall_alerts.csv", "No alerts or blocks recorded yet.")

        st.markdown("##### Hosts with BLOCK decisions")
        st.caption("Logged decisions only - no operating-system firewall rule is created.")
        blocked = database.get_blocked_sources()
        if blocked.empty:
            st.info("No hosts have been blocked yet.")
        else:
            blocked = blocked.rename(columns={
                "src_ip": "Source IP", "block_decisions": "BLOCK decisions",
                "max_anomaly_score": "Max anomaly score", "last_seen": "Last seen"})
            st.dataframe(blocked.style.format({"Max anomaly score": "{:.2f}"}), hide_index=True)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
    db_ready = database.init_db()  # automatic and safe to repeat

    render_header()
    if not db_ready:
        st.error(f"The SQLite database could not be opened at `{database.DB_PATH}`. "
                 "Check that the folder is writable, then refresh the page.")

    filters = render_sidebar()
    render_controls(filters["settings"])

    st.write("")
    try:
        render_cards(database.get_summary_counts())
        st.write("")
        render_charts(filters)
        render_tables(filters)
    except Exception as exc:  # noqa: BLE001 - last line of defence for the live demo
        st.error(f"The dashboard hit an unexpected problem: {type(exc).__name__}: {exc}")


main()
