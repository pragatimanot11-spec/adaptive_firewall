# adaptive_firewall
# Adaptive Network Firewall
### A Hybrid Rule-Based and Behavioral Anomaly Detection Framework

## 1. Project Overview

The Adaptive Network Firewall is a Python-based network security prototype that identifies suspicious network traffic using two approaches:

1. **Rule-Based Detection:** Checks network traffic against predefined security rules, such as blacklisted IP addresses, restricted ports, and allowed protocols.
2. **Behavioral Anomaly Detection:** Examines traffic patterns and identifies unusual activity, such as sudden increases in packet rates, scanning of multiple ports, and repeated TCP SYN packets.

The project includes an interactive Streamlit dashboard for monitoring traffic, viewing firewall decisions, analyzing risk levels, and reviewing logged events.

**Important:** This project currently simulates firewall decisions. It does not directly block packets at the operating-system or network level.

## 2. Objectives

- Identify traffic that violates predefined security rules.
- Detect suspicious behavior using traffic statistics and anomaly scoring.
- Classify network events into `ALLOW`, `ALERT`, and `BLOCK` decisions.
- Display traffic activity and security events through a dashboard.
- Store traffic records for monitoring and analysis.
- Test detection logic using automated test cases.
- Demonstrate how a basic adaptive firewall could be developed further for real-world use.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core firewall logic and traffic processing |
| Streamlit | Interactive monitoring dashboard |
| SQLite / logging | Store and review traffic and security events |
| Pytest | Automated testing |
| JSON | Configuration of firewall rules and thresholds |
| Synthetic traffic simulator | Generate normal and suspicious traffic scenarios |

## 4. Project Architecture

```text
Synthetic Network Traffic
          |
          v
Traffic Feature Extraction
          |
          v
Rule-Based Detection
(IP blacklist, ports, protocols)
          |
          v
Behavioral Anomaly Detection
(Packet rate, ports, bytes, SYN count)
          |
          v
Risk Assessment and Decision
          |
          v
ALLOW / ALERT / BLOCK
          |
          v
Database and Event Logs
          |
          v
Streamlit Dashboard
```

### How it works

**Step 1: Traffic generation**

The simulator generates sample network packets representing normal and suspicious traffic.

**Step 2: Feature extraction**

The system examines relevant packet information, including source and destination IP addresses, ports, protocols, packet sizes, timestamps, and available TCP flags.

**Step 3: Static rule checking**

The firewall checks whether the traffic matches configured rules. For example, traffic from a blacklisted IP or traffic directed to a restricted destination port can be blocked.

**Step 4: Behavioral analysis**

The engine examines traffic metrics over a time window. These include packet rate, number of distinct ports, byte rate, and TCP SYN activity. It compares observed behavior against configured thresholds and a learned baseline.

**Step 5: Decision-making**

The engine produces an action and a risk classification based on the applicable rules and anomaly results.

- `ALLOW`: Traffic is accepted by the prototype's decision logic.
- `ALERT`: Traffic is considered suspicious and should be investigated.
- `BLOCK`: Traffic is classified for blocking by the prototype.

**Step 6: Logging and visualization**

The dashboard displays processed traffic, security decisions, risk levels, trends, and event history.

## 5. Project Structure

```text
cn-project/
├── app.py
├── config.json
├── conftest.py
├── database.py
├── firewall_engine.py
├── simulator.py
├── test_engine_decisions.py
├── test_simulator.py
├── requirements.txt
├── README.md
└── .venv/
```

Additional files, such as generated CSV files, databases, and logs, may appear when the project runs.

| File | Responsibility |
|---|---|
| `app.py` | Streamlit dashboard and user interaction |
| `firewall_engine.py` | Rule-based checks, behavioral analysis, and decisions |
| `simulator.py` | Generates sample normal and suspicious traffic |
| `database.py` | Database operations and persistence |
| `config.json` | Configurable security rules and detection thresholds |
| `test_engine_decisions.py` | Tests firewall decision logic |
| `test_simulator.py` | Tests traffic simulation behavior |
| `conftest.py` | Shared pytest configuration and fixtures |
| `requirements.txt` | Python dependency list |

## 6. Prerequisites

- Windows 10 or Windows 11
- Python installed
- Visual Studio Code
- The project dependencies installed in the virtual environment

Open the project folder in VS Code:

```powershell
cd D:\sem5\CN\cn-project
```

If your project is stored in a different location, replace the path with your actual project directory.

## 7. Installation and Setup

### Step 1: Open the VS Code terminal

Open the project folder in VS Code and select **Terminal → New Terminal**.

### Step 2: Activate the virtual environment

In PowerShell, run:

```powershell
.\.venv\Scripts\Activate.ps1
```

If activation is blocked by your terminal's execution policy, you can skip activation and use the virtual environment's Python executable directly in the commands below.

### Step 3: Install dependencies if needed

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Step 4: Run the automated tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

The current verified result is:

```text
18 passed
```

If you make code or configuration changes, run the tests again to verify the current result.

## 8. Running the Application

Start the dashboard using:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Streamlit will display a local URL, normally:

```text
http://localhost:8501
```

Open that address in your browser.

Keep the terminal running while you demonstrate the application. To stop the server, return to the terminal and press **Ctrl + C**.

## 9. Demonstration Guide

Use the following sequence during your project review.

### Demo 1: Normal Traffic

**What to do:**
1. Open the dashboard.
2. Find the normal-traffic simulation control.
3. Run the simulation.
4. Observe the processed packet count, decision counters, risk indicators, charts, and event table.

**Expected observation:** Normal simulated traffic should generally receive `ALLOW` decisions when it does not violate any rule or anomaly threshold.

**What to explain:**

"This demonstrates the normal operating condition. The firewall processes simulated traffic, evaluates its characteristics, and records its decisions. The dashboard helps us monitor the network activity."

### Demo 2: Blacklisted IP Address

**What to do:**
1. Locate the **Blacklisted IP** simulation control.
2. Run it.
3. Observe the latest simulation result and the `BLOCK` counter.

The configured test IP is:

```text
10.66.66.66
```

**Expected observation:** Packets matching the configured blacklist should receive `BLOCK` decisions.

**What to explain:**

"Here, we simulate traffic from a known blacklisted source. The rule-based engine checks the source IP against our configured blacklist and classifies matching traffic for blocking. Static security rules take precedence over normal traffic behavior."

### Demo 3: Suspicious Port Activity

**What to do:**
1. Run the port-scan or unexpected-port simulation control.
2. Examine the resulting actions and risk levels.
3. Review the corresponding event records.

Configured example ports include:

```text
31337, 4444, 6667
```

**Expected observation:** Traffic matching a restricted destination port should be blocked by the static rule engine. Other scanning-like behavior may produce an alert or block depending on the implemented logic and thresholds.

**What to explain:**

"Port scanning can indicate that an attacker is searching for exposed services. Our prototype can identify configured restricted ports and analyze traffic patterns that may indicate scanning activity."

### Demo 4: Traffic Spike

**What to do:**
1. Run the traffic-spike simulation control, if available in the dashboard.
2. Observe packet counts, risk classifications, and anomaly information.
3. Check the event table for alerts or blocks.

**What to explain:**

"A sudden increase in packet rate can indicate abnormal activity, such as a traffic flood. The behavioral component compares observed metrics with configured thresholds and the learned baseline to help identify unusual traffic."

### Demo 5: Repeated TCP SYN Activity

**What to do:**
1. Run the repeated-SYN simulation control, if available.
2. Inspect the latest decisions and anomaly information.

**What to explain:**

"Repeated TCP SYN packets can be associated with connection attempts and, in some situations, SYN-flood activity. Our prototype monitors SYN-related behavior as one of its indicators. A real deployment would need additional connection-state and traffic validation before determining whether an attack is occurring."

### Demo 6: Event History and Logs

**What to do:**
1. Open the dashboard's event-history or log section.
2. Review recent `ALLOW`, `ALERT`, and `BLOCK` decisions.
3. Inspect available CSV exports or generated log files.

**What to explain:**

"Logging provides a record of what the system observed and how it classified each event. In a real security environment, these records would help an administrator investigate suspicious activity, identify recurring sources, and evaluate detection accuracy."

**Important:** Demonstrate the controls actually present in the current dashboard. If a scenario control is not present, do not claim to have run it; use the available interface or explain the scenario using the engine's implemented logic.

## 10. Configuration

The `config.json` file contains the security rules and detection parameters.

The current static-rule configuration includes:

```json
{
  "static_rules": {
    "blacklisted_ips": [
      "10.66.66.66"
    ],
    "restricted_ports": [
      23,
      135,
      139,
      445,
      3389,
      31337,
      4444,
      6667
    ],
    "allowed_protocols": [
      "TCP",
      "UDP",
      "ICMP"
    ]
  }
}
```

This is an illustrative excerpt of the relevant configuration, not a replacement for the complete project configuration. Keep the other existing settings in `config.json`, including the behavioral thresholds and baseline parameters.

These rules are intended for the project's simulated environment. Real networks require carefully designed rules that account for legitimate services and operational requirements.

## 11. Testing

Run the test suite with:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

The current verified test result is **18 passed, 0 failed**.

The tests provide evidence that the tested components behave as expected. They do not, by themselves, establish production-grade security or prove that every possible attack will be detected.

## 12. Real-World Applications

Potential applications of this approach include:

- **College networks:** Identify unusual traffic, restricted services, and suspicious connection patterns.
- **Corporate networks:** Monitor network activity and flag behavior that differs from expected patterns.
- **Cloud environments:** Analyze network flow logs to detect unusual communication patterns.
- **Security monitoring systems:** Provide alerts and event records for a security administrator to investigate.

## 13. How It Could Be Implemented in a Real Network

A practical implementation would require additional engineering beyond the current prototype.

1. **Collect authorized network telemetry:** Integrate with a packet-capture tool, network flow records, or supported firewall logs.
2. **Normalize the data:** Convert incoming records into a consistent format for the detection engine.
3. **Apply security rules:** Configure trusted networks, blocked sources, restricted services, and protocol policies.
4. **Run behavioral detection:** Establish suitable baselines and tune thresholds using representative traffic.
5. **Store and monitor events:** Use durable logging, access controls, retention policies, and monitoring.
6. **Validate detection quality:** Test against benign and malicious traffic in an isolated, authorized environment. Measure false positives, false negatives, detection latency, and resource usage.
7. **Add controlled enforcement:** Integrate with a supported operating-system or network firewall interface. Begin in monitor-only mode, then test enforcement with explicit safeguards and rollback procedures.
8. **Harden the deployment:** Secure configuration, protect logs, restrict administrative access, and monitor the health of the detection service.

The current project is a prototype and does not implement all these production requirements. It should not replace an established firewall or be connected to a live network for automatic blocking without further development and testing.

## 14. Limitations

- Traffic is generated by a simulator rather than collected from a live production network.
- Detection quality depends on the implemented rules, thresholds, and baseline behavior.
- Behavioral anomalies do not necessarily indicate malicious activity.
- A high anomaly score is not proof of an attack.
- The current `BLOCK` action represents a software decision, not guaranteed packet-level enforcement.
- The prototype has not been established as production-ready through large-scale performance or security testing.

## 15. Future Enhancements

- Integrate authorized live packet or network-flow collection.
- Improve behavioral baselines using representative traffic.
- Add configurable allowlists, blocklists, and per-network policies.
- Improve anomaly explanations and alert prioritization.
- Add authentication and role-based dashboard access.
- Add controlled firewall integration with rollback support.
- Evaluate precision, recall, false-positive rate, and processing latency.
- Add additional automated and integration tests.

## 16. Conclusion

The Adaptive Network Firewall demonstrates how predefined security rules and behavioral anomaly detection can be combined in one monitoring prototype. Its traffic simulator makes it possible to test security scenarios, while the Streamlit dashboard provides visibility into decisions, risks, and logs.

The project establishes a foundation for further development toward a network monitoring and response system. Live traffic collection, validated detection performance, and safe firewall enforcement are important next steps before real-world deployment.

## 17. Quick Commands for Project Review

Run these commands from the project folder in the VS Code PowerShell terminal.

**1. Verify the tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

**2. Start the application**

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

**3. Open the dashboard**

```text
http://localhost:8501
```

**4. Demonstrate the project in this order**

1. Normal traffic
2. Blacklisted IP
3. Suspicious port activity
4. Traffic spike or repeated SYN activity, if available
5. Event history, charts, and logs

**5. Finish by explaining**

- How rule-based filtering works.
- How behavioral anomaly detection works.
- How `ALLOW`, `ALERT`, and `BLOCK` decisions differ.
- How the dashboard and logs help an administrator.
- What must be added before the prototype can enforce rules on real network traffic.
