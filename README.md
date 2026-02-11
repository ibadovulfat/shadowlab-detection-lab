# ShadowLab Defender Web Simulator

> **Note:** Usage requires explicit permission from the author.

**Created by [Ulfat Ibadov](https://www.linkedin.com/in/ibadovulfat/)**

![banner](static/shadowlab_banner.png)

ShadowLab Defender Web Simulator is an **ethical, lab-only behavioral research platform**
designed to **study how Microsoft Defender and modern EDR solutions interpret system behavior**
through local telemetry, Windows security event logs, and an **AI-assisted behavioral scoring engine**.

**No bypass. No exploit. No payload.**  
This project focuses on **behavioral visibility and defensive understanding**, not evasion.

---

## What Is ShadowLab?

ShadowLab is a **comprehensive behavioral security platform** designed for both **defensive research (Blue Team)** and **controlled offensive simulation (Red Team)**.

It provides a high-fidelity **behavioral detection environment** that replicates how:
- **Legitimate users** and **adversarial actors** interact with the system.
- **Modern EDR/AV solutions** (like Microsoft Defender) interpret various telemetry signals.
- **Security analysts** can hunt for persistence, analyze internals, and take active response actions.

By combining defensive monitoring with controlled offensive modules (like ARP spoofing and stress scenarios), it allows for **full-spectrum defensive understanding**—seeing the attack, the telemetry it generates, and the response it requires.

---

## Purpose

ShadowLab was developed as part of an **Advanced Cybersecurity Portfolio**
to demonstrate a holistic range of **applied offensive and defensive research skills**, including:

- **Advanced Behavioral Detection**: Monitoring and scoring complex process activities.
- **Forensic Internals**: Deep-dive analysis of process memory, handles, and loaded modules.
- **Incident Response**: Implementation of active mitigation (Suspend/Kill) and audit logging.
- **Deception Technology**: Deploying and monitoring honeypots and ransomware canary files.
- **Threat Intelligence**: Automated correlation of telemetry with VirusTotal, AbuseIPDB, and MITRE ATT&CK.
- **Offensive Network Warfare**: Mastering layer-2 discovery and ARP spoofing from a defensive perspective.
- **Generative AI Analysis**: Integrating LLMs for contextual threat explainability.

All activity is conducted **strictly for research and educational purposes in isolated lab environments**.

---

## How It Works (High-Level)

ShadowLab operates as a continuous behavioral analysis pipeline:

### 1. Telemetry & Deep Internals
- **Live Monitoring**: CPU, RAM, Disk, and Network telemetry via `psutil`.
- **Hacker Internals**: Enumeration of open Handles (Files/Sockets) and loaded Modules (DLL/dylib).
- **String Inspector**: Printable ASCII/Unicode extraction from binaries.

### 2. Advanced Threat Hunting
- **Process Tree**: Interactive parent-child relationship visualization via `pyvis`.
- **YARA Scanning**: Deep scanning of process binaries using custom weaponized rules.
- **Network Sniffer**: Real-time packet capture and DNS query analysis via `scapy`.
- **Sandbox Tracer**: Real-time syscall-like monitoring of file handles and network connections.
- **Persistence Hunting**: Detection of LaunchAgents, Daemons, and Cron persistence.

### 3. Enterprise Defense & AI
- **Deception (Honeypot)**: Hidden honey-files that trigger immediate alerts on access.
- **Ransomware Canary**: Watchdog-monitored decoy files to detect unauthorized encryption.
- **AI Analyst (GenAI)**: LLM-powered interpretation of process behavior for better explainability.
- **Evidence Locker**: Automated screen capture triggered by high-severity incidents.

### 4. Network Warfare (Red Team)
- **ARP Discovery**: Local subnet scanner to discover connected devices (Phones, IoT, PCs).
- **WiFi Kicker**: Targeted ARP Spoofing to disconnect specific devices from the network.

---

## Technical Features & Stack

### Core Technologies
- **Traffic Analysis**: [Scapy](https://scapy.net/) (ARP/ICMP/TCP engineering)
- **Malware Signatures**: [YARA](https://github.com/VirusTotal/yara-python)
- **Host Telemetry**: [psutil](https://psutil.readthedocs.io/)
- **Visuals**: [Pyvis](https://pyvis.readthedocs.io/) (Dynamic Graphviz)
- **Forensics**: [Watchdog](https://github.com/gorakhargosh/watchdog), [PyAutoGUI](https://pyautogui.readthedocs.io/)

### Advanced Capabilities
- **MITRE ATT&CK Mapping**: Automatic correlation of security events to industry-standard techniques.
- **Scenario Simulation**: Dynamic stress profiles (CPU/RAM/Net/Disk) to test EDR visibility.
- **Statistical Anomaly Detection**: Z-Score based outlier detection for anomalous processes.
- **Fleet Management**: Simulation of multi-agent command and control (C2).
- **Response Actions**: Immediate process Suspend/Kill/Resume with audit logging.

---

## Interactive Dashboard

The web dashboard provides **real-time visibility** into:
- System and process telemetry
- Advanced Hunting & Forensic Internals
- Automated Deception & Ransomware Protection
- Network Warfare & Offensive Simulation
- MITRE-aligned event logs and historical data

---

## Demo Video (Live Research Preview)

A live demonstration is available on YouTube:

🔗 https://www.youtube.com/watch?v=5mdvXMRVc80

---

## Quickstart

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```
