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

ShadowLab is **not a penetration testing tool** and **not a malware framework**.

It is a **behavioral detection simulator** designed to replicate how
**legitimate or semi-adversarial user-mode activity**
affects system telemetry and how those signals correlate with
Defender and EDR detections.

The goal is to understand:

- **Why behavior becomes detectable**
- **Which signals increase detection confidence**
- **How EDR systems correlate multiple weak indicators**

---

## Purpose

ShadowLab was developed as part of an **MSc Cybersecurity application portfolio**
to demonstrate **applied defensive research skills**, including:

- Behavioral detection systems
- Adversarial telemetry analysis
- Detection engineering fundamentals
- Ethical offensive research from a defensive perspective

All activity occurs **strictly in isolated lab environments**.

---

## How It Works (High-Level)

ShadowLab operates as a continuous behavioral analysis pipeline:

### 1. Telemetry Collection
- CPU usage patterns
- Memory consumption
- Thread activity
- File I/O behavior
- TCP connection churn
- Network traffic rates (bytes sent / received)

### 2. Security Signal Correlation
- Microsoft Defender event summaries
- Sysmon event summaries (when available)

### 3. Behavioral Scoring Engine
- Heuristic detection logic
- Optional Logistic Regression model
- AI-assisted contextual interpretation

### 4. Visualization & Reporting
- Real-time Streamlit dashboard
- Interactive charts and network graphs
- Exportable CSV, JSON, and PDF artifacts

---

## Core Concept

ShadowLab evaluates how **“normal” or “suspicious”**
system behavior appears from a **defensive detection perspective**.

Behavioral Risk Score interpretation:

- **0.0 – 0.3** → Stable, expected behavior  
- **0.4 – 0.6** → Anomalous or irregular patterns  
- **0.7 – 1.0** → Detectable or high-risk behavioral footprint  

This models how modern EDR solutions reason about **behavioral context**, not single events.

---

## Key Technologies & Features

### Core Technologies
- **Language:** Python 3.12.x  
- **Web Framework:** Streamlit  
- **Data Processing:** Pandas, NumPy  
- **Visualization:** Plotly  
- **Machine Learning:** Scikit-learn  
- **System Telemetry:** psutil  
- **Windows Integration:** pywin32  
- **Security Signals:** Microsoft Defender & Sysmon  
- **AI Integration:** OpenAI SDK (contextual interpretation only)  
- **Reporting:** ReportLab (PDF export)  
- **Storage:** SQLite  
- **Configuration:** PyYAML  

---

### Enhanced Features
- Live system & process-level telemetry
- Interactive Plotly charts
- Pyvis-based network graph visualization
- Historical telemetry storage via SQLite
- MITRE ATT&CK mapping for Defender & Sysmon events
- AbuseIPDB threat intelligence lookups
- Dynamic plugin-based scenario profiles
- AI-assisted behavioral interpretation
- Customizable PDF report generation
- Graceful degradation for optional dependencies

---

## Scenario Profiles

ShadowLab supports multiple behavioral scenarios:

- **Balanced**
- **CPU-Heavy**
- **Memory-Heavy**
- **Network-Heavy**
- **File I/O-Heavy**

Each profile highlights how different activity patterns influence
telemetry interpretation and detection confidence.

---

## Interactive Dashboard

The web dashboard provides **real-time visibility** into:

- System and process telemetry
- Defender & Sysmon event correlation
- Behavioral risk score evolution
- Network connection graphs

This demonstrates how **user-mode behavior alone**
can create defensive visibility.

---

## Demo Video (Live Research Preview)

A live demonstration is available on LinkedIn:

🔗 https://www.youtube.com/watch?v=wcn79OrndJY

The demo showcases:
- Real-time telemetry visualization
- Behavioral score changes
- Correlation between activity and Defender events

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
