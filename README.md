# ??? Predictive Cyber Defence & Automated Threat Forecasting Platform

> **AI-Powered Proactive Network Threat Forecasting using Temporal Sequence Models & Automated Containment**  
> *Developed for Smart India Hackathon (SIH Team: SIH26153)*

---

## ?? Executive Summary

Traditional Intrusion Detection Systems (IDS) react **after** a breach occurs, analyzing network flows in isolation. Our platform models dynamic network state transitions over temporal 5-minute windows $P(S_{t+1} \mid S_t)$ to predict multi-stage attack trajectories (Reconnaissance ? DDoS ? Data Exfiltration) **before** compromise materializes.

---

## ?? Core Features & Platform Capabilities

- **Heavy Data Ingestion Engine:** Supports up to **1000MB (1GB)** network flow CSV/PCAP datasets (CIC-IDS2017) using an **8MB Chunked Stream Buffer** to eliminate browser memory crashes.
- **Dynamic Attack Vector Classification:** Automatic taxonomy classification identifying specific kill-chain vectors:
  - ?? **DDoS / Distributed Denial of Service**
  - ?? **PortScan (Reconnaissance & Probe)**
  - ?? **Web Attacks (SQL Injection / XSS)**
  - ?? **Infiltration & Lateral Movement**
- **Data Loss & Risk Exposure Estimator:** Live calculation comparing current exfiltrated traffic (~235 MB) against 5-minute forecasted potential loss exposure (~518 MB).
- **Automated Threat Mitigation Console:** SOC-ready interactive response triggering automated firewall rate-limiting, egress port isolation, and TCP session quarantine.
- **MITRE ATT&CK Stage Mapping:** Structured output aligning predictions directly with standardized adversary behavior frameworks.

---

## ??? System Architecture & Workflow
>> ```
>> Raw Network Telemetry (CIC-IDS2017 / NetFlow / PCAP)
>>        ?
>> 8MB Stream Chunking & Data Preprocessing (src/preprocessing.py)
>>        ?
>> 5-Minute Temporal Windowing & Feature Aggregation (38 Network-State Features)
>>        ?
>> Sequence Prediction Model / Logistic Baseline (models/baseline/)
>>        ?
>> Streamlit Live Defense Dashboard & Mitigation Engine (app/app.py)
>> ```
>>
>> ---
>>
>> ## ? Quick Start & Deployment Guide
>>
>> ### 1. Environment Setup
>>
>> ```bash
>> # Clone the repository
>> git clone [https://github.com/mohdayaan99/Network-Attack-Forecasting.git](https://github.com/mohdayaan99/Network-Attack-Forecasting.git)
>> cd Network-Attack-Forecasting
>>
>> # Create and activate virtual environment
>> python -m venv .venv
>> .venv\Scripts\activate  # Windows
>> source .venv/bin/activate  # Linux/macOS
>>
>> # Install dependencies
>> pip install -r requirements.txt
>> ```
>>
>> ### 2. Launching the Defense Dashboard
>>
>> ```bash
>> python -m streamlit run app/app.py --server.maxUploadSize=1000 --server.maxMessageSize=1000
>> ```
>> Open **http://localhost:8501** in your browser.
>>
>> ---
>>
>> ## ?? Team Members & Contributions
>>
>> - **Mohd Ayan (Lead / Member 1):** System Architecture, Streamlit Dashboard UI, Heavy File Chunking, Data Loss Calculator & Mitigation Engine Console.
>> - **Abdul Rafey (Member 2):** Preprocessing Pipeline, Packet-Level PCAP Parsing & Feature Extraction.
>> - **Abdullah Naseer (Member 3):** Temporal Sequence Model Architecture & Baseline ML Training.
>> - **Mubeen Uddin (Member 4):** Threat Intelligence, World Model Specification & MITRE ATT&CK Framework Mapping.
>>
>> ---
>>
>> ## ?? License
>> MIT License — Built for Smart India Hackathon.
