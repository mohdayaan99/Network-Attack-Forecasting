# ??? NetForecast: Temporal Network-Attack Forecasting Platform

> **An Offline Enterprise Prototype for Explainable Temporal Attack Forecasting, Telemetry Ingestion, and Controlled Defense Recommendations**  
> *Developed for Smart India Hackathon (SIH Team: SIH26153)*

---

## ?? Executive Summary

**NetForecast** is an offline prototype designed to evaluate proactive network-threat forecasting. Traditional Intrusion Detection Systems (IDS) react *after* packet anomalies trigger signatures. NetForecast converts streaming network telemetry into time-windowed network states $S_t$, models dynamic state transitions $P(S_{t+1} \mid S_t)$, and estimates future attack probabilities over subsequent time windows ($t+1$ to $t+K$).

The platform integrates heavy telemetry ingestion (up to 1 GB tested locally), attack-behavior classification, traffic-based exposure estimation, and an operator-in-the-loop controlled mitigation interface.

---

## ?? Implementation Status & Feature Matrix

| Capability | Status | Implementation Detail |
| :--- | :--- | :--- |
| **CSV Telemetry Ingestion** | ? Implemented | Supports CIC-IDS2017 / CIC-IDS2018 flow formats |
| **Stream Buffer Processing** | ? Implemented | 8MB chunked reading for handling heavy files up to 1 GB |
| **5-Min Temporal Windowing** | ? Implemented | Non-overlapping tumbling windows aggregating 38 state features |
| **Baseline Forecasting Model** | ? Implemented | Logistic Regression with class balancing ($t \to t+1$ prediction) |
| **Attack-Type Behavior Inference**| ? Implemented | Heuristic & label-mapped vector taxonomy (DDoS, PortScan, Web) |
| **Data Exposure Estimation** | ?? Simulated Estimate | Traffic-based heuristic estimation of suspicious outbound bytes |
| **Controlled Defense Console** | ?? Controlled / Sim | Operator-in-the-loop manual action triggers (Firewall, Egress Lock) |
| **MITRE ATT&CK Mapping** | ? Implemented | Mapping predictions to Reconnaissance, Impact & Exfiltration tactics |
| **Sequence Models (LSTM/Transformer)**| ?? Planned / Research | Extended multi-step rollout ($t+K$) for future iterations |

---

## ?? Mathematical Formulation & State Definition

### Network State Definition ($S_t$)
Each 5-minute tumbling window $S_t$ is summarized by a 38-dimensional feature vector $\mathbf{x}_t$ capturing volume, flow dynamics, protocol distributions, and TCP flag rates:

$$\mathbf{x}_t = \Big[ \text{TotalFlows}, \text{FlowDuration}_{\text{avg}}, \text{SYN}_{\text{rate}}, \text{ACK}_{\text{rate}}, \text{Bytes/Sec}_{\text{avg}}, \dots \Big]$$

### Forecasting Objective
The objective is to compute the likelihood of an attack occurring in the future window $S_{t+1}$ given the current window $S_t$:

$$P(Y_{t+1} = 1 \mid S_t) = \sigma(\mathbf{w}^T \mathbf{x}_t + b)$$

* **Zero Data Leakage:** Features in $S_t$ are computed strictly using packets arriving within $[t-5\text{min}, t]$. Target labels $Y_{t+1}$ are derived exclusively from traffic in $[t, t+5\text{min}]$.

---

## ?? Key Platform Capabilities

- **Large Telemetry Ingestion:** Designed with chunked buffer streams to process heavy CSV files (up to 1 GB on target hardware) without browser memory crashes.
- **Attack-Type & Behavior Classification:** Classifies risk probability alongside mapped behaviors (e.g., *PortScan / Reconnaissance*, *DDoS / Volumetric Impact*).
- **Potential Exposure Estimate:** Provides a traffic-based estimate of observed outbound volume vs. potential 5-minute exposure window to assist SOC analysts in triaging data risk.
- **Human-in-the-Loop Controlled Defense Console:** Recommends targeted firewall rate-limiting, egress port locks, and session isolation. All actions require operator approval before execution.

---

## ??? System Architecture

```text
Raw Network Telemetry (CIC-IDS2017 / NetFlow CSV)
       ?
Chunked Processing & Cleansing (src/preprocessing.py)
       ?
5-Minute Temporal Aggregation (38 Features / Window)
       ?
Temporal Forecasting Model (models/baseline/)
       ?
Interactive Streamlit Defense Console (app/app.py)
>> ```
>>
>> ---
>>
>> ## ? Quick Start & Reproducibility Guide
>>
>> ### 1. Requirements & Setup
>>
>> - **Python:** `3.10` – `3.12` recommended
>> - **Supported Datasets:** `CIC-IDS2017` / `CIC-IDS2018` GeneratedLabelledFlows
>>
>> ```bash
>> # Clone the repository
>> git clone https://github.com/mohdayaan99/Network-Attack-Forecasting.git
>> cd Network-Attack-Forecasting
>>
>> # Create virtual environment
>> python -m venv .venv
>> .venv\Scripts\activate  # Windows
>> source .venv/bin/activate  # Linux/macOS
>>
>> # Install dependencies
>> pip install -r requirements.txt
>> ```
>>
>> ### 2. Running the Pipeline
>>
>> ```bash
>> # Step 1: Clean Raw Dataset
>> python -m src.data.clean_data
>>
>> # Step 2: Create 5-Minute Window Features
>> python -m src.data.create_windows
>>
>> # Step 3: Train Baseline Model
>> python -m src.models.train
>> ```
>>
>> ### 3. Launching the Dashboard
>>
>> ```bash
>> python -m streamlit run app/app.py --server.maxUploadSize=1000 --server.maxMessageSize=1000
>> ```
>> Access the application at: **`http://localhost:8501`**
>>
>> ---
>>
>> ## ?? Known Limitations & Scope
>>
>> 1. **Dataset Scope:** The baseline model performance depends on available temporal attack windows in the dataset. Synthetic or single-attack datasets (e.g., Friday PortScan only) may exhibit class imbalance.
>> 2. **Exposure Estimates:** Data exfiltration numbers are heuristic inferences based on observed outbound byte spikes and should not be interpreted as byte-exact forensic evidence.
>> 3. **Defense Execution:** Mitigation actions on the console are simulated for demonstration safety and do not alter host routing tables automatically.
>>
>> ---
>>
>> ## ?? Team Members & Contributions
>>
>> - **Mohd Ayan (Lead):** Dashboard Architecture, Streamlit File-Buffer Chunking, Impact Metrics & Defense Console UI.
>> - **Abdul Rafey:** Data Preprocessing, Temporal Aggregation Pipeline & PCAP Parsing.
>> - **Abdullah Naseer:** Baseline ML Training, Scaler Pipelines & Model Artifact Persistence.
>> - **Mubeen Uddin:** Threat Modeling, MITRE ATT&CK Mapping & Presentation Architecture.
>>
>> ---
>>
>> ## ?? License
>> MIT License — Built for Smart India Hackathon.
