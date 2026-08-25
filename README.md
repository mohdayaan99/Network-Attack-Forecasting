# 🛡️ Network Attack Forecasting System

Proactive network threat forecasting using 5-minute window aggregations and Machine Learning.

---

## 📌 Project Overview
Unlike traditional Intrusion Detection Systems (IDS) that react *after* an attack occurs, this system aggregates network flow metrics into **5-minute time windows** to forecast attack probabilities and risk levels before full threat execution.

---

## 🏗️ System Architecture

```text
Raw Network Data (CIC-IDS2017)
       ↓
Data Preprocessing & 5-Min Aggregations (src/preprocessing.py)
       ↓
ML Baseline Model Training (src/model_training.py)
       ↓
FastAPI Prediction Engine (src/backend/app.py)
       ↓
Streamlit Live Dashboard (src/app.py)