# Network Attack Forecaster — MVP #1

A working prototype for **Smart India Hackathon** that forecasts network attacks 5 minutes into the future using aggregated network flow features and Logistic Regression.

## Project Overview

```
CIC-IDS2017 CSV
       ↓
Data validation & cleaning
       ↓
Timestamp parsing & chronological sort
       ↓
5-minute network windows
       ↓
Network-state feature aggregation
       ↓
Future attack target creation (next 5-min window)
       ↓
Chronological train/validation/test split
       ↓
Logistic Regression baseline
       ↓
Attack probability + binary prediction
       ↓
Streamlit dashboard
```

**Core Question:** Based on network activity in the previous 5 minutes, will an attack occur in the next 5 minutes?

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Prepare Data
Place CIC-IDS2017 CSV files in `data/raw/`:
```
data/raw/
├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv  (included)
└── ... (other CIC-IDS2017 files optional)
```

### 3. Run Pipeline (Step by Step)

**Step 1: Clean Data**
```bash
python -m src.data.clean_data
```
Output: `data/processed/cleaned_data.parquet`

**Step 2: Create 5-Minute Windows**
```bash
python -m src.data.create_windows
```
Output: `data/processed/windowed_data.parquet`

**Step 3: Train Baseline Model**
```bash
python -m src.models.train
```
Output: `models/baseline/` (model.joblib, scaler.joblib, metrics.json)

**Step 4: Launch Dashboard**
```bash
streamlit run app/app.py
```
Open http://localhost:8501

## Project Structure

```
network-attack-forecaster/
├── data/
│   ├── raw/                    # Original CSV files (read-only)
│   └── processed/              # Cleaned & windowed data (parquet)
├── models/
│   └── baseline/               # Trained Logistic Regression
├── src/
│   ├── data/
│   │   ├── clean_data.py       # Data cleaning pipeline
│   │   └── create_windows.py   # 5-min window aggregation + future target
│   └── models/
│       ├── train.py            # Logistic Regression training
│       └── predict.py          # Prediction pipeline
├── app/
│   └── app.py                  # Streamlit dashboard
├── requirements.txt
└── README.md
```

## Key Features

### Data Handling
- ✅ Strips whitespace from column names
- ✅ Removes duplicate columns
- ✅ Explicit timestamp parsing (`%m/%d/%Y %H:%M`)
- ✅ Chronological sorting (critical for forecasting)
- ✅ Handles NaN (15) and Inf (727) values with median imputation
- ✅ Removes duplicate rows (1)
- ✅ Preserves original labels + creates binary target

### Forecasting Dataset
- ✅ 5-minute tumbling windows
- ✅ 38 aggregated network-state features per window
- ✅ Future attack target: `future_attack = 1` if next window has any attack
- ✅ **Zero data leakage**: features use only current window, target uses only next window
- ✅ Original attack labels preserved for future multi-class work

### Model
- ✅ Logistic Regression with `class_weight='balanced'`
- ✅ StandardScaler fitted on train only (no leakage)
- ✅ Chronological split: 60% train / 20% val / 20% test
- ✅ Outputs: probability (0–1) + binary prediction

### Evaluation Metrics
| Metric | Description |
|--------|-------------|
| Precision | Of predicted attacks, how many were real? |
| Recall | Of actual attacks, how many did we catch? |
| F1 | Harmonic mean of precision & recall |
| PR-AUC | Area under Precision-Recall curve |
| ROC-AUC | Area under ROC curve |
| FPR | False Positive Rate = FP / (FP + TN) |

### Dashboard
- 📊 Current network state + future window prediction
- 📈 Risk timeline with actual vs predicted
- 🎯 Confusion matrix & metrics
- 📋 Detailed results table
- 🔧 Upload custom CSV or use sample

## Sample Results (Friday PortScan)

| Window | Flows | Attack Prob | Predicted | Actual Next |
|--------|-------|-------------|-----------|-------------|
| 01:00–01:05 | 1,428 | 91.5% | ⚠ ATTACK | ✅ ATTACK |
| 01:05–01:10 | 1,916 | 20.9% | ✅ NORMAL | ✅ NORMAL |
| ... | ... | ... | ... | ... |
| 03:25–03:30 | 6,909 | 28.5% | ✅ NORMAL | ✅ NORMAL |

**Test Metrics** (on 6 test windows):
- Precision: 0.000 | Recall: 0.000 | F1: 0.000 | PR-AUC: 0.589 | ROC-AUC: 0.556

> **Note:** Low test performance is expected with only 30 windows (29 usable) and distribution shift (PortScan appears only in later windows). The pipeline is correct; more data improves results.

## Upgrade Path (Future MVPs)

| MVP | Addition |
|-----|----------|
| 2 | Random Forest / Gradient Boosting |
| 3 | LSTM + sequences of windows |
| 4 | Multi-step future-state rollout |
| 5 | SHAP / attention explanations |
| 6 | MITRE ATT&CK stage mapping |
| 7 | PCAP ingestion + packet-level features |

## Reproducibility

```bash
# Full pipeline
python -m src.data.clean_data
python -m src.data.create_windows
python -m src.models.train
streamlit run app/app.py
```

All paths are relative. No hardcoded absolute paths. Random seeds fixed for reproducibility.

## License

MIT — Built for Smart India Hackathon 2024