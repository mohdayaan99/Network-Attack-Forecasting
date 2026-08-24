================================================================================
NETWORK ATTACK FORECASTER — MVP #1
Smart India Hackathon Project
================================================================================

WHAT THIS DOES:
---------------
This tool predicts whether a network attack will occur in the NEXT 5 minutes
based on network activity observed in the PREVIOUS 5 minutes.

Input:  CIC-IDS2017 CSV network flow data
Output: Attack probability (0-100%) + binary prediction (ATTACK / NORMAL)

Pipeline:
  Raw CSV → Clean → 5-min windows → Features → Logistic Regression → Prediction → Dashboard


================================================================================
QUICK START (3 STEPS)
================================================================================

STEP 1: EXTRACT & INSTALL
-------------------------
1. Extract "network-attack-forecaster.zip" to a folder
2. Open terminal/command prompt in that folder
3. Run:
   pip install -r requirements.txt

   This installs: pandas, numpy, scikit-learn, pyarrow, joblib, streamlit, plotly


STEP 2: ADD YOUR DATA
---------------------
1. Go to the extracted folder
2. Create folder: data/raw/
3. Copy your CIC-IDS2017 CSV file there
   Example: Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv

   (A sample CSV is included in this SHARE folder)


STEP 3: RUN PIPELINE (4 commands)
----------------------------------
Run these ONE BY ONE in terminal:

   python -m src.data.clean_data
   python -m src.data.create_windows
   python -m src.models.train
   streamlit run app/app.py

The last command opens the dashboard in your browser at http://localhost:8501


================================================================================
DETAILED INSTRUCTIONS
================================================================================

PREREQUISITES:
- Python 3.9+ installed
- pip (comes with Python)
- 2GB+ free disk space

FOLDER STRUCTURE AFTER EXTRACT:
network-attack-forecaster/
├── src/
│   ├── data/
│   │   ├── clean_data.py       # Cleans CSV, parses timestamps
│   │   └── create_windows.py   # Makes 5-min windows + future target
│   └── models/
│       ├── train.py            # Trains Logistic Regression
│       └── predict.py          # Prediction logic
├── app/
│   └── app.py                  # Streamlit dashboard
├── requirements.txt            # Python dependencies
└── README.md                   # Full documentation


WHAT EACH COMMAND DOES:
-----------------------

1) python -m src.data.clean_data
   - Reads CSV from data/raw/
   - Strips whitespace from column names
   - Parses timestamps (format: M/D/YYYY H:MM)
   - Sorts chronologically (CRITICAL for forecasting)
   - Handles NaN/Inf values (median fill)
   - Removes duplicate rows
   - Creates binary label: BENIGN=0, Attack=1
   - Saves: data/processed/cleaned_data.parquet

2) python -m src.data.create_windows
   - Groups flows into 5-minute windows
   - Aggregates 38 network-state features per window
   - Creates FUTURE target: attack in NEXT 5-min window?
   - Ensures NO DATA LEAKAGE (features=current window, target=next window)
   - Saves: data/processed/windowed_data.parquet

3) python -m src.models.train
   - Chronological split: 60% train / 20% val / 20% test
   - StandardScaler fitted on TRAIN only
   - Logistic Regression with class_weight='balanced'
   - Evaluates: Precision, Recall, F1, PR-AUC, ROC-AUC, FPR, Confusion Matrix
   - Saves: models/baseline/model.joblib, scaler.joblib, metrics.json

4) streamlit run app/app.py
   - Launches web dashboard at http://localhost:8501
   - Shows: current state, risk gauge, timeline, confusion matrix, metrics table
   - Can upload new CSV or use sample data


================================================================================
DASHBOARD FEATURES
================================================================================

- Current Network State: Shows time window, flow count
- Future Window: The 5-min window being predicted
- Attack Probability: 0-100% (color-coded gauge)
- Prediction: "⚠ ATTACK LIKELY" or "✅ NORMAL"
- Risk Timeline: Line chart of probability over time with actual attacks marked
- Confusion Matrix: Model performance on your data
- Metrics: Precision, Recall, F1, PR-AUC, ROC-AUC, FPR
- Detailed Table: Every window with prediction vs actual


================================================================================
TROUBLESHOOTING
================================================================================

"ModuleNotFoundError: No module named 'src'"
→ Run commands from the ROOT folder (where src/ folder is)

"FileNotFoundError: data/raw/...csv"
→ Create data/raw/ folder and put your CSV there

"Port 8501 already in use"
→ Run: streamlit run app/app.py --server.port 8502

"pip install fails"
→ Upgrade pip first: python -m pip install --upgrade pip

Dashboard shows no data
→ Check CSV has correct columns (CIC-IDS2017 format)


================================================================================
EXPECTED RESULTS (Sample Friday PortScan Data)
================================================================================

- 286,466 flows → 30 windows (5-min each) → 29 usable samples
- 38 features per window
- Future attack rate: ~41% (12/29 windows)
- Test metrics (6 windows): PR-AUC ~0.59, ROC-AUC ~0.56
- Low accuracy is EXPECTED with small dataset — pipeline is correct

To improve: Add more CIC-IDS2017 CSV files (Monday, Tuesday, Wednesday, etc.)
to data/raw/ and re-run pipeline.


================================================================================
FILES IN THIS SHARE FOLDER
================================================================================

SHARED/
├── network-attack-forecaster.zip    # Source code (extract this)
├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv  # Sample data
└── README.txt                       # This file


================================================================================
NEXT STEPS FOR HACKATHON (MVP #2+)
================================================================================

MVP #2: Add Random Forest / XGBoost
MVP #3: Add LSTM for temporal sequences
MVP #4: Multi-step future rollout
MVP #5: SHAP explanations
MVP #6: MITRE ATT&CK mapping
MVP #7: PCAP ingestion

See README.md in the zip for full upgrade path.


================================================================================
CONTACT / HELP
================================================================================

If issues:
1. Check Python version: python --version (need 3.9+)
2. Check installed packages: pip list | findstr pandas
3. Re-run: pip install -r requirements.txt
4. Ensure CSV is CIC-IDS2017 GeneratedLabelledFlows format

================================================================================