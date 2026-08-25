# Data Preprocessing Report

## Overview
Created a reusable data cleaning pipeline (`src/preprocessing.py`) to resolve schema and data quality issues found in the raw CIC-IDS2017 network traffic dataset.

## Key Issues & Fixes Applied
1. **Column Header Whitespace:** Stripped leading/trailing spaces from column names (e.g., `' Destination Port'` → `'Destination Port'`) to ensure proper feature mapping.
2. **Timestamp Standardisation:** Parsed `Timestamp` strings into datetime objects using mixed-format parsing for accurate 5-minute time windowing.
3. **Label Sanitization:** Stripped extra spaces from class labels (e.g., `'BENIGN '` → `'BENIGN'`).
4. **Infinite & Missing Values:** Replaced `+Inf` and `-Inf` with `NaN` and dropped null rows to prevent ML model crash/errors.
5. **Deduplication:** Removed exact duplicate flow entries to avoid data leakage and overfitting.

## Script Usage
```python
from src.preprocessing import clean_cic_ids_data

df = clean_cic_ids_data("path/to/raw_cic_ids.csv")