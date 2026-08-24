"""
Prediction module for trained model.
"""
import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from src.data.clean_data import clean_data
from src.data.create_windows import create_forecasting_dataset


def load_model(model_dir: str):
    """Load model, scaler, and feature columns."""
    model = joblib.load(Path(model_dir) / 'model.joblib')
    scaler = joblib.load(Path(model_dir) / 'scaler.joblib')
    with open(Path(model_dir) / 'feature_cols.json') as f:
        feature_cols = json.load(f)
    return model, scaler, feature_cols


def predict_window_features(model, scaler, feature_cols, window_features: pd.DataFrame):
    """Predict attack probability for a single window's features."""
    X = window_features[feature_cols].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median())
    X_scaled = scaler.transform(X)
    proba = model.predict_proba(X_scaled)[:, 1]
    pred = (proba >= 0.5).astype(int)
    return proba[0], pred[0]


def process_csv_for_dashboard(csv_path: str, model_dir: str):
    """Full pipeline: raw CSV -> cleaned -> windows -> predictions."""
    # Clean
    cleaned_path = "data/processed/temp_cleaned.parquet"
    df = clean_data(csv_path, cleaned_path)
    
    # Create windows
    windowed_path = "data/processed/temp_windowed.parquet"
    windows_df = create_forecasting_dataset(cleaned_path, windowed_path)
    
    # Load model
    model, scaler, feature_cols = load_model(model_dir)
    
    # Predict for each window
    results = []
    for _, row in windows_df.iterrows():
        proba, pred = predict_window_features(model, scaler, feature_cols, 
                                               pd.DataFrame([row]))
        results.append({
            'window_start': row['window_start'],
            'window_end': row['window_end'],
            'total_flows': row['total_flows'],
            'attack_probability': proba,
            'predicted_attack': pred,
            'future_attack_actual': row['future_attack'],
            'future_label': row['future_dominant_label']
        })
    
    results_df = pd.DataFrame(results)
    return results_df


if __name__ == "__main__":
    # Test with our data
    results = process_csv_for_dashboard(
        "data/raw/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "models/baseline"
    )
    print(results[['window_start', 'window_end', 'attack_probability', 
                   'predicted_attack', 'future_attack_actual']].to_string())