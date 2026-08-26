"""
Train Logistic Regression baseline with chronological split.
"""
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (precision_score, recall_score, f1_score, 
                             average_precision_score, confusion_matrix,
                             roc_auc_score)
import joblib
import json


def prepare_features(df: pd.DataFrame):
    """Select and prepare numerical features for modeling."""
    # Exclude non-feature columns
    exclude_cols = ['window_start', 'window_end', 'window_attack_count', 
                    'window_attack_ratio', 'window_dominant_label',
                    'future_attack', 'future_attack_ratio', 'future_dominant_label',
                    'window_has_attack']
    
    feature_cols = [c for c in df.columns if c not in exclude_cols]
    X = df[feature_cols].copy()
    y = df['future_attack'].copy()
    
    # Handle any remaining NaN/Inf
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median())
    
    print(f"  Features: {len(feature_cols)}")
    print(f"  Feature names: {feature_cols}")
    return X, y, feature_cols


def chronological_split(X, y, train_ratio=0.6, val_ratio=0.2):
    """Split chronologically: train -> val -> test."""
    n = len(X)
    train_end = int(n * train_ratio)
    val_end = int(n * (train_ratio + val_ratio))
    
    X_train, y_train = X.iloc[:train_end], y.iloc[:train_end]
    X_val, y_val = X.iloc[train_end:val_end], y.iloc[train_end:val_end]
    X_test, y_test = X.iloc[val_end:], y.iloc[val_end:]
    
    print(f"  Train: {len(X_train)} samples (indices 0-{train_end-1})")
    print(f"  Val:   {len(X_val)} samples (indices {train_end}-{val_end-1})")
    print(f"  Test:  {len(X_test)} samples (indices {val_end}-{n-1})")
    print(f"  Train class dist: {y_train.value_counts().to_dict()}")
    print(f"  Val class dist:   {y_val.value_counts().to_dict()}")
    print(f"  Test class dist:  {y_test.value_counts().to_dict()}")
    
    return X_train, X_val, X_test, y_train, y_val, y_test


def train_model(X_train, y_train, X_val, y_val):
    """Train Logistic Regression with scaling."""
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    
    # Class weight balanced for imbalanced data
    model = LogisticRegression(
        class_weight='balanced',
        max_iter=1000,
        random_state=42,
        solver='lbfgs'
    )
    model.fit(X_train_scaled, y_train)
    
    # Validation predictions
    val_proba = model.predict_proba(X_val_scaled)[:, 1]
    val_pred = (val_proba >= 0.5).astype(int)
    
    return model, scaler, val_proba, val_pred


def evaluate_model(y_true, y_pred, y_proba, split_name):
    """Compute all required metrics."""
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    pr_auc = average_precision_score(y_true, y_proba)
    roc_auc = roc_auc_score(y_true, y_proba)
    cm = confusion_matrix(y_true, y_pred)
    
    # False Positive Rate = FP / (FP + TN)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    metrics = {
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'pr_auc': float(pr_auc),
        'roc_auc': float(roc_auc),
        'fpr': float(fpr),
        'confusion_matrix': cm.tolist(),
        'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)
    }
    
    print(f"\n  {split_name} Metrics:")
    print(f"    Precision:  {precision:.4f}")
    print(f"    Recall:     {recall:.4f}")
    print(f"    F1:         {f1:.4f}")
    print(f"    PR-AUC:     {pr_auc:.4f}")
    print(f"    ROC-AUC:    {roc_auc:.4f}")
    print(f"    FPR:        {fpr:.4f}")
    print(f"    Confusion Matrix:")
    print(f"      TN={tn} FP={fp}")
    print(f"      FN={fn} TP={tp}")
    
    return metrics


def save_model(model, scaler, feature_cols, metrics, output_dir):
    """Save model, scaler, and metadata."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    joblib.dump(model, Path(output_dir) / 'model.joblib')
    joblib.dump(scaler, Path(output_dir) / 'scaler.joblib')
    
    with open(Path(output_dir) / 'feature_cols.json', 'w') as f:
        json.dump(feature_cols, f)
    
    with open(Path(output_dir) / 'metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    
    print(f"\n  Saved model to {output_dir}")


def train_baseline(input_path: str, model_dir: str):
    """Full training pipeline."""
    print(f"Loading windowed data: {input_path}")
    df = pd.read_parquet(input_path)
    print(f"  Loaded shape: {df.shape}")
    
    X, y, feature_cols = prepare_features(df)
    X_train, X_val, X_test, y_train, y_val, y_test = chronological_split(X, y)
    
    model, scaler, val_proba, val_pred = train_model(X_train, y_train, X_val, y_val)
    
    # Evaluate on validation
    val_metrics = evaluate_model(y_val, val_pred, val_proba, "Validation")
    
    # Evaluate on test
    X_test_scaled = scaler.transform(X_test)
    test_proba = model.predict_proba(X_test_scaled)[:, 1]
    test_pred = (test_proba >= 0.5).astype(int)
    test_metrics = evaluate_model(y_test, test_pred, test_proba, "Test")
    
    # Save
    all_metrics = {
        'validation': val_metrics,
        'test': test_metrics,
        'feature_cols': feature_cols,
        'n_features': len(feature_cols)
    }
    save_model(model, scaler, feature_cols, all_metrics, model_dir)
    
    return model, scaler, feature_cols, all_metrics


if __name__ == "__main__":
    input_file = "data/processed/windowed_data.parquet"
    model_dir = "models/baseline"
    train_baseline(input_file, model_dir)