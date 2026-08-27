import os
import argparse
import pickle
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score, precision_recall_fscore_support
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader

# ==========================================
# 1. Dataset & 5-Minute Sliding Window Logic
# ==========================================
class NetworkWindowDataset(Dataset):
    def __init__(self, sequences, targets):
        self.sequences = torch.tensor(sequences, dtype=torch.float32)
        self.targets = torch.tensor(targets, dtype=torch.float32)

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        return self.sequences[idx], self.targets[idx]

def process_sliding_windows(df, window_size_minutes=5, seq_len=10):
    """
    Groups traffic into sliding windows and builds sequence history.
    """
    # Ensure timestamp is datetime
    if 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        df = df.sort_values('Timestamp')
    else:
        # Fallback or synthetic timestamp index if missing in demo
        df['Timestamp'] = pd.date_range(start='2026-01-01', periods=len(df), freq='S')

    # Set index to timestamp for resampling
    df.set_index('Timestamp', inplace=True)
    
    # Resample / Aggregate into 5-minute windows
    window_str = f"{window_size_minutes}min"
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    if 'Label' in numeric_cols:
        numeric_cols.remove('Label')

    # Aggregate features (mean) and target (max -> if any attack occurred in window)
    agg_dict = {col: 'mean' for col in numeric_cols}
    if 'Label' in df.columns:
        agg_dict['Label'] = 'max'

    resampled = df.resample(window_str).agg(agg_dict).dropna()
    
    features = resampled.drop(columns=['Label'], errors='ignore').values
    labels = resampled['Label'].values if 'Label' in resampled.columns else np.zeros(len(resampled))

    # Normalize features
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    # Build sequence history (e.g., 10 prior time windows predicting state)
    X, y = [], []
    for i in range(seq_len, len(features_scaled)):
        X.append(features_scaled[i-seq_len:i])
        y.append(labels[i])

    return np.array(X), np.array(y), scaler

# ==========================================
# 2. PyTorch LSTM Sequence World Model
# ==========================================
class LSTMWorldModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2):
        super(LSTMWorldModel, self).__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=0.2)
        self.fc = nn.Linear(hidden_dim, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out[:, -1, :])  # Take last time step
        return self.sigmoid(out)

# ==========================================
# 3. Training Pipeline
# ==========================================
def main():
    parser = argparse.ArgumentParser(description="Train Baseline and Sequence World Model for NTRO Forecaster")
    parser.add_argument("--data_path", type=str, required=True, help="Path to raw flow CSV (CIC-IDS2017 format)")
    args = parser.parse_args()

    print(f"[*] Loading dataset from {args.data_path}...")
    if not os.path.exists(args.data_path):
        raise FileNotFoundError(f"Data file not found at {args.data_path}. Please provide a valid sample.")

    df = pd.read_csv(args.data_path)

    print("[*] Generating 5-minute sliding windows...")
    X, y, scaler = process_sliding_windows(df, window_size_minutes=5, seq_len=10)

    if len(X) == 0:
        raise ValueError("Dataset is too small to construct sliding windows with sequence length 10. Provide a larger CSV.")

    # Time-based split: First 70% train, last 30% test
    split_idx = int(len(X) * 0.7)
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]

    print(f"[*] Training samples: {len(X_train)} | Testing samples: {len(X_test)}")

    # ------------------------------------------
    # Train Baseline Model (Logistic Regression)
    # ------------------------------------------
    print("[*] Training Baseline Model (Logistic Regression)...")
    # Flatten sequence for baseline: (Batch, Seq_Len, Features) -> (Batch, Seq_Len * Features)
    X_train_flat = X_train.reshape(X_train.shape[0], -1)
    X_test_flat = X_test.reshape(X_test.shape[0], -1)

    baseline_model = LogisticRegression(max_iter=1000)
    baseline_model.fit(X_train_flat, y_train)

    os.makedirs("models/baseline", exist_ok=True)
    with open("models/baseline/model.pkl", "wb") as f:
        pickle.dump({"model": baseline_model, "scaler": scaler}, f)
    print("[+] Baseline model saved to models/baseline/model.pkl")

    # ------------------------------------------
    # Train Sequence World Model (PyTorch LSTM)
    # ------------------------------------------
    print("[*] Training Sequence World Model (LSTM)...")
    train_dataset = NetworkWindowDataset(X_train, y_train)
    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)

    input_dim = X_train.shape[2]
    world_model = LSTMWorldModel(input_dim=input_dim)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(world_model.parameters(), lr=0.001)

    world_model.train()
    epochs = 5
    for epoch in range(epochs):
        epoch_loss = 0
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            preds = world_model(batch_x).squeeze()
            loss = criterion(preds, batch_y)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
        print(f"    Epoch {epoch+1}/{epochs} - Loss: {epoch_loss/len(train_loader):.4f}")

    os.makedirs("models/world_model", exist_ok=True)
    torch.save(world_model.state_dict(), "models/world_model/lstm.pt")
    print("[+] World Model weights saved to models/world_model/lstm.pt")

    # Save test sets for evaluation script use
    np.savez("models/test_data.npz", X_test=X_test, X_test_flat=X_test_flat, y_test=y_test)
    print("[*] Training completed successfully!")

if __name__ == "__main__":
    main()