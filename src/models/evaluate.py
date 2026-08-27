import pickle
import numpy as np
import torch
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from train import LSTMWorldModel

def calculate_lead_time(y_true, y_pred_proba, threshold=0.5, window_seconds=300):
    """
    Calculates Mean Early Warning Lead Time (seconds before attack state completion).
    """
    preds = (y_pred_proba >= threshold).astype(int)
    lead_times = []
    
    in_attack_sequence = False
    attack_start_idx = 0
    
    for i in range(len(y_true)):
        if y_true[i] == 1 and not in_attack_sequence:
            in_attack_sequence = True
            attack_start_idx = i
        elif y_true[i] == 0 and in_attack_sequence:
            # Check when model first warned during this sequence
            warning_indices = np.where(preds[attack_start_idx:i] == 1)[0]
            if len(warning_indices) > 0:
                first_warning = attack_start_idx + warning_indices[0]
                lead_windows = i - first_warning
                lead_times.append(lead_windows * window_seconds)
            in_attack_sequence = False

    return np.mean(lead_times) if lead_times else 0.0

def evaluate():
    print("[*] Loading test data and models...")
    try:
        test_data = np.load("models/test_data.npz")
        X_test = test_data["X_test"]
        X_test_flat = test_data["X_test_flat"]
        y_test = test_data["y_test"]
    except FileNotFoundError:
        print("[-] Test data not found. Please run training first: python src/models/train.py --data_path <path>")
        return

    # Load Baseline
    with open("models/baseline/model.pkl", "rb") as f:
        baseline_data = pickle.load(f)
    baseline_model = baseline_data["model"]

    # Load World Model
    input_dim = X_test.shape[2]
    world_model = LSTMWorldModel(input_dim=input_dim)
    world_model.load_state_dict(torch.load("models/world_model/lstm.pt"))
    world_model.eval()

    # Predictions - Baseline
    base_probs = baseline_model.predict_proba(X_test_flat)[:, 1]
    base_preds = (base_probs >= 0.5).astype(int)

    # Predictions - World Model
    with torch.no_grad():
        wm_probs = world_model(torch.tensor(X_test, dtype=torch.float32)).squeeze().numpy()
        wm_preds = (wm_probs >= 0.5).astype(int)

    # Metrics Calculations
    base_prec, base_rec, base_f1, _ = precision_recall_fscore_support(y_test, base_preds, average='binary', zero_division=0)
    base_auc = roc_auc_score(y_test, base_probs) if len(np.unique(y_test)) > 1 else 0.0
    base_lead = calculate_lead_time(y_test, base_probs)

    wm_prec, wm_rec, wm_f1, _ = precision_recall_fscore_support(y_test, wm_preds, average='binary', zero_division=0)
    wm_auc = roc_auc_score(y_test, wm_probs) if len(np.unique(y_test)) > 1 else 0.0
    wm_lead = calculate_lead_time(y_test, wm_probs)

    # Print Clean Comparative Table
    print("\n" + "="*80)
    print(f"{'NTRO ATTACK FORECASTER - COMPARATIVE MODEL EVALUATION':^80}")
    print("="*80)
    print(f"{'Metric':<30} | {'Baseline (Logistic Reg)':<25} | {'Sequence World Model (LSTM)':<25}")
    print("-" * 84)
    print(f"{'Precision':<30} | {base_prec:<25.4f} | {wm_prec:<25.4f}")
    print(f"{'Recall':<30} | {base_rec:<25.4f} | {wm_rec:<25.4f}")
    print(f"{'F1-Score':<30} | {base_f1:<25.4f} | {wm_f1:<25.4f}")
    print(f"{'ROC-AUC Score':<30} | {base_auc:<25.4f} | {wm_auc:<25.4f}")
    print(f"{'Mean Early Warning Lead Time':<30} | {f'{base_lead:.1f} sec':<25} | {f'{wm_lead:.1f} sec':<25}")
    print("="*80 + "\n")

if __name__ == "__main__":
    evaluate()