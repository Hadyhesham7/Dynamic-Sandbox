"""
retrain_v4.py - Retraining Pipeline v4 (Balanced + Full Vocab)
================================================================
Improvements over v3:
  1. Full 509 API vocabulary (was 310)
  2. Malware undersampled to 5000 (from 44,082) -> 2.1:1 ratio
  3. Stratified train/test split
  4. Cosine annealing LR scheduler
  5. Early stopping (patience=7)
  6. Saves best model by val_loss (not last epoch)

Result: ~7,364 samples (5,000 malware + 2,364 benign) @ 68/32 ratio
"""

import os
import sys
import json
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.style.use("ggplot")
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score,
    roc_curve, roc_auc_score,
)

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader

# ──────────────────────────────────────────────────────────────────────
# 1. CONFIGURATION
# ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH   = os.path.join(SCRIPT_DIR, "dynamic_api_call_sequence_per_malware_100_0_306.csv")
MALBEHAVD_PATH = os.path.join(SCRIPT_DIR, "new datasets", "MalBehavD-V1-dataset.csv")
API_LIST_PATH  = os.path.join(SCRIPT_DIR, "api_list.txt")
OUTPUT_DIR     = os.path.join(SCRIPT_DIR, "output")

PAD_IDX        = 0
UNK_IDX        = None
VOCAB_SIZE     = None
EMBED_DIM      = 64
HIDDEN_DIM     = 128
NUM_LAYERS     = 2
SEQ_LEN        = 100
DROPOUT        = 0.3
EPOCHS         = 60
BATCH_SIZE     = 64       # smaller batch for smaller dataset
LR             = 0.001
UNK_MASK_RATE  = 0.10
RANDOM_STATE   = 42
TEST_SIZE      = 0.20     # 80/20 split (more training data)
UNDERSAMPLE_MAL = 5000    # cap malware samples

os.makedirs(OUTPUT_DIR, exist_ok=True)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _save_fig(name):
    path = os.path.join(OUTPUT_DIR, name)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  [SAVED] {path}")


# ──────────────────────────────────────────────────────────────────────
# 2. LOAD API LIST (full 509 vocab)
# ──────────────────────────────────────────────────────────────────────

def load_api_list():
    global UNK_IDX, VOCAB_SIZE
    print("\n" + "="*60)
    print("STEP 1 - Load api_list.txt (full 509 vocab)")
    print("="*60)
    with open(API_LIST_PATH, "r", encoding="utf-8") as f:
        raw = [line.strip() for line in f if line.strip()]
    print(f"  API names loaded : {len(raw)}")

    UNK_IDX = len(raw) + 1
    VOCAB_SIZE = len(raw) + 2  # PAD + APIs + UNK

    api_to_idx = {"<PAD>": PAD_IDX, "<UNK>": UNK_IDX}
    idx_to_api = {PAD_IDX: "<PAD>", UNK_IDX: "<UNK>"}
    for orig_idx, name in enumerate(raw):
        new_idx = orig_idx + 1
        api_to_idx[name] = new_idx
        idx_to_api[new_idx] = name

    print(f"  Vocab size  : {VOCAB_SIZE}")
    print(f"  UNK index   : {UNK_IDX}")

    maps_path = os.path.join(OUTPUT_DIR, "token_maps.json")
    with open(maps_path, "w", encoding="utf-8") as f:
        json.dump({"api_to_idx": api_to_idx,
                    "idx_to_api": {str(k): v for k, v in idx_to_api.items()}}, f)
    print(f"  [SAVED] {maps_path}")
    return api_to_idx, idx_to_api, raw


# ──────────────────────────────────────────────────────────────────────
# 3. LOAD OLIVEIRA DATASET
# ──────────────────────────────────────────────────────────────────────

def load_oliveira():
    print("\n" + "="*60)
    print("STEP 2a - Load Oliveira Dataset")
    print("="*60)
    data = pd.read_csv(DATASET_PATH)
    api_cols = [f"t_{i}" for i in range(SEQ_LEN)]
    X = data[api_cols].values.astype(np.int64) + 1  # shift +1 for PAD
    y = data["malware"].values.astype(np.float32)
    n_mal = int(y.sum())
    n_ben = len(y) - n_mal
    print(f"  Samples: {len(y)} ({n_mal} malware, {n_ben} benign)")
    return X, y


# ──────────────────────────────────────────────────────────────────────
# 4. LOAD MALBEHAVD DATASET
# ──────────────────────────────────────────────────────────────────────

def load_malbehavd(api_to_idx):
    print("\n" + "="*60)
    print("STEP 2b - Load MalBehavD-V1 Dataset")
    print("="*60)
    if not os.path.exists(MALBEHAVD_PATH):
        print(f"  [SKIP] Not found: {MALBEHAVD_PATH}")
        return None, None

    df = pd.read_csv(MALBEHAVD_PATH)
    api_cols = [c for c in df.columns if c not in ('sha256', 'labels')]
    labels = df["labels"].values.astype(np.float32)

    api_lower = {name.lower(): idx for name, idx in api_to_idx.items()}
    X = np.zeros((len(df), SEQ_LEN), dtype=np.int64)
    matched, unmatched = 0, 0

    for row_idx in range(len(df)):
        col_count = 0
        row = df.iloc[row_idx]
        for col in api_cols:
            if col_count >= SEQ_LEN:
                break
            val = row[col]
            if pd.isna(val):
                continue
            name = str(val).strip()
            if name in api_to_idx:
                X[row_idx, col_count] = api_to_idx[name]
                matched += 1
            elif name.lower() in api_lower:
                X[row_idx, col_count] = api_lower[name.lower()]
                matched += 1
            else:
                X[row_idx, col_count] = UNK_IDX
                unmatched += 1
            col_count += 1

    total = matched + unmatched
    print(f"  Samples: {len(df)} (mal={int(labels.sum())}, ben={len(labels)-int(labels.sum())})")
    print(f"  Tokenized: {matched}/{total} matched ({100*matched/max(total,1):.1f}%)")
    return X, labels


# ──────────────────────────────────────────────────────────────────────
# 5. MERGE + UNDERSAMPLE + SPLIT
# ──────────────────────────────────────────────────────────────────────

def merge_and_balance(X_oliv, y_oliv, X_mal, y_mal):
    print("\n" + "="*60)
    print("STEP 3 - Merge, Undersample & Split")
    print("="*60)

    # Merge datasets
    if X_mal is not None:
        X = np.vstack([X_oliv, X_mal])
        y = np.concatenate([y_oliv, y_mal])
    else:
        X, y = X_oliv, y_oliv

    n_mal = int(y.sum())
    n_ben = len(y) - n_mal
    print(f"  Before undersample: {n_mal} malware, {n_ben} benign (ratio {n_mal/max(n_ben,1):.1f}:1)")

    # Undersample malware
    mal_idx = np.where(y == 1)[0]
    ben_idx = np.where(y == 0)[0]

    if len(mal_idx) > UNDERSAMPLE_MAL:
        np.random.seed(RANDOM_STATE)
        mal_keep = np.random.choice(mal_idx, UNDERSAMPLE_MAL, replace=False)
        keep_idx = np.concatenate([mal_keep, ben_idx])
        np.random.shuffle(keep_idx)
        X = X[keep_idx]
        y = y[keep_idx]

    n_mal = int(y.sum())
    n_ben = len(y) - n_mal
    print(f"  After undersample:  {n_mal} malware, {n_ben} benign (ratio {n_mal/max(n_ben,1):.1f}:1)")
    print(f"  Total samples: {len(y)}")

    # Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE,
        stratify=y, shuffle=True)

    n_tr_mal = int(y_train.sum())
    n_tr_ben = len(y_train) - n_tr_mal
    n_te_mal = int(y_test.sum())
    n_te_ben = len(y_test) - n_te_mal
    print(f"  Train: {len(y_train)} ({n_tr_mal} mal, {n_tr_ben} ben)")
    print(f"  Test:  {len(y_test)} ({n_te_mal} mal, {n_te_ben} ben)")

    return X_train, X_test, y_train, y_test


# ──────────────────────────────────────────────────────────────────────
# 6. DATASET + MODEL + LOSS (same architecture)
# ──────────────────────────────────────────────────────────────────────

class MalwareDataset(Dataset):
    def __init__(self, sequences, labels, training=False, unk_mask_rate=0.0):
        self.sequences = sequences
        self.labels = labels
        self.training = training
        self.unk_mask_rate = unk_mask_rate

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        seq = self.sequences[idx].copy()
        label = self.labels[idx]
        if self.training and self.unk_mask_rate > 0:
            mask = np.random.random(len(seq)) < self.unk_mask_rate
            seq[mask] = UNK_IDX
        return torch.LongTensor(seq), torch.FloatTensor([label])


class MalwareClassifier(nn.Module):
    def __init__(self, vocab_size, embed_dim=EMBED_DIM,
                 hidden_dim=HIDDEN_DIM, num_layers=NUM_LAYERS, dropout=DROPOUT):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD_IDX)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers,
                            batch_first=True, bidirectional=True,
                            dropout=dropout if num_layers > 1 else 0)
        self.dropout1 = nn.Dropout(dropout)
        self.fc1 = nn.Linear(hidden_dim * 2, 64)
        self.relu = nn.ReLU()
        self.dropout2 = nn.Dropout(0.2)
        self.fc2 = nn.Linear(64, 1)

    def forward(self, x):
        embedded = self.embedding(x)
        _, (hidden, _) = self.lstm(embedded)
        cat = torch.cat([hidden[-2], hidden[-1]], dim=1)
        out = self.dropout1(cat)
        out = self.relu(self.fc1(out))
        out = self.dropout2(out)
        return self.fc2(out)


class FocalLoss(nn.Module):
    def __init__(self, alpha=0.25, gamma=2.0):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, logits, targets):
        probs = torch.sigmoid(logits)
        bce = nn.functional.binary_cross_entropy_with_logits(logits, targets, reduction="none")
        p_t = targets * probs + (1 - targets) * (1 - probs)
        alpha_t = targets * self.alpha + (1 - targets) * (1 - self.alpha)
        focal_weight = alpha_t * torch.pow(1.0 - p_t, self.gamma)
        return (focal_weight * bce).mean()


# ──────────────────────────────────────────────────────────────────────
# 7. TRAINING WITH EARLY STOPPING + COSINE LR
# ──────────────────────────────────────────────────────────────────────

def train_model(X_train, y_train, X_test, y_test):
    print("\n" + "="*60)
    print("STEP 4 - Train BiLSTM (Early Stopping + Cosine LR)")
    print("="*60)
    print(f"  Device: {DEVICE}")

    train_ds = MalwareDataset(X_train, y_train, training=True, unk_mask_rate=UNK_MASK_RATE)
    test_ds = MalwareDataset(X_test, y_test, training=False)
    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, num_workers=0)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, shuffle=False, num_workers=0)

    model = MalwareClassifier(vocab_size=VOCAB_SIZE).to(DEVICE)
    criterion = FocalLoss(alpha=0.25, gamma=2.0)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS)

    # Class weights
    n_mal = int(y_train.sum())
    n_ben = len(y_train) - n_mal
    weight_for_benign = n_mal / max(n_ben, 1)
    print(f"  Benign weight: {weight_for_benign:.2f}x")
    print(f"  Vocab size: {VOCAB_SIZE}")
    print(f"  Architecture: Embedding({VOCAB_SIZE},{EMBED_DIM}) -> BiLSTM({HIDDEN_DIM},layers={NUM_LAYERS}) -> FC")
    print(f"  Params: {sum(p.numel() for p in model.parameters()):,}")
    print(f"  Epochs: {EPOCHS}, Batch: {BATCH_SIZE}, LR: {LR}")
    print()

    history = {"train_loss": [], "val_loss": [], "train_acc": [], "val_acc": []}
    best_val_loss = float("inf")
    patience, patience_counter = 7, 0
    best_state = None

    for epoch in range(1, EPOCHS + 1):
        # Train
        model.train()
        train_loss, correct, total = 0, 0, 0
        for seqs, labels in train_loader:
            seqs, labels = seqs.to(DEVICE), labels.to(DEVICE)
            optimizer.zero_grad()
            logits = model(seqs)

            # Per-sample weighting
            sample_w = torch.where(labels == 0, weight_for_benign, 1.0)
            loss = criterion(logits, labels)
            weighted_loss = loss * sample_w.mean()
            weighted_loss.backward()
            optimizer.step()

            train_loss += loss.item() * seqs.size(0)
            preds = (torch.sigmoid(logits) > 0.5).float()
            correct += (preds == labels).sum().item()
            total += labels.size(0)

        train_loss /= total
        train_acc = correct / total
        scheduler.step()

        # Validate
        model.eval()
        val_loss, correct, total = 0, 0, 0
        with torch.no_grad():
            for seqs, labels in test_loader:
                seqs, labels = seqs.to(DEVICE), labels.to(DEVICE)
                logits = model(seqs)
                loss = criterion(logits, labels)
                val_loss += loss.item() * seqs.size(0)
                preds = (torch.sigmoid(logits) > 0.5).float()
                correct += (preds == labels).sum().item()
                total += labels.size(0)
        val_loss /= total
        val_acc = correct / total

        history["train_loss"].append(train_loss)
        history["val_loss"].append(val_loss)
        history["train_acc"].append(train_acc)
        history["val_acc"].append(val_acc)

        lr_now = optimizer.param_groups[0]['lr']
        marker = ""
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = model.state_dict().copy()
            patience_counter = 0
            marker = " *BEST*"
        else:
            patience_counter += 1

        print(f"  Epoch {epoch:02d}/{EPOCHS} - loss: {train_loss:.4f} acc: {train_acc:.4f} "
              f"val_loss: {val_loss:.4f} val_acc: {val_acc:.4f} lr: {lr_now:.6f}{marker}")

        if patience_counter >= patience:
            print(f"\n  Early stopping at epoch {epoch} (patience={patience})")
            break

    # Restore best model
    if best_state is not None:
        model.load_state_dict(best_state)
        print(f"  Restored best model (val_loss={best_val_loss:.4f})")

    return model, history, test_loader


# ──────────────────────────────────────────────────────────────────────
# 8. EVALUATION
# ──────────────────────────────────────────────────────────────────────

def evaluate_model(model, test_loader, y_test):
    print("\n" + "="*60)
    print("STEP 5 - Evaluate")
    print("="*60)
    model.eval()
    all_probs, all_preds = [], []
    with torch.no_grad():
        for seqs, _ in test_loader:
            seqs = seqs.to(DEVICE)
            logits = model(seqs)
            probs = torch.sigmoid(logits).cpu().numpy().flatten()
            all_probs.extend(probs)
            all_preds.extend((probs > 0.5).astype(int))

    y_pred = np.array(all_preds)
    y_prob = np.array(all_probs)
    roc_auc = roc_auc_score(y_test, y_prob)

    print(classification_report(y_test, y_pred, digits=4,
                                target_names=["Benign", "Malware"]))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"Confusion Matrix:\n{cm}")

    # Save confusion matrix
    plt.figure()
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Benign", "Malware"],
                yticklabels=["Benign", "Malware"])
    plt.ylabel("Actual"); plt.xlabel("Predicted")
    plt.title("Confusion Matrix - BiLSTM v4")
    _save_fig("cm_BiLSTM_v4.png")

    # ROC curve
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f"BiLSTM v4 (AUC = {roc_auc:.4f})")
    plt.plot([0, 1], [0, 1], color="gray", linestyle="--")
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("ROC Curve - BiLSTM v4"); plt.legend(); plt.grid(alpha=0.3)
    _save_fig("roc_BiLSTM_v4.png")

    metrics = {
        "Model": "BiLSTM_v4", "Accuracy": accuracy_score(y_test, y_pred),
        "F1-Score": f1_score(y_test, y_pred),
        "Recall": recall_score(y_test, y_pred),
        "Precision": precision_score(y_test, y_pred),
        "Benign_Precision": precision_score(y_test, y_pred, pos_label=0),
        "Benign_Recall": recall_score(y_test, y_pred, pos_label=0),
        "FP": int(fp), "FN": int(fn), "ROC-AUC": roc_auc,
    }
    print(f"\n  Accuracy         : {metrics['Accuracy']:.4f}")
    print(f"  F1               : {metrics['F1-Score']:.4f}")
    print(f"  ROC-AUC          : {metrics['ROC-AUC']:.4f}")
    print(f"  Benign Precision : {metrics['Benign_Precision']:.4f}")
    print(f"  Benign Recall    : {metrics['Benign_Recall']:.4f}")
    print(f"  FP={fp}, FN={fn}")
    return metrics


def plot_history(history):
    plt.figure(figsize=(12, 5))
    plt.subplot(1, 2, 1)
    plt.plot(history["train_loss"], label="Train"); plt.plot(history["val_loss"], label="Val")
    plt.xlabel("Epoch"); plt.ylabel("Loss"); plt.title("v4 - Loss"); plt.legend()
    plt.subplot(1, 2, 2)
    plt.plot(history["train_acc"], label="Train"); plt.plot(history["val_acc"], label="Val")
    plt.xlabel("Epoch"); plt.ylabel("Accuracy"); plt.title("v4 - Accuracy"); plt.legend()
    _save_fig("training_history_v4.png")


# ──────────────────────────────────────────────────────────────────────
# 9. MAIN
# ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  MALWARE DETECTION v4 - Balanced + Full 509 Vocab")
    print(f"  Device: {DEVICE}")
    print("=" * 60)

    api_to_idx, idx_to_api, raw_api_names = load_api_list()
    X_oliv, y_oliv = load_oliveira()
    X_mal, y_mal = load_malbehavd(api_to_idx)
    X_train, X_test, y_train, y_test, = merge_and_balance(X_oliv, y_oliv, X_mal, y_mal)

    model, history, test_loader = train_model(X_train, y_train, X_test, y_test)
    plot_history(history)
    metrics = evaluate_model(model, test_loader, y_test)

    # Save results
    df = pd.DataFrame([metrics])
    csv_path = os.path.join(OUTPUT_DIR, "results_v4.csv")
    df.to_csv(csv_path, index=False)
    print(f"\n  [SAVED] results -> {csv_path}")

    # Save model (overwrites old one)
    model_path = os.path.join(OUTPUT_DIR, "malware_lstm_model.pt")
    torch.save(model.state_dict(), model_path)
    print(f"  [SAVED] model -> {model_path}")

    # Update config
    config_path = os.path.join(SCRIPT_DIR, "config.json")
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)
        config["last_training_results"] = {
            "version": "v4",
            "accuracy": round(metrics["Accuracy"], 4),
            "f1_score": round(metrics["F1-Score"], 4),
            "roc_auc": round(metrics["ROC-AUC"], 4),
            "benign_precision": round(metrics["Benign_Precision"], 4),
            "benign_recall": round(metrics["Benign_Recall"], 4),
            "false_positives": metrics["FP"],
            "false_negatives": metrics["FN"],
            "vocab_size": VOCAB_SIZE,
            "malware_samples": int(y_train[y_train == 1].sum()) + int(y_test[y_test == 1].sum()),
            "benign_samples": int((y_train == 0).sum()) + int((y_test == 0).sum()),
            "note": f"Retrained with 509 vocab, undersampled malware to {UNDERSAMPLE_MAL}",
        }
        with open(config_path, "w") as f:
            json.dump(config, f, indent=4)
        print(f"  [SAVED] config -> {config_path}")

    print("\n" + "=" * 60)
    print("  RETRAINING COMPLETE [OK]")
    print("=" * 60)


if __name__ == "__main__":
    main()
