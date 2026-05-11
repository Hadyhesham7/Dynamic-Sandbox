"""
Interactive Malware Prediction - PyTorch BiLSTM v4
=================================================
Enter API call indices (0-306) and get a prediction.
Dynamic vocab loaded from token_maps.json.
"""
import os, json
import torch
import torch.nn as nn

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR    = os.path.join(SCRIPT_DIR, "output")

# Dynamic vocab from token maps
with open(os.path.join(OUTPUT_DIR, "token_maps.json"), "r") as f:
    _maps = json.load(f)
PAD_IDX = 0
UNK_IDX = _maps["api_to_idx"]["<UNK>"]
VOCAB_SIZE = max(int(k) for k in _maps["idx_to_api"].keys()) + 1
EMBED_DIM, HIDDEN_DIM, NUM_LAYERS, SEQ_LEN, DROPOUT = 64, 128, 2, 100, 0.3
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class MalwareClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.embedding = nn.Embedding(VOCAB_SIZE, EMBED_DIM, padding_idx=PAD_IDX)
        self.lstm = nn.LSTM(EMBED_DIM, HIDDEN_DIM, NUM_LAYERS, batch_first=True,
                            bidirectional=True, dropout=DROPOUT)
        self.dropout1 = nn.Dropout(DROPOUT)
        self.fc1 = nn.Linear(HIDDEN_DIM * 2, 64)
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

# Load
with open(os.path.join(OUTPUT_DIR, "token_maps.json"), "r") as f:
    maps = json.load(f)
idx_to_api = {int(k): v for k, v in maps["idx_to_api"].items()}

model = MalwareClassifier().to(DEVICE)
model.load_state_dict(torch.load(os.path.join(OUTPUT_DIR, "malware_lstm_model.pt"),
                                  map_location=DEVICE, weights_only=True))
model.eval()

print("=" * 60)
print("  MALWARE PREDICTION - Interactive (PyTorch BiLSTM)")
print("=" * 60)
print(f"  Model loaded on: {DEVICE}")
print(f"  API list: 307 entries (original 0-306)")
print(f"  Required: {SEQ_LEN} API calls (auto-pads if shorter)")
print()
print("  HOW TO USE:")
print("  Paste API indices separated by commas or spaces.")
print("  Example: 112, 274, 158, 215, 274, 158, 215, 298 ...")
print("  Type 'quit' to exit.")
print("=" * 60)


def do_predict(original_indices):
    shifted = [i + 1 for i in original_indices]
    if len(shifted) < SEQ_LEN:
        shifted += [PAD_IDX] * (SEQ_LEN - len(shifted))
    else:
        shifted = shifted[:SEQ_LEN]
    seq = torch.LongTensor(shifted).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        prob = torch.sigmoid(model(seq)).item()
    if prob > 0.5:
        return "MALWARE", prob * 100, prob
    return "BENIGN", (1 - prob) * 100, prob


while True:
    print()
    user_input = input("Enter API indices >> ").strip()
    if user_input.lower() in ("quit", "exit", "q"):
        print("Goodbye!")
        break
    if not user_input:
        print("  [ERROR] Empty input.")
        continue
    try:
        raw = user_input.replace(",", " ").split()
        indices = [int(x.strip()) for x in raw]
    except ValueError:
        print("  [ERROR] Numbers only (0-306).")
        continue

    invalid = [i for i in indices if i < 0 or i > 306]
    if invalid:
        print(f"  [ERROR] Out of range: {invalid}")
        continue

    if len(indices) < SEQ_LEN:
        print(f"  [INFO] {len(indices)} indices. Padding to {SEQ_LEN}.")
    elif len(indices) > SEQ_LEN:
        print(f"  [INFO] Truncating to first {SEQ_LEN}.")

    # Translate
    names = [idx_to_api.get(i + 1, f"IDX_{i}") for i in indices[:15]]
    print(f"\n  Translated (first 15):")
    for j, (idx, name) in enumerate(zip(indices[:15], names)):
        print(f"    [{j:2d}] {idx:3d} -> {name}")

    label, confidence, raw_prob = do_predict(indices)
    print()
    print("  " + "-" * 40)
    print(f"  PREDICTION:  {label}")
    print(f"  CONFIDENCE:  {confidence:.2f}%")
    print(f"  Raw score:   {raw_prob:.6f} (>0.5 = malware)")
    print("  " + "-" * 40)
