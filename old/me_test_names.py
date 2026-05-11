"""
Interactive Malware Prediction from API NAMES - v4
====================================================
Dynamic vocabulary: loads VOCAB_SIZE from token_maps.json
Includes: reliability scoring + UNK ratio warnings.
"""
import os, json
import torch
import torch.nn as nn

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")

# Load token maps first to get dynamic vocab size
with open(os.path.join(OUTPUT_DIR, "token_maps.json"), "r") as f:
    maps = json.load(f)
api_to_idx = maps["api_to_idx"]
idx_to_api = {int(k): v for k, v in maps["idx_to_api"].items()}

PAD_IDX = 0
UNK_IDX = api_to_idx["<UNK>"]
VOCAB_SIZE = max(idx_to_api.keys()) + 1
EMBED_DIM, HIDDEN_DIM, NUM_LAYERS, SEQ_LEN, DROPOUT = 64, 128, 2, 100, 0.3
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

NUM_APIS = VOCAB_SIZE - 2  # exclude PAD and UNK


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


model = MalwareClassifier().to(DEVICE)
model.load_state_dict(torch.load(os.path.join(OUTPUT_DIR, "malware_lstm_model.pt"),
                                  map_location=DEVICE, weights_only=True))
model.eval()


def normalize_api_name(raw_name):
    name = raw_name.strip()
    if not name:
        return None, None
    if name in api_to_idx:
        return api_to_idx[name], None
    if "." in name:
        stripped = name.split(".")[-1]
        if stripped in api_to_idx:
            return api_to_idx[stripped], None
    name_lower = name.lower()
    for api_name, idx in api_to_idx.items():
        if api_name.lower() == name_lower:
            return idx, None
    if "." in name:
        stripped_lower = name.split(".")[-1].lower()
        for api_name, idx in api_to_idx.items():
            if api_name.lower() == stripped_lower:
                return idx, None
    for suffix in ["A", "W", "Ex", "ExA", "ExW"]:
        variant = name + suffix
        if variant in api_to_idx:
            return api_to_idx[variant], None
    return UNK_IDX, raw_name


def predict_from_names(name_list):
    indices, matched_names, unknown_apis = [], [], []
    for name in name_list:
        token_idx, unk = normalize_api_name(name)
        if token_idx is None:
            continue
        indices.append(token_idx)
        if unk:
            unknown_apis.append(unk)
            matched_names.append(f"{unk} -> <UNK>")
        else:
            matched_names.append(f"{name.strip()} -> {idx_to_api.get(token_idx, '?')}")

    original_len = len(indices)
    if len(indices) < SEQ_LEN:
        indices += [PAD_IDX] * (SEQ_LEN - len(indices))
    else:
        indices = indices[:SEQ_LEN]

    seq = torch.LongTensor(indices).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        prob = torch.sigmoid(model(seq)).item()

    if prob > 0.5:
        verdict, confidence = "MALWARE", prob * 100
    else:
        verdict, confidence = "BENIGN", (1 - prob) * 100

    unk_ratio = len(unknown_apis) / max(original_len, 1)
    if unk_ratio <= 0.1: reliability = "HIGH"
    elif unk_ratio <= 0.3: reliability = "MEDIUM"
    elif unk_ratio <= 0.7: reliability = "LOW"
    else: reliability = "VERY LOW"

    return verdict, confidence, prob, unknown_apis, matched_names, original_len, unk_ratio, reliability


# Interactive Loop
print("=" * 60)
print("  MALWARE PREDICTION v4 - API Names (Dynamic Vocab)")
print("=" * 60)
print(f"  Model loaded on: {DEVICE}")
print(f"  Vocab: {NUM_APIS} APIs + PAD + UNK = {VOCAB_SIZE} tokens")
print()
print("  Paste comma-separated or tab-separated API names.")
print("  Type 'quit' to exit.")
print("=" * 60)

while True:
    print()
    user_input = input("Enter API names >> ").strip()
    if user_input.lower() in ("quit", "exit", "q"):
        print("Goodbye!")
        break
    if not user_input:
        continue

    if "\t" in user_input:
        api_names = [x.strip() for x in user_input.split("\t") if x.strip()]
    else:
        api_names = [x.strip() for x in user_input.split(",") if x.strip()]
    if not api_names:
        continue

    verdict, confidence, raw, unknowns, matched, orig_len, unk_ratio, reliability = predict_from_names(api_names)

    print(f"\n  API translations ({orig_len} total, showing first 15):")
    for i, m in enumerate(matched[:15]):
        print(f"    [{i:2d}] {m}")
    if len(matched) > 15:
        print(f"    ... and {len(matched) - 15} more")

    if orig_len < SEQ_LEN:
        print(f"\n  [INFO] {orig_len} APIs provided, padded to {SEQ_LEN}")

    if unknowns:
        print(f"\n  [WARNING] {len(unknowns)} unknown APIs (not in vocabulary):")
        for u in unknowns[:10]:
            print(f"    - {u}")
        if len(unknowns) > 10:
            print(f"    ... and {len(unknowns) - 10} more")

    print()
    print("  " + "=" * 44)
    print(f"  PREDICTION:   {verdict}")
    print(f"  CONFIDENCE:   {confidence:.2f}%")
    print(f"  RELIABILITY:  {reliability} (UNK ratio: {unk_ratio:.0%})")
    print(f"  Raw score:    {raw:.6f} (>0.5 = malware)")
    if reliability == "VERY LOW":
        print(f"  WARNING: VERDICT IS UNRELIABLE")
    elif reliability == "LOW":
        print(f"  WARNING: Low confidence - many APIs unknown")
    print("  " + "=" * 44)
