"""
Standalone inference test for PyTorch BiLSTM model v4.
Tests: benign, malware, unknown APIs, normalization, reliability scoring.
Dynamic vocab size loaded from token_maps.json.
"""
import os, json
import torch
import torch.nn as nn

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")

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

with open(os.path.join(OUTPUT_DIR, "token_maps.json"), "r") as f:
    maps = json.load(f)
api_to_idx = maps["api_to_idx"]
idx_to_api = {int(k): v for k, v in maps["idx_to_api"].items()}

model = MalwareClassifier().to(DEVICE)
model.load_state_dict(torch.load(os.path.join(OUTPUT_DIR, "malware_lstm_model.pt"),
                                  map_location=DEVICE, weights_only=True))
model.eval()
print(f"Loaded BiLSTM v3 model on {DEVICE}")


def predict_from_original_indices(indices_list):
    shifted = [i + 1 for i in indices_list]
    if len(shifted) < SEQ_LEN:
        shifted += [PAD_IDX] * (SEQ_LEN - len(shifted))
    else:
        shifted = shifted[:SEQ_LEN]
    seq = torch.LongTensor(shifted).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        prob = torch.sigmoid(model(seq)).item()
    if prob > 0.5:
        return "Malware", prob * 100
    return "Benign", (1 - prob) * 100


def normalize_api_name(raw_name):
    name = raw_name.strip()
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
    indices, unknown = [], []
    for name in name_list:
        token_idx, unk = normalize_api_name(name)
        indices.append(token_idx)
        if unk:
            unknown.append(unk)
    orig_len = len(indices)
    if len(indices) < SEQ_LEN:
        indices += [PAD_IDX] * (SEQ_LEN - len(indices))
    else:
        indices = indices[:SEQ_LEN]
    seq = torch.LongTensor(indices).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        prob = torch.sigmoid(model(seq)).item()
    unk_ratio = len(unknown) / max(orig_len, 1)
    if unk_ratio <= 0.1: reliability = "HIGH"
    elif unk_ratio <= 0.3: reliability = "MEDIUM"
    elif unk_ratio <= 0.7: reliability = "LOW"
    else: reliability = "VERY LOW"
    if prob > 0.5:
        return "Malware", prob * 100, unknown, unk_ratio, reliability
    return "Benign", (1 - prob) * 100, unknown, unk_ratio, reliability


# ============================================================
# TEST 1-3: Real samples from dataset (indices)
# ============================================================
print("\n" + "="*60)
print("TEST 1: REAL BENIGN sample")
print("="*60)
benign_1 = [286, 110, 172, 240, 117, 240, 117, 240, 117, 106,
            171, 260, 141, 65, 260, 141, 65, 260, 141, 65,
            260, 141, 65, 260, 141, 65, 260, 215, 274, 158,
            215, 274, 158, 215, 240, 117, 71, 297, 135, 171,
            215, 112, 117, 56, 240, 117, 275, 112, 240, 117,
            260, 141, 65, 260, 117, 260, 141, 65, 117, 260,
            141, 65, 117, 9, 117, 260, 65, 141, 65, 260,
            65, 141, 65, 117, 215, 260, 65, 141, 65, 260,
            240, 117, 202, 260, 141, 65, 202, 65, 117, 260,
            297, 215, 114, 215, 117, 261, 106, 144, 297, 117]
label, conf = predict_from_original_indices(benign_1)
print(f"  Expected: Benign | Result: {label} ({conf:.2f}%)")

print("\n" + "="*60)
print("TEST 2: REAL BENIGN sample #2")
print("="*60)
benign_2 = [82, 228, 16, 29, 82, 29, 82, 248, 194, 144,
            194, 144, 194, 16, 172, 117, 29, 82, 29, 82,
            297, 29, 82, 29, 82, 29, 82, 108, 208, 172,
            117, 172, 117, 194, 20, 114, 215, 82, 228, 240,
            117, 208, 82, 208, 187, 208, 194, 20, 114, 215,
            82, 228, 240, 117, 29, 82, 228, 240, 117, 29,
            82, 228, 240, 117, 29, 82, 228, 240, 117, 29,
            82, 228, 240, 117, 29, 82, 228, 240, 117, 29,
            82, 228, 240, 117, 29, 82, 228, 240, 117, 29,
            82, 228, 240, 117, 29, 82, 228, 240, 117, 29]
label, conf = predict_from_original_indices(benign_2)
print(f"  Expected: Benign | Result: {label} ({conf:.2f}%)")

print("\n" + "="*60)
print("TEST 3: REAL MALWARE sample")
print("="*60)
malware_1 = [112, 274, 158, 215, 274, 158, 215, 298, 76, 208,
             76, 172, 117, 172, 117, 172, 76, 117, 35, 60,
             81, 60, 81, 60, 81, 60, 81, 60, 81, 60,
             81, 60, 81, 60, 81, 60, 81, 60, 81, 60,
             81, 60, 81, 60, 81, 60, 81, 117, 60, 81,
             60, 81, 208, 35, 215, 35, 208, 240, 117, 172,
             60, 81, 60, 81, 225, 35, 60, 81, 35, 225,
             172, 60, 81, 60, 81, 60, 81, 172, 117, 76,
             172, 117, 172, 117, 35, 111, 81, 140, 208, 240,
             117, 71, 297, 135, 171, 215, 35, 208, 56, 71]
label, conf = predict_from_original_indices(malware_1)
print(f"  Expected: Malware | Result: {label} ({conf:.2f}%)")

# ============================================================
# TEST 4: Known + Unknown API names
# ============================================================
print("\n" + "="*60)
print("TEST 4: Mixed known/unknown APIs")
print("="*60)
test_names = ["NtOpenProcess", "FakeNewAPI2025", "LdrLoadDll",
              "UnknownSyscall", "NtAllocateVirtualMemory", "NtClose"]
label, conf, unknowns, unk_r, rel = predict_from_names(test_names)
print(f"  Result: {label} ({conf:.2f}%) | Reliability: {rel} | UNK: {unk_r:.0%}")
print(f"  Unknown: {unknowns}")

# ============================================================
# TEST 5: Normalization
# ============================================================
print("\n" + "="*60)
print("TEST 5: API Name Normalization")
print("="*60)
for api in ["ntdll.NtOpenProcess", "ntopenprocess", "NTCLOSE", "CreateFile", "TotallyFakeAPI"]:
    token_idx, unk = normalize_api_name(api)
    matched = idx_to_api.get(token_idx, "<UNK>")
    status = "MATCHED" if unk is None else "UNKNOWN"
    print(f"  '{api}' -> [{status}] {matched}")

# ============================================================
# TEST 6: ALL-UNK sequence (VirusShare-style) - MUST show VERY LOW reliability
# ============================================================
print("\n" + "="*60)
print("TEST 6: ALL-UNK sequence (simulating VirusShare)")
print("="*60)
all_unk = ["__CIcos", "_adj_fptan", "__vbaVarMove", "__vbaFreeVar",
           "__vbaEnd", "__vbaFreeVarList", "_adj_fdiv_m64", "_adj_fprem1",
           "__vbaCopyBytes", "__vbaSetSystemError", "__vbaHresultCheckObj",
           "_adj_fdiv_m32", "__vbaObjSet", "_adj_fdiv_m16i"]
label, conf, unknowns, unk_r, rel = predict_from_names(all_unk)
print(f"  APIs: {len(all_unk)} total, {len(unknowns)} unknown")
print(f"  Result: {label} ({conf:.2f}%)")
print(f"  RELIABILITY: {rel} (UNK ratio: {unk_r:.0%})")
if rel == "VERY LOW":
    print(f"  [OK] CORRECT: System flagged verdict as UNRELIABLE")
else:
    print(f"  [FAIL] PROBLEM: Should be VERY LOW reliability")

print("\n" + "="*60)
print("ALL TESTS COMPLETE")
print("="*60)
