"""
VirusShare Dataset Filter - Phase D
=====================================
Filters VirusShare.csv to extract only samples with enough
recognized APIs to provide meaningful signal for our model.

Outputs: virusshare_filtered.csv in the same format as our pipeline.
"""
import os, json
import pandas as pd
import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
VIRUSSHARE_PATH = os.path.join(SCRIPT_DIR, "new datasets", "VirusShare.csv")
FILTERED_PATH = os.path.join(SCRIPT_DIR, "new datasets", "virusshare_filtered.csv")

SEQ_LEN = 100
MIN_MATCH_RATIO = 0.30  # Keep samples where >=30% APIs are recognized

# Load token maps
with open(os.path.join(OUTPUT_DIR, "token_maps.json"), "r") as f:
    maps = json.load(f)
api_to_idx = maps["api_to_idx"]
UNK_IDX = api_to_idx["<UNK>"]

# Build lowercase lookup
api_lower = {name.lower(): idx for name, idx in api_to_idx.items()
             if name not in ("<PAD>", "<UNK>")}


def normalize(name):
    """Try to match an API name to our vocabulary."""
    name = name.strip()
    if not name:
        return None
    if name in api_to_idx:
        return api_to_idx[name]
    # Strip module prefix
    if "." in name:
        stripped = name.split(".")[-1]
        if stripped in api_to_idx:
            return api_to_idx[stripped]
    # Case-insensitive
    if name.lower() in api_lower:
        return api_lower[name.lower()]
    # A/W suffix
    for suffix in ["A", "W", "Ex", "ExA", "ExW"]:
        variant = name + suffix
        if variant in api_to_idx:
            return api_to_idx[variant]
    return None  # not matched


print("=" * 60)
print("  VirusShare Filter - Phase D")
print("=" * 60)

df = pd.read_csv(VIRUSSHARE_PATH)
print(f"  Total samples: {len(df)}")
print(f"  Class distribution: {df['class'].value_counts().to_dict()}")

kept_rows = []
kept_labels = []
stats = {"total": 0, "kept": 0, "rejected": 0, "avg_match_ratio": []}

for idx, row in df.iterrows():
    if pd.isna(row["api"]):
        stats["rejected"] += 1
        continue

    apis = [a.strip() for a in str(row["api"]).split(",") if a.strip()]
    if not apis:
        stats["rejected"] += 1
        continue

    stats["total"] += 1

    # Tokenize with normalization
    tokens = []
    matched = 0
    for api_name in apis:
        token = normalize(api_name)
        if token is not None:
            tokens.append(token)
            matched += 1
        # Skip unmatched APIs entirely (don't add UNK - filter them out)

    match_ratio = matched / len(apis)

    if match_ratio >= MIN_MATCH_RATIO and len(tokens) >= 5:
        # Pad/truncate to SEQ_LEN
        if len(tokens) < SEQ_LEN:
            tokens += [0] * (SEQ_LEN - len(tokens))
        else:
            tokens = tokens[:SEQ_LEN]
        kept_rows.append(tokens)
        kept_labels.append(1)  # all VirusShare = malware
        stats["kept"] += 1
        stats["avg_match_ratio"].append(match_ratio)
    else:
        stats["rejected"] += 1

    if (idx + 1) % 2000 == 0:
        print(f"  Processed {idx+1}/{len(df)}... kept {stats['kept']}")

print(f"\n  Results:")
print(f"  Total processed: {stats['total']}")
print(f"  Kept: {stats['kept']} ({100*stats['kept']/max(stats['total'],1):.1f}%)")
print(f"  Rejected: {stats['rejected']}")
if stats["avg_match_ratio"]:
    avg_r = np.mean(stats["avg_match_ratio"])
    print(f"  Avg match ratio (kept): {avg_r:.1%}")

if kept_rows:
    # Save as CSV
    cols = [f"t_{i}" for i in range(SEQ_LEN)]
    out_df = pd.DataFrame(kept_rows, columns=cols)
    out_df["malware"] = kept_labels
    out_df.to_csv(FILTERED_PATH, index=False)
    print(f"\n  [SAVED] {FILTERED_PATH}")
    print(f"  Shape: {out_df.shape}")
else:
    print("\n  [WARNING] No samples passed the filter!")

print("\n" + "=" * 60)
print("  DONE")
print("=" * 60)
