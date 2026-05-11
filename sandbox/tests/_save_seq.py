"""Save the clean API call sequence from the test report to a file."""
import json
import os

report_path = "sandbox/reports/test_report.json"
output_path = "sandbox/reports/apis_calls_sequence.json"

with open(report_path) as f:
    r = json.load(f)

# Extract all calls in order
calls = []
for p in r["behavior"]["processes"]:
    for c in p["calls"]:
        calls.append(c)
calls.sort(key=lambda x: x.get("time", 0))

# Filter MinHook init noise (first 0.1s of VirtualProtect/FlushInstructionCache)
if calls:
    init_cutoff = calls[0].get("time", 0) + 0.1
    clean = [c for c in calls if c.get("time", 0) > init_cutoff
             or c.get("api") not in ("VirtualProtect", "FlushInstructionCache")]
else:
    clean = []

# Cut at ExitProcess (remove shutdown cleanup)
for i, c in enumerate(clean):
    if c.get("api") == "ExitProcess":
        clean = clean[:i + 1]
        break

# Build output
raw_sequence = [c.get("api", "?") for c in clean]

# Deduplicated (consecutive duplicates removed)
deduped = []
prev = None
for api in raw_sequence:
    if api != prev:
        deduped.append(api)
        prev = api

# Unique APIs
unique_apis = sorted(set(raw_sequence))

# Category flow
cat_sequence = [c.get("category", "?") for c in clean]
cat_flow = []
prev_cat = None
for cat in cat_sequence:
    if cat != prev_cat:
        cat_flow.append(cat)
        prev_cat = cat

output = {
    "info": {
        "source": "api_exerciser.exe",
        "report_file": report_path,
        "total_raw_calls": len(calls),
        "total_clean_calls": len(clean),
        "unique_api_count": len(unique_apis),
        "deduped_sequence_length": len(deduped)
    },
    "raw_sequence": raw_sequence,
    "deduped_sequence": deduped,
    "unique_apis": unique_apis,
    "category_flow": cat_flow,
    "detailed_calls": [
        {
            "index": i + 1,
            "api": c.get("api"),
            "category": c.get("category"),
            "arguments": c.get("arguments", {}),
            "return": c.get("return", ""),
            "time": c.get("time", 0),
            "tid": c.get("tid", 0)
        }
        for i, c in enumerate(clean)
    ]
}

os.makedirs(os.path.dirname(output_path), exist_ok=True)
with open(output_path, "w") as f:
    json.dump(output, f, indent=2)

print(f"Saved to: {output_path}")
print(f"  Raw calls:          {len(raw_sequence)}")
print(f"  Deduped sequence:   {len(deduped)} steps")
print(f"  Unique APIs:        {len(unique_apis)}")
print(f"  Category flow:      {' -> '.join(cat_flow)}")
