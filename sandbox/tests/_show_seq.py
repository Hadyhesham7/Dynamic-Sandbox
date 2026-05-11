"""Show the CLEAN API sequence — filters out MinHook initialization noise."""
import json

with open("sandbox/reports/test_report.json") as f:
    r = json.load(f)

calls = []
for p in r["behavior"]["processes"]:
    for c in p["calls"]:
        calls.append(c)
calls.sort(key=lambda x: x.get("time", 0))

# Filter out MinHook init: skip VirtualProtect/FlushInstructionCache
# that happen in the first 0.1 seconds (hook installation phase)
if calls:
    init_cutoff = calls[0].get("time", 0) + 0.1
    real_calls = [c for c in calls if c.get("time", 0) > init_cutoff
                  or c.get("api") not in ("VirtualProtect", "FlushInstructionCache")]

    # Also filter the shutdown phase VirtualProtect/FlushInstructionCache at the end
    # (MinHook removing hooks)
    clean = []
    for c in real_calls:
        api = c.get("api", "?")
        t = c.get("time", 0)
        # Keep everything that's not MinHook noise
        if api in ("VirtualProtect", "FlushInstructionCache") and t > init_cutoff:
            # Only keep if it's the exerciser's OWN VirtualProtect test
            # (the one surrounded by VirtualAlloc/VirtualFree)
            clean.append(c)  # keep all for now
        else:
            clean.append(c)
else:
    clean = []

# Remove shutdown-phase MinHook cleanup (last burst of VirtualProtect)
# Find ExitProcess and cut there
exit_idx = len(clean)
for i, c in enumerate(clean):
    if c.get("api") == "ExitProcess":
        exit_idx = i + 1
        break

clean = clean[:exit_idx]

print("=" * 70)
print("  CLEAN API CALL SEQUENCE (MinHook overhead removed)")
print("=" * 70)
print(f"  {'#':>4}  {'Time':>8}  {'Cat':>5}  API")
print("-" * 70)

for i, c in enumerate(clean, 1):
    t = c.get("time", 0)
    cat = c.get("category", "?")
    api = c.get("api", "?")
    ret = str(c.get("return", ""))[:20]
    print(f"  {i:4d}  {t:8.4f}  {cat:>5}  {api}")

print(f"\n  Total: {len(clean)} meaningful API calls")
print(f"  (Filtered from {len(calls)} raw calls)")

# Deduplicated for ML
print()
print("=" * 70)
print("  ML-READY SEQUENCE (consecutive duplicates removed)")
print("=" * 70)

deduped = []
prev = None
for c in clean:
    api = c.get("api", "?")
    if api != prev:
        deduped.append(api)
        prev = api

for i, api in enumerate(deduped, 1):
    print(f"  {i:3d}. {api}")

print(f"\n  Sequence length: {len(deduped)} steps")

# Category flow
print()
print("=" * 70)
print("  BEHAVIORAL FLOW")
print("=" * 70)

cat_flow = []
prev_cat = None
for c in clean:
    cat = c.get("category", "?")
    if cat != prev_cat:
        cat_flow.append(cat)
        prev_cat = cat

print("  " + " -> ".join(cat_flow))

# Unique API list
unique = sorted(set(c.get("api", "?") for c in clean))
print(f"\n  Unique APIs ({len(unique)}):")
for api in unique:
    print(f"    - {api}")
