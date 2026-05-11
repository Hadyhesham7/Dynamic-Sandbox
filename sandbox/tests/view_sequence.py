"""
view_sequence.py — Display the API call sequence from a sandbox report
======================================================================
Shows the exact order of API calls as captured by the hook engine.
This is what gets fed to the ML classifier.
"""
import json
import sys
import os

def main():
    # Find the report
    report_path = sys.argv[1] if len(sys.argv) > 1 else "sandbox/reports/test_report.json"
    
    if not os.path.exists(report_path):
        print(f"Report not found: {report_path}")
        sys.exit(1)
    
    with open(report_path) as f:
        report = json.load(f)
    
    # Extract all calls in order
    calls = []
    for proc in report.get("behavior", {}).get("processes", []):
        for c in proc.get("calls", []):
            calls.append(c)
    
    # Sort by timestamp
    calls.sort(key=lambda x: x.get("time", 0))
    
    # ── FULL SEQUENCE ──
    print("=" * 75)
    print("  FULL API CALL SEQUENCE")
    print("=" * 75)
    print(f"  {'#':>4}  {'Time (s)':>10}  {'Cat':>5}  {'API Name':<35}  Return")
    print("-" * 75)
    
    for i, c in enumerate(calls, 1):
        t = c.get("time", 0)
        cat = c.get("category", "?")
        api = c.get("api", "?")
        ret = str(c.get("return", ""))
        if len(ret) > 15:
            ret = ret[:12] + "..."
        print(f"  {i:4d}  {t:10.4f}  {cat:>5}  {api:<35}  {ret}")
    
    print(f"\n  Total: {len(calls)} API calls\n")
    
    # ── DEDUPLICATED SEQUENCE (for ML) ──
    print("=" * 75)
    print("  API SEQUENCE FOR ML (consecutive duplicates removed)")
    print("=" * 75)
    
    deduped = []
    prev = None
    for c in calls:
        api = c.get("api", "?")
        if api != prev:
            deduped.append(api)
            prev = api
    
    print(f"  Sequence length: {len(deduped)} (from {len(calls)} raw calls)\n")
    
    for i, api in enumerate(deduped, 1):
        print(f"  {i:3d}. {api}")
    
    # ── RAW API NAME LIST (for ML input) ──
    print(f"\n{'=' * 75}")
    print("  RAW SEQUENCE (copy-paste for ML)")
    print("=" * 75)
    
    raw_seq = [c.get("api", "?") for c in calls]
    print(f"  {raw_seq}")
    
    # ── CATEGORY FLOW ──
    print(f"\n{'=' * 75}")
    print("  BEHAVIORAL FLOW (category transitions)")
    print("=" * 75)
    
    cat_flow = []
    prev_cat = None
    for c in calls:
        cat = c.get("category", "?")
        if cat != prev_cat:
            cat_flow.append(cat)
            prev_cat = cat
    
    print(f"  {' -> '.join(cat_flow)}")
    print()

if __name__ == "__main__":
    main()
