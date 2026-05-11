"""
verdict_engine.py — Hybrid Final Verdict (Heuristics + LSTM)
=============================================================
Combines monitor red flags with LSTM behavioral prediction
to produce a definitive MALWARE / BENIGN / SUSPICIOUS verdict.

Architecture:
    Layer 1: Heuristic Score (0-100) from monitors
    Layer 2: LSTM Prediction (0-100% confidence) from API sequence
    Fusion:  Weighted combination with corroboration logic

Usage:
    from verdict_engine import calculate_final_verdict
    verdict = calculate_final_verdict(final_report, api_sequence)
"""

import os
import sys
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── LSTM Model Loader ──────────────────────────────────────────────────────

_lstm_model = None
_token_maps = None
_lstm_available = False


def _load_lstm():
    """Lazy-load the BiLSTM model and token maps."""
    global _lstm_model, _token_maps, _lstm_available

    if _lstm_model is not None:
        return _lstm_available

    model_dir = os.path.join(SCRIPT_DIR, "..", "old", "output")
    model_path = os.path.join(model_dir, "malware_lstm_model.pt")
    maps_path = os.path.join(model_dir, "token_maps.json")

    if not os.path.exists(model_path) or not os.path.exists(maps_path):
        print("[VERDICT] WARNING: LSTM model not found. AI layer disabled.")
        _lstm_available = False
        return False

    try:
        import torch
        import torch.nn as nn

        with open(maps_path, "r") as f:
            _token_maps = json.load(f)

        api_to_idx = _token_maps["api_to_idx"]
        PAD_IDX = 0
        UNK_IDX = api_to_idx["<UNK>"]
        VOCAB_SIZE = max(int(k) for k in _token_maps["idx_to_api"].keys()) + 1

        class MalwareClassifier(nn.Module):
            def __init__(self):
                super().__init__()
                self.embedding = nn.Embedding(VOCAB_SIZE, 64, padding_idx=PAD_IDX)
                self.lstm = nn.LSTM(64, 128, 2, batch_first=True,
                                    bidirectional=True, dropout=0.3)
                self.dropout1 = nn.Dropout(0.3)
                self.fc1 = nn.Linear(256, 64)
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

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = MalwareClassifier().to(device)
        model.load_state_dict(torch.load(model_path, map_location=device,
                                          weights_only=True))
        model.eval()

        _lstm_model = {"model": model, "device": device,
                       "vocab_size": VOCAB_SIZE, "unk_idx": UNK_IDX}
        _lstm_available = True
        print(f"[VERDICT] LSTM model loaded on {device} (vocab={VOCAB_SIZE})")
        return True

    except ImportError:
        print("[VERDICT] WARNING: PyTorch not installed. AI layer disabled.")
        _lstm_available = False
        return False
    except Exception as e:
        print(f"[VERDICT] WARNING: LSTM load failed: {e}")
        _lstm_available = False
        return False


# ─── API Name Normalization ─────────────────────────────────────────────────

# Our hook DLL captures Win32 API names (CreateFileA, CloseHandle, etc.)
# but the LSTM was trained on Cuckoo sandbox data which uses Nt-level names.
# This mapping bridges the gap.
_WIN32_TO_CUCKOO = {
    # File operations
    "CreateFileA":          "NtCreateFile",
    "CreateFileW":          "NtCreateFile",
    "WriteFile":            "NtWriteFile",
    "ReadFile":             "NtReadFile",
    "CloseHandle":          "NtClose",
    "DeleteFileA":          "DeleteFileW",
    "DeleteFileW":          "DeleteFileW",
    "MoveFileA":            "MoveFileWithProgressW",
    "MoveFileW":            "MoveFileWithProgressW",
    "CopyFileA":            "CopyFileA",
    "SetFilePointer":       "SetFilePointer",
    "GetFileSize":          "GetFileSize",
    "FindFirstFileA":       "FindFirstFileExA",
    "FindFirstFileW":       "FindFirstFileExW",
    "CreateDirectoryA":     "CreateDirectoryW",
    # Process operations
    "CreateProcessA":       "CreateProcessInternalW",
    "CreateProcessW":       "CreateProcessInternalW",
    "OpenProcess":          "NtOpenProcess",
    "TerminateProcess":     "NtTerminateProcess",
    "ExitProcess":          "NtTerminateProcess",
    "ResumeThread":         "NtResumeThread",
    "SuspendThread":        "NtSuspendThread",
    "CreateThread":         "CreateThread",
    "GetCurrentProcessId":  "NtQueryInformationFile",
    # Memory operations
    "VirtualAlloc":         "NtAllocateVirtualMemory",
    "VirtualAllocEx":       "NtAllocateVirtualMemory",
    "VirtualFree":          "NtFreeVirtualMemory",
    "VirtualProtect":       "NtProtectVirtualMemory",
    "VirtualProtectEx":     "NtProtectVirtualMemory",
    "ReadProcessMemory":    "ReadProcessMemory",
    "WriteProcessMemory":   "WriteProcessMemory",
    # Registry operations
    "RegOpenKeyExA":        "RegOpenKeyExA",
    "RegOpenKeyExW":        "RegOpenKeyExW",
    "RegCreateKeyExA":      "RegCreateKeyExA",
    "RegCreateKeyExW":      "RegCreateKeyExW",
    "RegSetValueExA":       "RegSetValueExA",
    "RegSetValueExW":       "RegSetValueExW",
    "RegQueryValueExA":     "RegQueryValueExA",
    "RegQueryValueExW":     "RegQueryValueExW",
    "RegCloseKey":          "RegCloseKey",
    "RegDeleteKeyA":        "RegDeleteKeyA",
    "RegDeleteKeyW":        "RegDeleteKeyW",
    "RegDeleteValueA":      "RegDeleteValueA",
    "RegDeleteValueW":      "RegDeleteValueW",
    # DLL operations
    "LoadLibraryA":         "LdrLoadDll",
    "LoadLibraryW":         "LdrLoadDll",
    "LoadLibraryExA":       "LdrLoadDll",
    "LoadLibraryExW":       "LdrLoadDll",
    "FreeLibrary":          "LdrUnloadDll",
    "GetProcAddress":       "LdrGetProcedureAddress",
    # Network operations
    "socket":               "socket",
    "connect":              "connect",
    "send":                 "send",
    "recv":                 "recv",
    "closesocket":          "closesocket",
    "bind":                 "bind",
    "listen":               "listen",
    "accept":               "accept",
    "gethostbyname":        "gethostbyname",
    "getaddrinfo":          "getaddrinfo",
    "WSAStartup":           "WSAStartup",
    "WSASend":              "WSASend",
    "WSARecv":              "WSARecv",
    # Synchronization
    "CreateMutexA":         "NtCreateMutant",
    "CreateMutexW":         "NtCreateMutant",
    "OpenMutexA":           "NtOpenMutant",
    "OpenMutexW":           "NtOpenMutant",
    # System
    "ShellExecuteA":        "ShellExecuteExW",
    "ShellExecuteW":        "ShellExecuteExW",
    "ShellExecuteExA":      "ShellExecuteExW",
    "IsDebuggerPresent":    "IsDebuggerPresent",
    "GetSystemInfo":        "GetSystemInfo",
    "GetComputerNameA":     "GetComputerNameA",
    "GetComputerNameW":     "GetComputerNameW",
    "GetUserNameA":         "GetUserNameA",
    "GetUserNameW":         "GetUserNameW",
    # Crypto
    "CryptEncrypt":         "CryptEncrypt",
    "CryptDecrypt":         "CryptDecrypt",
    # Service
    "CreateServiceA":       "CreateServiceA",
    "CreateServiceW":       "CreateServiceW",
    "OpenServiceA":         "OpenServiceA",
    "OpenServiceW":         "OpenServiceW",
}


def _normalize_api_name(raw_name):
    """Map a raw API name from our hooks to the LSTM vocabulary token index."""
    if not _token_maps:
        return 0, raw_name

    api_to_idx = _token_maps["api_to_idx"]
    unk_idx = api_to_idx.get("<UNK>", 309)
    name = raw_name.strip()

    # 1. Direct match
    if name in api_to_idx:
        return api_to_idx[name], None

    # 2. Win32 → Cuckoo/Nt name mapping
    cuckoo_name = _WIN32_TO_CUCKOO.get(name)
    if cuckoo_name and cuckoo_name in api_to_idx:
        return api_to_idx[cuckoo_name], None

    # 3. Strip module prefix (e.g., "ntdll.NtOpenProcess" → "NtOpenProcess")
    if "." in name:
        stripped = name.split(".")[-1]
        if stripped in api_to_idx:
            return api_to_idx[stripped], None
        # Also check mapping for stripped name
        cuckoo_stripped = _WIN32_TO_CUCKOO.get(stripped)
        if cuckoo_stripped and cuckoo_stripped in api_to_idx:
            return api_to_idx[cuckoo_stripped], None

    # 4. Case-insensitive match
    name_lower = name.lower()
    for api_name, idx in api_to_idx.items():
        if api_name.lower() == name_lower:
            return idx, None

    # 5. Try A/W suffix variants
    base = name
    for suffix in ["A", "W"]:
        if name.endswith(suffix):
            base = name[:-1]
            break
    if base != name:
        if base in api_to_idx:
            return api_to_idx[base], None
        # Check mapping for base name
        cuckoo_base = _WIN32_TO_CUCKOO.get(base)
        if cuckoo_base and cuckoo_base in api_to_idx:
            return api_to_idx[cuckoo_base], None

    # 6. Try adding suffixes
    for suffix in ["A", "W", "Ex", "ExA", "ExW"]:
        variant = name + suffix
        if variant in api_to_idx:
            return api_to_idx[variant], None

    return unk_idx, raw_name


# ─── LSTM Prediction ────────────────────────────────────────────────────────

def _predict_lstm(api_names: list) -> dict:
    """
    Run the LSTM model on an API call sequence.

    Args:
        api_names: List of API function names (e.g., ["CreateFileA", "RegSetValueExW", ...])

    Returns:
        Dict with prediction, confidence, reliability tier, and unknown APIs.
    """
    if not _load_lstm():
        return {
            "lstm_available": False,
            "lstm_prediction": "UNAVAILABLE",
            "lstm_confidence": 0.0,
            "lstm_reliability": "NONE",
            "lstm_unk_ratio": 0.0,
            "lstm_unknown_apis": [],
        }

    import torch

    model = _lstm_model["model"]
    device = _lstm_model["device"]
    unk_idx = _lstm_model["unk_idx"]
    SEQ_LEN = 100

    # Tokenize
    indices = []
    unknown_apis = []
    for name in api_names:
        token_idx, unk = _normalize_api_name(name)
        indices.append(token_idx)
        if unk:
            unknown_apis.append(unk)

    orig_len = max(len(indices), 1)

    # Pad or truncate to SEQ_LEN
    if len(indices) < SEQ_LEN:
        indices += [0] * (SEQ_LEN - len(indices))
    else:
        indices = indices[:SEQ_LEN]

    # Predict
    seq = torch.LongTensor(indices).unsqueeze(0).to(device)
    with torch.no_grad():
        prob = torch.sigmoid(model(seq)).item()

    # Reliability tier based on UNK ratio
    unk_ratio = len(set(unknown_apis)) / orig_len
    if unk_ratio <= 0.10:
        reliability = "HIGH"
    elif unk_ratio <= 0.30:
        reliability = "MEDIUM"
    elif unk_ratio <= 0.70:
        reliability = "LOW"
    else:
        reliability = "VERY_LOW"

    if prob > 0.5:
        prediction = "MALWARE"
        confidence = prob * 100
    else:
        prediction = "BENIGN"
        confidence = (1 - prob) * 100

    return {
        "lstm_available": True,
        "lstm_prediction": prediction,
        "lstm_confidence": round(confidence, 2),
        "lstm_raw_prob": round(prob, 4),
        "lstm_reliability": reliability,
        "lstm_unk_ratio": round(unk_ratio, 4),
        "lstm_unknown_apis": list(set(unknown_apis))[:20],
        "lstm_sequence_length": orig_len,
    }


# ─── Heuristic Score Extraction ─────────────────────────────────────────────

def _extract_heuristic_flags(report: dict) -> dict:
    """
    Extract concrete red flags from the monitor reports.
    Each flag is a boolean + its contribution to the heuristic score.

    Returns:
        Dict of named flags with their weights and evidence strings.
    """
    summary = report.get("summary", {})
    files = report.get("file_activity", {})
    reg = report.get("registry_activity", {})
    mem = report.get("memory_activity", {})
    net = report.get("network_activity", {})

    file_sum = files.get("summary", {})
    reg_sum = reg.get("summary", {})
    mem_sum = mem.get("summary", {})
    net_sum = net.get("summary", {})

    flags = []

    # ── FILE flags ──
    susp_files = file_sum.get("suspicious_files", [])
    if susp_files:
        flags.append({
            "flag": "SUSPICIOUS_FILE_DROP",
            "weight": min(len(susp_files) * 15, 30),
            "evidence": f"{len(susp_files)} suspicious file(s): "
                        f"{[os.path.basename(f) for f in susp_files[:3]]}",
            "severity": "HIGH",
        })

    # ── REGISTRY flags ──
    if reg_sum.get("persistence_detected"):
        indicators = reg.get("persistence_indicators", [])
        flags.append({
            "flag": "REGISTRY_PERSISTENCE",
            "weight": 25,
            "evidence": f"Persistence keys modified: {indicators[:2]}",
            "severity": "CRITICAL",
        })

    # ── MEMORY flags ──
    rwx_count = mem_sum.get("rwx_count", 0)
    if rwx_count > 0:
        flags.append({
            "flag": "RWX_MEMORY",
            "weight": min(rwx_count * 10, 20),
            "evidence": f"{rwx_count} RWX allocation(s) detected",
            "severity": "HIGH",
        })

    if mem_sum.get("injection_detected"):
        flags.append({
            "flag": "PROCESS_INJECTION",
            "weight": 20,
            "evidence": "Cross-process memory injection detected",
            "severity": "CRITICAL",
        })

    if mem_sum.get("pe_in_memory"):
        flags.append({
            "flag": "PE_IN_MEMORY",
            "weight": 10,
            "evidence": "PE header found in memory dump (unpacked payload)",
            "severity": "HIGH",
        })

    # ── NETWORK flags ──
    if net_sum.get("connections_without_dns"):
        flags.append({
            "flag": "DIRECT_IP_CONNECTION",
            "weight": 10,
            "evidence": f"Direct IP (no DNS): {net_sum['connections_without_dns'][:2]}",
            "severity": "MEDIUM",
        })

    if net_sum.get("c2_risk") in ("HIGH", "MEDIUM"):
        w = 15 if net_sum["c2_risk"] == "HIGH" else 8
        flags.append({
            "flag": "C2_COMMUNICATION",
            "weight": w,
            "evidence": f"C2 risk level: {net_sum['c2_risk']}",
            "severity": "CRITICAL" if net_sum["c2_risk"] == "HIGH" else "HIGH",
        })

    if net_sum.get("suspicious_ports_used"):
        flags.append({
            "flag": "SUSPICIOUS_PORTS",
            "weight": 8,
            "evidence": f"Ports: {net_sum['suspicious_ports_used'][:3]}",
            "severity": "MEDIUM",
        })

    heuristic_score = min(sum(f["weight"] for f in flags), 100)

    return {
        "flags": flags,
        "heuristic_score": heuristic_score,
        "flag_count": len(flags),
    }


# ─── Fusion Engine ──────────────────────────────────────────────────────────

def calculate_final_verdict(final_report: dict, api_sequence: list = None) -> dict:
    """
    Calculate the definitive MALWARE / BENIGN / SUSPICIOUS verdict.

    Combines two independent layers:
        Layer 1 (Heuristic): Explicit red flags from monitors (0-100)
        Layer 2 (AI/LSTM):   Behavioral sequence prediction (0-100%)

    Fusion Logic:
        ┌─────────────────────────────────────────────────────────────┐
        │  IF heuristic_score >= 50         → MALWARE (monitors say) │
        │  IF heuristic_score >= 30 AND     → MALWARE (corroborated) │
        │     LSTM says MALWARE >= 70%                               │
        │  IF LSTM says MALWARE >= 90% AND  → MALWARE (AI confident) │
        │     reliability is HIGH                                    │
        │  IF heuristic_score >= 15 OR      → SUSPICIOUS             │
        │     LSTM says MALWARE >= 55%                               │
        │  ELSE                             → BENIGN                 │
        └─────────────────────────────────────────────────────────────┘

    Args:
        final_report: The merged final_report.json dict.
        api_sequence: List of API names from deduped_sequence.
                      If None, extracted from report automatically.

    Returns:
        Dict with verdict, confidence, reasoning, and layer details.
    """
    # ── Extract API sequence from report if not provided ──
    if api_sequence is None:
        api_behavior = final_report.get("api_behavior", {})
        api_sequence = api_behavior.get("deduped_sequence", [])

    # ── Layer 1: Heuristic Analysis ──
    heuristic = _extract_heuristic_flags(final_report)
    h_score = heuristic["heuristic_score"]
    flags = heuristic["flags"]

    # ── Layer 2: LSTM Prediction ──
    if len(api_sequence) >= 5:
        lstm = _predict_lstm(api_sequence)
    else:
        lstm = {
            "lstm_available": False,
            "lstm_prediction": "INSUFFICIENT_DATA",
            "lstm_confidence": 0.0,
            "lstm_reliability": "NONE",
            "lstm_unk_ratio": 0.0,
            "lstm_unknown_apis": [],
            "lstm_sequence_length": len(api_sequence),
        }

    lstm_says_malware = (lstm["lstm_prediction"] == "MALWARE")
    lstm_conf = lstm["lstm_confidence"]
    lstm_reliable = lstm["lstm_reliability"] in ("HIGH", "MEDIUM")

    # ── Fusion Decision ──
    reasoning = []
    verdict = "BENIGN"
    combined_confidence = 0.0

    # Rule 1: Strong heuristic evidence alone = MALWARE
    if h_score >= 50:
        verdict = "MALWARE"
        combined_confidence = min(h_score + 10, 100)
        reasoning.append(
            f"Heuristic score {h_score}/100 exceeds threshold (>=50). "
            f"{len(flags)} red flag(s) detected by monitors."
        )

    # Rule 2: Moderate heuristic + LSTM agreement = MALWARE
    elif h_score >= 30 and lstm_says_malware and lstm_conf >= 70:
        verdict = "MALWARE"
        combined_confidence = (h_score * 0.5) + (lstm_conf * 0.5)
        reasoning.append(
            f"Corroborated: Heuristic {h_score}/100 + LSTM {lstm_conf:.1f}% malware. "
            f"Both layers agree."
        )

    # Rule 3: Very high LSTM confidence + reliable = MALWARE
    elif lstm_says_malware and lstm_conf >= 90 and lstm_reliable:
        verdict = "MALWARE"
        combined_confidence = lstm_conf * 0.85
        reasoning.append(
            f"LSTM predicts MALWARE at {lstm_conf:.1f}% confidence "
            f"(reliability: {lstm['lstm_reliability']}). "
            f"AI-driven verdict with high confidence."
        )

    # Rule 4: Moderate signals = SUSPICIOUS
    elif h_score >= 15:
        verdict = "SUSPICIOUS"
        combined_confidence = h_score + 15
        reasoning.append(
            f"Heuristic score {h_score}/100 indicates suspicious behavior. "
            f"Not enough evidence for definitive malware verdict."
        )

    elif lstm_says_malware and lstm_conf >= 55 and lstm_reliable:
        verdict = "SUSPICIOUS"
        combined_confidence = lstm_conf * 0.6
        reasoning.append(
            f"LSTM predicts MALWARE at {lstm_conf:.1f}% but no heuristic "
            f"corroboration. Flagged as suspicious."
        )

    # Rule 5: Clean
    else:
        verdict = "BENIGN"
        if lstm["lstm_prediction"] == "BENIGN" and lstm["lstm_available"]:
            combined_confidence = lstm_conf
            reasoning.append(
                f"No red flags. LSTM predicts BENIGN at {lstm_conf:.1f}%."
            )
        else:
            combined_confidence = max(100 - h_score, 50)
            reasoning.append(
                f"No red flags detected by monitors (score: {h_score}/100)."
            )

    # ── Reliability caveat ──
    if lstm.get("lstm_reliability") == "VERY_LOW" and lstm["lstm_available"]:
        reasoning.append(
            f"WARNING: LSTM reliability is VERY LOW "
            f"(UNK ratio: {lstm['lstm_unk_ratio']:.0%}). "
            f"AI prediction should NOT be trusted."
        )
        # Downgrade AI-only verdicts
        if verdict == "MALWARE" and h_score < 30:
            verdict = "SUSPICIOUS"
            reasoning.append("Downgraded: MALWARE→SUSPICIOUS due to low AI reliability.")

    combined_confidence = round(min(combined_confidence, 100), 1)

    # ── Build result ──
    result = {
        "verdict": verdict,
        "combined_confidence": combined_confidence,
        "reasoning": reasoning,

        # Layer 1 detail
        "heuristic": {
            "score": h_score,
            "flag_count": len(flags),
            "flags": flags,
        },

        # Layer 2 detail
        "lstm": lstm,

        # Decision metadata
        "decision_path": _get_decision_path(h_score, lstm),
    }

    # ── Print verdict ──
    _print_verdict(result)

    return result


def _get_decision_path(h_score, lstm) -> str:
    """Return a human-readable label for which rule triggered the verdict."""
    lstm_pred = lstm.get("lstm_prediction", "")
    lstm_conf = lstm.get("lstm_confidence", 0)
    reliable = lstm.get("lstm_reliability", "") in ("HIGH", "MEDIUM")

    if h_score >= 50:
        return "HEURISTIC_DOMINANT"
    if h_score >= 30 and lstm_pred == "MALWARE" and lstm_conf >= 70:
        return "CORROBORATED"
    if lstm_pred == "MALWARE" and lstm_conf >= 90 and reliable:
        return "AI_DOMINANT"
    if h_score >= 15:
        return "HEURISTIC_SUSPICIOUS"
    if lstm_pred == "MALWARE" and lstm_conf >= 55 and reliable:
        return "AI_SUSPICIOUS"
    return "CLEAN"


def _print_verdict(result: dict):
    """Print a formatted verdict to the terminal."""
    v = result["verdict"]
    conf = result["combined_confidence"]
    h = result["heuristic"]
    lstm = result["lstm"]

    W = 64
    if v == "MALWARE":
        icon, bar = "[!!!]", "#" * 20
    elif v == "SUSPICIOUS":
        icon, bar = "[???]", "?" * 14
    else:
        icon, bar = "[OK]", "-" * 8

    print()
    print("=" * W)
    print(f"  {icon}  FINAL VERDICT: {v}")
    print(f"       Combined Confidence: {conf}%")
    print(f"       Decision Path: {result['decision_path']}")
    print("=" * W)

    # Layer 1
    print(f"  Layer 1 — Heuristic Monitors")
    print(f"    Score: {h['score']}/100  |  Red Flags: {h['flag_count']}")
    for f in h["flags"]:
        print(f"    [{f['severity'][:4]}] {f['flag']}: {f['evidence']}")

    # Layer 2
    print(f"  Layer 2 — LSTM Behavioral AI")
    if lstm.get("lstm_available"):
        print(f"    Prediction: {lstm['lstm_prediction']} "
              f"({lstm['lstm_confidence']:.1f}%)")
        print(f"    Reliability: {lstm['lstm_reliability']} "
              f"(UNK ratio: {lstm['lstm_unk_ratio']:.0%})")
        print(f"    Sequence Length: {lstm.get('lstm_sequence_length', '?')}")
        if lstm.get("lstm_unknown_apis"):
            print(f"    Unknown APIs: {lstm['lstm_unknown_apis'][:5]}")
    else:
        print(f"    Status: {lstm.get('lstm_prediction', 'UNAVAILABLE')}")

    # Reasoning
    print(f"\n  Reasoning:")
    for r in result["reasoning"]:
        print(f"    > {r}")
    print("=" * W)


# ─── Standalone Test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Verdict Engine Test")
    parser.add_argument("--report", default=None,
                        help="Path to final_report.json")
    args = parser.parse_args()

    if args.report and os.path.exists(args.report):
        with open(args.report) as f:
            report = json.load(f)
        result = calculate_final_verdict(report)
    else:
        # Demo with synthetic data
        print("[VERDICT] Running demo with synthetic report...\n")
        demo_report = {
            "summary": {"threat_score": 45, "threat_level": "HIGH"},
            "api_behavior": {
                "deduped_sequence": [
                    "NtCreateFile", "RegSetValueExW", "NtAllocateVirtualMemory",
                    "NtProtectVirtualMemory", "CreateThread", "connect",
                    "send", "recv", "NtClose", "NtTerminateProcess",
                ],
            },
            "file_activity": {
                "summary": {
                    "total_created": 2,
                    "suspicious_files": ["C:\\Temp\\payload.exe"],
                }
            },
            "registry_activity": {
                "summary": {"persistence_detected": True},
                "persistence_indicators": [
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                ],
            },
            "memory_activity": {
                "summary": {"rwx_count": 2, "rwx_detected": True,
                            "injection_detected": False, "pe_in_memory": False},
            },
            "network_activity": {
                "summary": {"total_connections": 1, "c2_risk": "MEDIUM",
                            "connections_without_dns": [],
                            "suspicious_ports_used": []},
            },
        }
        result = calculate_final_verdict(demo_report)
        print(f"\nResult JSON keys: {list(result.keys())}")
