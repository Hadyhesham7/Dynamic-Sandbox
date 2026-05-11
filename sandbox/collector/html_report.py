"""
html_report.py — Static HTML Dashboard Generator
===================================================
Generates a self-contained, offline HTML report from final_report.json.
No external CDN, no web server, no network pollution.

Usage:
    from sandbox.collector.html_report import generate_html_report
    generate_html_report("sandbox/reports/final_report.json",
                         "sandbox/reports/report.html")
"""

import os
import json
import time
import html as html_mod


def _escape(text):
    """Escape text for safe HTML embedding."""
    if text is None:
        return ""
    return html_mod.escape(str(text))


def _risk_color(level):
    """Return CSS color for risk level."""
    if level in ("HIGH", "CRITICAL"):
        return "#ff4757"
    if level == "MEDIUM":
        return "#ffa502"
    return "#2ed573"


def _friendly_reg_type(reg_type):
    """Convert registry type codes to human-friendly descriptions."""
    mapping = {
        "REG_SZ": "Text String",
        "REG_EXPAND_SZ": "Expandable Text String",
        "REG_BINARY": "Binary Data",
        "REG_DWORD": "Integer Number (32-bit)",
        "REG_QWORD": "Integer Number (64-bit)",
        "REG_MULTI_SZ": "Multiple Text Strings",
    }
    friendly = mapping.get(reg_type, reg_type)
    return f"{friendly} ({reg_type})" if reg_type in mapping else reg_type


def _build_stat_card(title, value, icon, color="#a29bfe"):
    """Generate HTML for a stat card."""
    return f"""
    <div class="stat-card">
        <div class="stat-icon" style="color:{color}">{icon}</div>
        <div class="stat-value">{_escape(str(value))}</div>
        <div class="stat-label">{_escape(title)}</div>
    </div>"""


def _build_evidence_row(icon, title, detail, context="", raw_html=False):
    """Generate HTML for an evidence row."""
    ctx_html = ""
    if context:
        ctx_html = f'<div class="evidence-context">↳ {_escape(context)}</div>'
    detail_html = detail if raw_html else _escape(detail)
    return f"""
    <div class="evidence-row">
        <span class="evidence-icon">{icon}</span>
        <div class="evidence-content">
            <div class="evidence-title">{_escape(title)}</div>
            <div class="evidence-detail">{detail_html}</div>
            {ctx_html}
        </div>
    </div>"""


def generate_html_report(json_path, output_path=None):
    """
    Generate a self-contained HTML report from final_report.json.

    Args:
        json_path: Path to final_report.json
        output_path: Where to save the HTML (default: same dir as json)

    Returns:
        Path to generated HTML file
    """
    if not os.path.exists(json_path):
        print(f"[HTML] ERROR: Report not found: {json_path}")
        return None

    with open(json_path) as f:
        report = json.load(f)

    if output_path is None:
        output_path = json_path.replace(".json", ".html")

    summary = report.get("summary", {})
    api = report.get("api_behavior", {})
    files = report.get("file_activity", {})
    reg = report.get("registry_activity", {})
    net = report.get("network_activity", {})
    mem = report.get("memory_activity", {})
    info = report.get("info", {})
    ai_verdict = report.get("ai_verdict", {})

    risk_count = summary.get("total_risk_indicators", 0)
    threat_score = summary.get("threat_score", 0)
    threat_level = summary.get("threat_level", "UNKNOWN")
    risk_level = threat_level

    sample_info = info.get("sample", {})
    sample_name = sample_info.get("name", "")
    # Try to extract exe name from the json path or api report
    if not sample_name:
        # Look for sample name in the API behavior data
        api_report_path = api.get("source_report", "")
        if api_report_path:
            sample_name = os.path.basename(api_report_path)
    # Final fallback: extract from the json_path directory context
    if not sample_name:
        # Try to find any .exe reference in the report
        for f_item in files.get("summary", {}).get("suspicious_files", []):
            if f_item.lower().endswith(".exe"):
                sample_name = os.path.basename(f_item)
                break
    exe_hint = sample_name if sample_name else "unknown"
    if not sample_name:
        sample_name = f"Unknown (see JSON report)"
    generated_at = info.get("generated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ"))

    # Color for threat score
    if threat_score >= 70:
        score_color = "#ff6b6b"
    elif threat_score >= 50:
        score_color = "#fd79a8"
    elif threat_score >= 30:
        score_color = "#ffeaa7"
    else:
        score_color = "#00cec9"

    stat_cards = "".join([
        _build_stat_card("Threat Score", f"{threat_score}/100", "🎯", score_color),
        _build_stat_card("API Calls", api.get("total_calls", 0), "⚡", "#a29bfe"),
        _build_stat_card("Unique APIs", api.get("unique_apis", 0), "🔧", "#74b9ff"),
        _build_stat_card("Files Dropped", files.get("summary", {}).get("total_created", 0), "📁", "#ffeaa7"),
        _build_stat_card("Registry Changes", summary.get("registry_changes", 0), "🔑", "#fd79a8"),
        _build_stat_card("Connections", summary.get("connections", 0), "🌐", "#00cec9"),
        _build_stat_card("RWX Allocs", summary.get("rwx_count", 0), "💉", "#ff6b6b"),
    ])

    # ── Build risk indicators ──
    risk_html = ""
    for ind in summary.get("risk_indicators", []):
        risk_html += f'<div class="risk-item">⚠ {_escape(ind)}</div>\n'
    if not risk_html:
        risk_html = '<div class="risk-clean">✅ No risk indicators detected.</div>'

    # ── Build FILE evidence ──
    file_evidence = ""
    f_summary = files.get("summary", {})
    if f_summary:
        for f_item in files.get("files_created", []):
            fp = f_item.get("path", "?")
            fname = os.path.basename(fp)
            ext = os.path.splitext(fname)[1].lower()
            ftype = f_item.get("file_type", "Unknown")
            size = f_item.get("size", "?")
            sha = f_item.get("hash_sha256") or f_item.get("hash", "")
            md5 = f_item.get("hash_md5", "")
            is_suspicious = f_item.get("suspicious", False)

            if is_suspicious:
                if ext in (".exe", ".dll", ".scr"):
                    ctx = "Executable dropped — possible payload delivery"
                elif ext in (".bat", ".cmd", ".ps1", ".vbs"):
                    ctx = "Script dropped — possible second-stage execution"
                else:
                    ctx = "Suspicious file type dropped to disk"
                icon = "🔴"
            else:
                ctx = ""
                icon = "🟡"

            # Build detail string with hashes
            detail_parts = [f"Size: {size} bytes", f"Type: {ftype}"]
            detail = " | ".join(detail_parts)
            if sha:
                detail += f"<br><span style='font-family:monospace;font-size:0.8em;color:#a29bfe'>SHA256: {_escape(sha)}</span>"
            if md5:
                detail += f"<br><span style='font-family:monospace;font-size:0.8em;color:#74b9ff'>MD5: {_escape(md5)}</span>"

            file_evidence += _build_evidence_row(icon, f"Dropped: {fname}", detail, ctx, raw_html=True)

        for f_item in files.get("files_modified", []):
            fname = os.path.basename(f_item.get("path", "?"))
            old_s = f_item.get("old_size", "?")
            new_s = f_item.get("new_size", "?")
            file_evidence += _build_evidence_row(
                "🟠", f"Modified: {fname}",
                f"Size: {old_s} → {new_s} bytes")

    if not file_evidence:
        file_evidence = '<div class="no-data">No file activity detected.</div>'

    # ── Build REGISTRY evidence ──
    reg_evidence = ""
    persistence = reg.get("persistence_indicators", [])
    for ind in persistence[:5]:
        if "\\Run" in ind:
            ctx = "Ensures automatic execution on startup (Persistence)"
        elif "\\Services" in ind:
            ctx = "Registers as Windows Service (Persistence)"
        elif "\\Winlogon" in ind:
            ctx = "Hijacks login process (Advanced Persistence)"
        else:
            ctx = "Sensitive registry location modified"
        reg_evidence += _build_evidence_row("🔴", "Persistence", ind, ctx)

    for val in reg.get("values_set", [])[:5]:
        key = val.get("key", "")
        name = val.get("name", "")
        data = val.get("data", "")
        raw_type = val.get("type", "")
        friendly_type = _friendly_reg_type(raw_type) if raw_type else ""
        reg_evidence += _build_evidence_row("🟠", f"{key}\\{name}",
                                            f"Value: {data}",
                                            friendly_type)
    if not reg_evidence:
        reg_evidence = '<div class="no-data">No registry changes detected.</div>'

    # ── Build NETWORK evidence ──
    net_evidence = ""
    for conn in net.get("connections", [])[:5]:
        ip = conn.get("ip", "?")
        port = conn.get("port", "?")
        susp = conn.get("suspicious", "")
        if susp:
            net_evidence += _build_evidence_row(
                "🔴", f"Connection → {ip}:{port}",
                f"Suspicious: {susp}",
                f"Port {port} is commonly used for {susp}")
        else:
            net_evidence += _build_evidence_row(
                "🟡", f"Connection → {ip}:{port}", "")

    for dns in net.get("dns_queries", [])[:5]:
        hostname = dns.get("hostname", "?")
        net_evidence += _build_evidence_row(
            "🟠", f"DNS → {hostname}", "",
            "Domain resolution — possible C2 beacon")

    no_dns = net.get("summary", {}).get("connections_without_dns", [])
    for ip in no_dns[:3]:
        net_evidence += _build_evidence_row(
            "🔴", f"Direct IP (no DNS): {ip}", "",
            "Hardcoded IP — bypasses DNS monitoring")
    if not net_evidence:
        net_evidence = '<div class="no-data">No network activity detected.</div>'

    # ── Build MEMORY evidence ──
    mem_evidence = ""
    for rwx in mem.get("rwx_allocations", [])[:5]:
        addr = rwx.get("address", "?")
        size = rwx.get("size", "?")
        api_name = rwx.get("api", "?")
        if api_name == "VirtualAllocEx":
            ctx = "Remote RWX — classic process injection pattern"
        elif api_name == "VirtualProtect":
            ctx = "Re-protection to RWX — possible unpacking/shellcode"
        else:
            ctx = "Executable memory — could contain shellcode"
        mem_evidence += _build_evidence_row(
            "🔴", f"{api_name} @ {addr}", f"Size: {size} bytes", ctx)

    for inj in mem.get("injection_indicators", [])[:3]:
        mem_evidence += _build_evidence_row(
            "🔴", f"Injection: {inj.get('api', '?')}", "",
            "Process injection technique detected")
    if not mem_evidence:
        mem_evidence = '<div class="no-data">No suspicious memory activity.</div>'

    # ── Build API frequency chart (CSS-only bar chart) ──
    api_freq = api.get("api_frequency", {})
    top_apis = list(api_freq.items())[:12]
    max_count = max((c for _, c in top_apis), default=1)
    api_bars = ""
    for name, count in top_apis:
        pct = min(count / max_count * 100, 100)
        api_bars += f"""
        <div class="bar-row">
            <span class="bar-label">{_escape(name)}</span>
            <div class="bar-track">
                <div class="bar-fill" style="width:{pct}%"></div>
            </div>
            <span class="bar-value">{count}</span>
        </div>"""

    # ── Build API category chart ──
    cat_counts = api.get("category_counts", {})
    cat_bars = ""
    cat_max = max(cat_counts.values(), default=1)
    cat_colors = {
        "FILE": "#ffeaa7", "REG": "#fd79a8", "NET": "#00cec9",
        "MEM": "#ff6b6b", "PROC": "#a29bfe", "DLL": "#74b9ff",
        "SYS": "#636e72", "SYNC": "#81ecec", "CRYPTO": "#fab1a0",
        "SVC": "#dfe6e9",
    }
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        pct = min(count / cat_max * 100, 100)
        color = cat_colors.get(cat, "#b2bec3")
        cat_bars += f"""
        <div class="bar-row">
            <span class="bar-label">{_escape(cat)}</span>
            <div class="bar-track">
                <div class="bar-fill" style="width:{pct}%;background:{color}"></div>
            </div>
            <span class="bar-value">{count}</span>
        </div>"""

    # ── Deduped API sequence (scrollable) ──
    deduped = api.get("deduped_sequence", [])
    seq_html = " → ".join(f'<span class="seq-api">{_escape(a)}</span>'
                          for a in deduped[:60])
    if len(deduped) > 60:
        seq_html += f' <span class="seq-more">... +{len(deduped)-60} more</span>'

    # ── Build Screenshots evidence ──
    screenshots = report.get("screenshots", {})
    screenshots_html = ""
    if screenshots.get("count", 0) > 0:
        screenshots_html = '<div class="screenshot-grid">'
        for f in screenshots.get("files", []):
            # Paths relative to the html report in the reports/ dir
            rel_path = f"artifacts/screenshots/{f}"
            screenshots_html += f'''
            <div class="screenshot-card">
                <a href="{rel_path}" target="_blank">
                    <img src="{rel_path}" alt="Screenshot" loading="lazy">
                </a>
            </div>'''
        screenshots_html += '</div>'
    else:
        screenshots_html = '<div class="no-data">No screenshots captured during execution.</div>'

    # ── Build AI Verdict banner ──
    verdict_html = ""
    if ai_verdict and ai_verdict.get("verdict"):
        v = ai_verdict["verdict"]
        v_conf = ai_verdict.get("combined_confidence", 0)
        v_path = ai_verdict.get("decision_path", "")
        h_data = ai_verdict.get("heuristic", {})
        l_data = ai_verdict.get("lstm", {})
        h_score = h_data.get("score", 0)
        h_flags = h_data.get("flags", [])
        l_pred = l_data.get("lstm_prediction", "N/A")
        l_conf = l_data.get("lstm_confidence", 0)
        l_rel = l_data.get("lstm_reliability", "N/A")
        l_unk = l_data.get("lstm_unk_ratio", 0)
        reasoning = ai_verdict.get("reasoning", [])

        if v == "MALWARE":
            v_color, v_border, v_icon = "#ff4757", "#ff6b81", "\u2620\ufe0f"
        elif v == "SUSPICIOUS":
            v_color, v_border, v_icon = "#ffa502", "#ffbe76", "\u26a0\ufe0f"
        else:
            v_color, v_border, v_icon = "#2ed573", "#7bed9f", "\u2705"

        # Build flag rows
        flag_rows = ""
        for fl in h_flags:
            sev = fl.get("severity", "")
            sev_color = "#ff4757" if sev in ("CRITICAL", "HIGH") else "#ffa502"
            flag_rows += f'<div class="verdict-flag"><span style="color:{sev_color}">[{_escape(sev)}]</span> {_escape(fl.get("flag", ""))}: {_escape(fl.get("evidence", ""))}</div>'

        # Build reasoning
        reason_rows = ""
        for r in reasoning:
            reason_rows += f'<div class="verdict-reason">&gt; {_escape(r)}</div>'

        verdict_html = f'''
    <div class="verdict-banner" style="border-color:{v_border}">
        <div class="verdict-header">
            <div class="verdict-icon">{v_icon}</div>
            <div class="verdict-title">
                <div class="verdict-label" style="color:{v_color}">AI VERDICT: {_escape(v)}</div>
                <div class="verdict-conf">Confidence: {v_conf}% &nbsp;|&nbsp; Path: {_escape(v_path)}</div>
            </div>
        </div>
        <div class="verdict-layers">
            <div class="verdict-layer">
                <div class="verdict-layer-title">Layer 1 &mdash; Heuristic Monitors</div>
                <div class="verdict-layer-score">Score: {h_score}/100 &nbsp;|&nbsp; Red Flags: {len(h_flags)}</div>
                {flag_rows}
            </div>
            <div class="verdict-layer">
                <div class="verdict-layer-title">Layer 2 &mdash; LSTM Behavioral AI</div>
                <div class="verdict-layer-score">Prediction: {_escape(l_pred)} ({l_conf}%) &nbsp;|&nbsp; Reliability: {_escape(l_rel)} &nbsp;|&nbsp; UNK: {l_unk:.0%}</div>
            </div>
        </div>
        <div class="verdict-reasoning">{reason_rows}</div>
    </div>'''
    else:
        verdict_html = '<div class="no-data">AI Verdict not available (run pipeline with PyTorch installed).</div>'

    # ── Assemble final HTML ──
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dynamic Sandbox Report - {_escape(sample_name)}</title>
<style>
:root {{
    --bg: #0a0a1a;
    --surface: #12122a;
    --surface2: #1a1a3e;
    --border: #2a2a5a;
    --text: #e0e0ff;
    --text-dim: #8888aa;
    --accent: #6c5ce7;
    --accent2: #a29bfe;
    --red: #ff4757;
    --orange: #ffa502;
    --green: #2ed573;
    --yellow: #ffeaa7;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    min-height: 100vh;
}}

/* Header */
.header {{
    background: linear-gradient(135deg, #1a1a3e 0%, #0a0a2e 100%);
    border-bottom: 1px solid var(--border);
    padding: 2rem 2rem 1.5rem;
}}
.header h1 {{
    font-size: 1.8rem;
    font-weight: 700;
    background: linear-gradient(90deg, var(--accent2), #74b9ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0.3rem;
}}
.header .subtitle {{
    color: var(--text-dim);
    font-size: 0.9rem;
}}
.risk-badge {{
    display: inline-block;
    padding: 0.3rem 1rem;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.85rem;
    margin-top: 0.8rem;
    letter-spacing: 0.5px;
}}

/* Layout */
.container {{ max-width: 1280px; margin: 0 auto; padding: 1.5rem; }}
.grid {{ display: grid; gap: 1.5rem; }}
.grid-2 {{ grid-template-columns: 1fr 1fr; }}
.grid-3 {{ grid-template-columns: repeat(3, 1fr); }}
.grid-6 {{ grid-template-columns: repeat(6, 1fr); }}
@media (max-width: 900px) {{
    .grid-2, .grid-3, .grid-6 {{ grid-template-columns: 1fr; }}
}}

/* Cards */
.card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    transition: border-color 0.2s;
}}
.card:hover {{ border-color: var(--accent); }}
.card h2 {{
    font-size: 1rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--accent2);
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
}}

/* Stat Cards */
.stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem;
    text-align: center;
    transition: transform 0.2s, border-color 0.2s;
}}
.stat-card:hover {{ transform: translateY(-2px); border-color: var(--accent); }}
.stat-icon {{ font-size: 1.5rem; margin-bottom: 0.3rem; }}
.stat-value {{ font-size: 1.8rem; font-weight: 700; color: #fff; }}
.stat-label {{ font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; }}

/* Evidence rows */
.evidence-row {{
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    padding: 0.75rem;
    border-radius: 8px;
    margin-bottom: 0.5rem;
    background: var(--surface2);
    border-left: 3px solid var(--border);
    transition: border-color 0.2s;
}}
.evidence-row:hover {{ border-left-color: var(--accent); }}
.evidence-icon {{ font-size: 1.2rem; flex-shrink: 0; margin-top: 2px; }}
.evidence-content {{ flex: 1; min-width: 0; }}
.evidence-title {{ font-weight: 600; font-size: 0.9rem; color: #fff; }}
.evidence-detail {{
    font-size: 0.8rem;
    color: var(--text-dim);
    word-break: break-all;
}}
.evidence-context {{
    font-size: 0.75rem;
    color: var(--orange);
    margin-top: 0.25rem;
    font-style: italic;
}}

/* Risk indicators */
.risk-item {{
    padding: 0.6rem 1rem;
    background: rgba(255,71,87,0.1);
    border: 1px solid rgba(255,71,87,0.3);
    border-radius: 8px;
    margin-bottom: 0.5rem;
    font-size: 0.85rem;
    color: var(--red);
}}
.risk-clean {{
    padding: 1rem;
    text-align: center;
    color: var(--green);
    font-size: 1rem;
}}

/* Bar chart */
.bar-row {{ display: flex; align-items: center; margin-bottom: 0.4rem; gap: 0.5rem; }}
.bar-label {{
    width: 140px;
    font-size: 0.75rem;
    color: var(--text-dim);
    text-align: right;
    flex-shrink: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}}
.bar-track {{
    flex: 1;
    height: 18px;
    background: var(--surface2);
    border-radius: 9px;
    overflow: hidden;
}}
.bar-fill {{
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
    border-radius: 9px;
    transition: width 0.5s ease;
    min-width: 2px;
}}
.bar-value {{ width: 40px; font-size: 0.75rem; color: var(--text-dim); }}

/* API Sequence */
.seq-container {{
    max-height: 150px;
    overflow-y: auto;
    padding: 1rem;
    background: var(--surface2);
    border-radius: 8px;
    font-size: 0.75rem;
    line-height: 2;
}}
.seq-api {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    margin: 0.1rem;
    color: var(--accent2);
    font-family: 'Consolas', monospace;
}}
.seq-more {{ color: var(--text-dim); }}

/* No data */
.no-data {{ color: var(--text-dim); text-align: center; padding: 1.5rem; font-style: italic; }}

/* Screenshots */
.screenshot-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1rem;
    padding: 1rem 0;
}}
.screenshot-card {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    transition: transform 0.2s, border-color 0.2s;
}}
.screenshot-card:hover {{ transform: translateY(-3px); border-color: var(--accent); }}
.screenshot-card img {{
    width: 100%;
    height: auto;
    display: block;
    border-bottom: 1px solid var(--border);
}}

/* Info grid */
.info-grid {{
    display: grid;
    grid-template-columns: 140px 1fr;
    gap: 0.5rem 1rem;
    font-size: 0.9rem;
}}
.info-label {{ color: var(--text-dim); font-weight: 500; }}
.info-value {{ color: #fff; font-weight: 600; word-break: break-all; }}

/* AI Verdict Banner */
.verdict-banner {{
    background: var(--surface);
    border: 2px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
}}
.verdict-header {{
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1rem;
}}
.verdict-icon {{ font-size: 2.5rem; }}
.verdict-label {{
    font-size: 1.6rem;
    font-weight: 800;
    letter-spacing: 1px;
}}
.verdict-conf {{
    font-size: 0.85rem;
    color: var(--text-dim);
    margin-top: 0.2rem;
}}
.verdict-layers {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
}}
.verdict-layer {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
}}
.verdict-layer-title {{
    font-weight: 700;
    color: var(--accent2);
    margin-bottom: 0.4rem;
    font-size: 0.9rem;
}}
.verdict-layer-score {{
    font-size: 0.8rem;
    color: var(--text-dim);
    margin-bottom: 0.5rem;
}}
.verdict-flag {{
    font-size: 0.78rem;
    color: var(--text);
    padding: 0.15rem 0;
    font-family: 'Consolas', monospace;
}}
.verdict-reasoning {{
    border-top: 1px solid var(--border);
    padding-top: 0.8rem;
}}
.verdict-reason {{
    font-size: 0.82rem;
    color: var(--text-dim);
    padding: 0.15rem 0;
    font-style: italic;
}}

/* Tabs */
.tabs {{ display: flex; gap: 0; margin-bottom: 1.5rem; }}
.tab {{
    padding: 0.6rem 1.5rem;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-dim);
    cursor: pointer;
    font-size: 0.85rem;
    transition: all 0.2s;
}}
.tab:first-child {{ border-radius: 8px 0 0 8px; }}
.tab:last-child {{ border-radius: 0 8px 8px 0; }}
.tab.active {{
    background: var(--accent);
    color: #fff;
    border-color: var(--accent);
}}
.tab-content {{ display: none; }}
.tab-content.active {{ display: block; }}

/* Footer */
.footer {{
    text-align: center;
    padding: 2rem;
    color: var(--text-dim);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
}}

/* Scrollbar */
::-webkit-scrollbar {{ width: 6px; }}
::-webkit-scrollbar-track {{ background: var(--surface); }}
::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
    <h1>Dynamic Sandbox Analysis Report</h1>
    <div class="subtitle">
        Sample: <strong>{_escape(sample_name)}</strong> &nbsp;|&nbsp;
        Generated: {_escape(generated_at)}
    </div>
    <div class="risk-badge" style="background:rgba({
        '255,71,87' if risk_level in ('HIGH','CRITICAL') else
        '255,165,2' if risk_level == 'MEDIUM' else
        '46,213,115' if risk_level == 'CLEAN' else '162,155,254'
    },0.2); color:{_risk_color(risk_level)}; border:1px solid {_risk_color(risk_level)}">
        {risk_level} RISK &mdash; {risk_count} indicator{'s' if risk_count != 1 else ''}
    </div>
</div>

<div class="container">

    <!-- Stat Cards -->
    <div class="grid grid-6" style="margin-bottom:1.5rem">
        {stat_cards}
    </div>

    <!-- Sample Info + Category Breakdown -->
    <div class="grid grid-2" style="margin-bottom:1.5rem">
        <div class="card">
            <h2>📋 Sample Information</h2>
            <div class="info-grid">
                <div class="info-label">Sample:</div>
                <div class="info-value">{_escape(sample_name)}</div>
                <div class="info-label">Total API calls:</div>
                <div class="info-value">{api.get('total_calls', 0)}</div>
                <div class="info-label">Unique APIs:</div>
                <div class="info-value">{api.get('unique_apis', 0)}</div>
                <div class="info-label">Generated:</div>
                <div class="info-value">{_escape(generated_at)}</div>
            </div>
        </div>
        <div class="card">
            <h2>📊 Calls by Category</h2>
            {cat_bars}
        </div>
    </div>

    <!-- AI Verdict Banner -->
    {verdict_html}

    <!-- Risk Indicators -->
    <div class="card" style="margin-bottom:1.5rem">
        <h2>⚠ Risk Indicators</h2>
        {risk_html}
    </div>

    <!-- Tab navigation -->
    <div class="tabs">
        <div class="tab active" onclick="switchTab('files')">📁 Files</div>
        <div class="tab" onclick="switchTab('registry')">🔑 Registry</div>
        <div class="tab" onclick="switchTab('network')">🌐 Network</div>
        <div class="tab" onclick="switchTab('memory')">💉 Memory</div>
        <div class="tab" onclick="switchTab('apis')">⚡ API Behavior</div>
        <div class="tab" onclick="switchTab('screenshots')">📸 Screenshots</div>
    </div>

    <!-- File Activity -->
    <div id="tab-files" class="tab-content active">
        <div class="card">
            <h2>📁 File System Activity</h2>
            {file_evidence}
        </div>
    </div>

    <!-- Registry Activity -->
    <div id="tab-registry" class="tab-content">
        <div class="card">
            <h2>🔑 Registry Activity</h2>
            {reg_evidence}
        </div>
    </div>

    <!-- Network Activity -->
    <div id="tab-network" class="tab-content">
        <div class="card">
            <h2>🌐 Network Activity</h2>
            {net_evidence}
        </div>
    </div>

    <!-- Memory Activity -->
    <div id="tab-memory" class="tab-content">
        <div class="card">
            <h2>💉 Memory Activity</h2>
            {mem_evidence}
        </div>
    </div>

    <!-- API Behavior -->
    <div id="tab-apis" class="tab-content">
        <div class="grid grid-2">
            <div class="card">
                <h2>Top APIs (frequency)</h2>
                {api_bars}
            </div>
            <div class="card">
                <h2>Category Breakdown</h2>
                {cat_bars}
            </div>
        </div>
        <div class="card" style="margin-top:1.5rem">
            <h2>API Call Sequence (Deduplicated)</h2>
            <div class="seq-container">{seq_html}</div>
        </div>
    </div>

    <!-- Screenshots -->
    <div id="tab-screenshots" class="tab-content">
        <div class="card">
            <h2>📸 Execution Screenshots</h2>
            {screenshots_html}
        </div>
    </div>

</div>

<div class="footer">
    Dynamic Sandbox v2.0 &nbsp;|&nbsp; Report generated offline — no network used
</div>

<script>
function switchTab(name) {{
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    event.target.classList.add('active');
}}
</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[HTML] Dashboard saved: {output_path}")
    return output_path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HTML Report Generator")
    parser.add_argument("--input", default="sandbox/reports/final_report.json")
    parser.add_argument("--output", default="sandbox/reports/report.html")
    args = parser.parse_args()
    generate_html_report(args.input, args.output)
