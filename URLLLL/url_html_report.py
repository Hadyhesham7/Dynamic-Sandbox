"""
url_html_report.py — Premium HTML Dashboard for URL Analysis v4.0
=================================================================
Features: Radial risk gauge, glassmorphism cards, ML probability bars,
Tranco/URLhaus badges, animated stat counters, smooth transitions.
"""
import os, json, time, html as html_mod, base64

def _esc(t):
    return html_mod.escape(str(t)) if t is not None else ""

def _risk_color(l):
    l = str(l).lower()
    return {"critical":"#ff4757","high":"#ff6348","medium":"#ffa502","low":"#ffeaa7"}.get(l,"#2ed573")

def _risk_icon(l):
    l = str(l).lower()
    return {"critical":"&#x1F6A8;","high":"&#x1F534;","medium":"&#x1F536;","low":"&#x26A0;&#xFE0F;","clean":"&#x2705;","blocked":"&#x1F6D1;"}.get(l,"&#x2753;")

def _yn(v):
    return '<span class="tag-bad">YES</span>' if v else '<span class="tag-ok">NO</span>'

def _gauge_svg(score, color):
    pct = min(score, 100) / 100
    r, circ = 54, 339.29
    offset = circ * (1 - pct)
    return f'''<svg viewBox="0 0 120 120" style="width:140px;height:140px;">
      <circle cx="60" cy="60" r="{r}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"/>
      <circle cx="60" cy="60" r="{r}" fill="none" stroke="{color}" stroke-width="10"
        stroke-dasharray="{circ}" stroke-dashoffset="{offset}" stroke-linecap="round"
        transform="rotate(-90 60 60)" style="transition:stroke-dashoffset 1.5s ease;"/>
      <text x="60" y="55" text-anchor="middle" fill="{color}" font-size="28" font-weight="800">{score}</text>
      <text x="60" y="72" text-anchor="middle" fill="#888" font-size="10">/100</text>
    </svg>'''

def _prob_bar(label, val, color):
    pct = max(0, min(val * 100, 100))
    return f'''<div style="margin:4px 0;display:flex;align-items:center;gap:8px;">
      <span style="width:80px;font-size:11px;color:#999;text-align:right;">{_esc(label)}</span>
      <div style="flex:1;height:18px;background:rgba(255,255,255,0.04);border-radius:9px;overflow:hidden;">
        <div style="width:{pct}%;height:100%;background:linear-gradient(90deg,{color},transparent);
          border-radius:9px;transition:width 1s ease;"></div>
      </div>
      <span style="width:45px;font-size:11px;color:#dfe6e9;font-weight:600;">{pct:.1f}%</span>
    </div>'''

CSS = '''
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;background:#06060f;color:#dfe6e9;line-height:1.6;min-height:100vh}
.hdr{text-align:center;padding:48px 24px 36px;background:linear-gradient(160deg,#08081e 0%,#12123a 40%,#0a0a20 100%);
  border-bottom:1px solid rgba(162,155,254,0.15);position:relative;overflow:hidden}
.hdr::before{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;
  background:radial-gradient(ellipse at 30% 50%,rgba(108,92,231,0.08),transparent 60%);pointer-events:none}
.hdr h1{font-size:32px;font-weight:800;background:linear-gradient(135deg,#a29bfe,#6c5ce7,#74b9ff);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-0.5px}
.hdr .sub{color:#666;font-size:13px;margin-top:6px;letter-spacing:0.3px}
.wrap{max-width:1140px;margin:0 auto;padding:28px 20px}
.gauge-area{display:flex;align-items:center;justify-content:center;gap:32px;
  padding:32px;margin-bottom:24px;background:rgba(255,255,255,0.015);border-radius:16px;
  border:1px solid rgba(255,255,255,0.04);backdrop-filter:blur(10px)}
.gauge-label{font-size:13px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.gauge-level{font-size:24px;font-weight:800;letter-spacing:1px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.stat{background:rgba(255,255,255,0.025);border:1px solid rgba(255,255,255,0.05);border-radius:14px;
  padding:20px 16px;text-align:center;transition:transform .2s,border-color .2s;position:relative;overflow:hidden}
.stat:hover{transform:translateY(-2px);border-color:rgba(162,155,254,0.2)}
.stat .ico{font-size:20px;margin-bottom:6px}
.stat .val{font-size:30px;font-weight:800}
.stat .lbl{font-size:10px;color:#777;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:20px;
  font-size:11px;font-weight:700;text-transform:uppercase}
.badge-tranco{background:rgba(46,213,115,0.1);color:#2ed573;border:1px solid rgba(46,213,115,0.2)}
.badge-urlhaus{background:rgba(255,71,87,0.1);color:#ff4757;border:1px solid rgba(255,71,87,0.2)}
.badge-vt{background:rgba(255,165,2,0.1);color:#ffa502;border:1px solid rgba(255,165,2,0.2)}
.ucard{background:rgba(255,255,255,0.018);border:1px solid rgba(255,255,255,0.05);
  border-radius:16px;margin-bottom:20px;overflow:hidden;transition:border-color .3s}
.ucard:hover{border-color:rgba(162,155,254,0.15)}
.ucard-hdr{display:flex;justify-content:space-between;align-items:center;padding:20px 24px;
  border-bottom:1px solid rgba(255,255,255,0.04);flex-wrap:wrap;gap:12px}
.ucard-hdr .url-text{font-size:14px;word-break:break-all;color:#b2bec3;font-family:'Fira Code',monospace}
.risk-pill{padding:6px 18px;border-radius:24px;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:0.5px}
.ucard-body{padding:20px 24px}
details{margin-bottom:10px}
summary{padding:12px 18px;border-radius:10px;cursor:pointer;font-size:14px;font-weight:600;color:#b2bec3;
  background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.04);transition:all .2s;
  list-style:none;display:flex;align-items:center;gap:8px}
summary::-webkit-details-marker{display:none}
summary::before{content:'\\25B6';font-size:9px;transition:transform .2s;color:#666}
details[open] summary::before{transform:rotate(90deg)}
summary:hover{background:rgba(255,255,255,0.04);border-color:rgba(162,155,254,0.15)}
details[open] summary{border-radius:10px 10px 0 0;background:rgba(255,255,255,0.03)}
.sec-body{padding:14px 18px;background:rgba(0,0,0,0.12);border:1px solid rgba(255,255,255,0.03);
  border-top:none;border-radius:0 0 10px 10px}
.row{display:flex;justify-content:space-between;align-items:center;padding:7px 0;
  border-bottom:1px solid rgba(255,255,255,0.025);font-size:13px}
.row:last-child{border-bottom:none}
.row .k{color:#777}.row .v{color:#dfe6e9;font-weight:500;text-align:right;max-width:60%}
.tag-bad{color:#ff4757;font-weight:700;background:rgba(255,71,87,0.1);padding:1px 8px;border-radius:8px;font-size:12px}
.tag-ok{color:#2ed573;font-size:12px}
.sig{display:flex;align-items:center;gap:10px;padding:9px 14px;margin:4px 0;
  background:rgba(255,71,87,0.05);border-left:3px solid #ff4757;border-radius:0 8px 8px 0;font-size:13px}
.sig-pts{background:rgba(255,71,87,0.15);padding:2px 10px;border-radius:12px;font-weight:800;
  font-size:11px;color:#ff4757;white-space:nowrap}
.footer{text-align:center;padding:28px;color:#444;font-size:11px;border-top:1px solid rgba(255,255,255,0.04);margin-top:32px}
@media(max-width:768px){.stats{grid-template-columns:1fr 1fr}.gauge-area{flex-direction:column}}
'''

def _row(k, v, hi=False):
    vc = 'class="v"' if not hi else 'class="v" style="color:#ff4757;font-weight:700"'
    return f'<div class="row"><span class="k">{_esc(k)}</span><span {vc}>{v}</span></div>'

def _sec(title, icon, body, opened=True):
    o = "open" if opened else ""
    return f'<details {o}><summary>{icon} {_esc(title)}</summary><div class="sec-body">{body}</div></details>'

def generate_url_html_report(url_results, output_path, email_meta=None):
    if not isinstance(url_results, list):
        url_results = [url_results]
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    n = len(url_results)
    crit = sum(1 for r in url_results if str(r.get("risk_level","")).lower()=="critical")
    high = sum(1 for r in url_results if str(r.get("risk_level","")).lower()=="high")
    med = sum(1 for r in url_results if str(r.get("risk_level","")).lower()=="medium")
    clean = sum(1 for r in url_results if str(r.get("risk_level","")).lower() in ("clean","low"))
    vt_hits = sum(1 for r in url_results if r.get("vt_malicious",0)>0)
    tranco = sum(1 for r in url_results if r.get("tranco_whitelisted"))
    urlhaus = sum(1 for r in url_results if r.get("urlhaus_hit"))
    mx = max((r.get("risk_score",0) for r in url_results), default=0)
    wl = "critical" if crit else ("high" if high else ("medium" if med else "clean"))
    wc = _risk_color(wl)

    H = [f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>URL Threat Analysis - KNOWHOW</title><style>{CSS}</style></head><body>
<div class="hdr"><h1>&#x1F6E1; KNOWHOW Threat Intelligence</h1>
<div class="sub">URL Analysis Report &bull; {_esc(ts)} &bull; {n} URL(s) Scanned</div></div>
<div class="wrap">''']

    # Email banner
    if email_meta:
        H.append(f'''<div style="background:rgba(108,92,231,0.06);border:1px solid rgba(108,92,231,0.2);
          border-radius:14px;padding:18px 22px;margin-bottom:20px;">
          <div style="font-weight:700;color:#a29bfe;margin-bottom:8px;">&#x1F4E7; Source Email</div>
          {_row("From",_esc(email_meta.get("from","N/A")))}
          {_row("Subject",_esc(email_meta.get("subject","N/A")))}
          {_row("Date",_esc(email_meta.get("date","N/A")))}</div>''')

    # Gauge + verdict
    H.append(f'''<div class="gauge-area">
      <div style="text-align:center">{_gauge_svg(mx, wc)}
        <div class="gauge-label">Threat Score</div></div>
      <div style="text-align:center">
        <div class="gauge-level" style="color:{wc}">{_risk_icon(wl)} {wl.upper()}</div>
        <div style="color:#666;font-size:12px;margin-top:4px;">Overall Assessment</div>
        <div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap;justify-content:center;">''')
    if tranco: H.append(f'<span class="badge badge-tranco">&#x2705; Tranco Whitelisted: {tranco}</span>')
    if urlhaus: H.append(f'<span class="badge badge-urlhaus">&#x26A0; URLhaus Hits: {urlhaus}</span>')
    if vt_hits: H.append(f'<span class="badge badge-vt">&#x1F6E1; VT Flagged: {vt_hits}</span>')
    H.append('</div></div></div>')

    # Stats grid
    H.append('<div class="stats">')
    for lbl,val,ico,clr in [("URLs Analyzed",n,"&#x1F517;","#a29bfe"),("Critical",crit,"&#x1F6A8;","#ff4757"),
      ("High Risk",high,"&#x1F534;","#ff6348"),("Medium",med,"&#x1F536;","#ffa502"),("Clean / Low",clean,"&#x2705;","#2ed573"),
      ("VT Flagged",vt_hits,"&#x1F6E1;","#ffa502"),("URLhaus",urlhaus,"&#x2620;","#ff4757"),("Tranco WL",tranco,"&#x1F30D;","#2ed573")]:
        H.append(f'<div class="stat"><div class="ico">{ico}</div><div class="val" style="color:{clr}">{val}</div><div class="lbl">{_esc(lbl)}</div></div>')
    H.append('</div>')

    # URL cards
    for idx, r in enumerate(url_results, 1):
        url = r.get("url","N/A"); rl = str(r.get("risk_level","unknown")).lower()
        rs = r.get("risk_score",0); rc = _risk_color(rl)
        H.append(f'<div class="ucard"><div class="ucard-hdr"><div><span style="font-size:11px;color:#666;">URL #{idx}</span><br><span class="url-text">{_esc(url)}</span></div>')
        H.append(f'<span class="risk-pill" style="background:rgba({",".join(str(int(rc.lstrip("#")[i:i+2],16)) for i in (0,2,4))},0.12);color:{rc};border:1px solid {rc};">{rl.upper()} &mdash; {rs}/100</span></div>')

        if r.get("ssrf_blocked"):
            H.append('<div style="padding:20px;text-align:center;color:#ff4757;">&#x1F6D1; BLOCKED by SSRF Guard</div></div>')
            continue

        H.append('<div class="ucard-body">')

        # Inline badges
        badges = ''
        if r.get("tranco_whitelisted"): badges += '<span class="badge badge-tranco">&#x1F30D; Tranco Top 1M</span> '
        if r.get("urlhaus_hit"): badges += f'<span class="badge badge-urlhaus">&#x2620; URLhaus: {_esc(r.get("urlhaus_match","hit"))}</span> '
        if r.get("vt_malicious",0)>0: badges += f'<span class="badge badge-vt">&#x1F6E1; VT: {r.get("vt_malicious",0)} engines</span> '
        if badges: H.append(f'<div style="margin-bottom:14px;display:flex;gap:6px;flex-wrap:wrap;">{badges}</div>')

        # VT Reputation
        vt = ''
        vt += _row("Malicious Engines", _esc(r.get("vt_malicious","N/A")), r.get("vt_malicious",0)>0)
        vt += _row("Suspicious Engines", _esc(r.get("vt_suspicious","N/A")))
        vt += _row("Harmless Engines", _esc(r.get("vt_harmless","N/A")))
        vt += _row("Undetected Engines", _esc(r.get("vt_undetected","N/A")))
        H.append(_sec("VirusTotal Reputation","&#x1F6E1;",vt))

        # Domain Intel
        d = ''
        d += _row("Registered Domain", _esc(r.get("domain","N/A")))
        d += _row("Domain Age (days)", _esc(r.get("domain_age_days","N/A")))
        d += _row("WHOIS Registrar", _esc(str(r.get("whois_registrar","N/A"))[:50]))
        d += _row("Newly Registered", _yn(r.get("newly_registered_domain",0)))
        d += _row("WHOIS Privacy", _yn(r.get("whois_privacy",0)))
        d += _row("Suspicious TLD", _yn(r.get("phish_suspicious_tld",0)))
        d += _row("DNS A Records", _esc(r.get("dns_ip_count","N/A")))
        d += _row("DNS Has MX", _yn(r.get("dns_has_mx",0)))
        d += _row("Fast Flux", _yn(r.get("fast_flux_detected",0)))
        tb = r.get("typosquat_target_brand","")
        if tb: d += _row("Typosquatting Target", f'<span class="tag-bad">{_esc(tb)}</span>', True)
        H.append(_sec("Domain Intelligence","&#x1F310;",d))

        # Static
        s = ''
        s += _row("URL Length", _esc(r.get("url_len","N/A")))
        s += _row("IP in Hostname", _yn(r.get("having_ip_address",0)))
        s += _row("URL Shortener", _yn(r.get("shortening_service",0)))
        s += _row("Entropy", _esc(r.get("url_entropy","N/A")))
        s += _row("Suspicious Keywords", _esc(r.get("suspicious_keyword_count","N/A")))
        s += _row("Path Depth", _esc(r.get("path_depth","N/A")))
        s += _row("Query Params", _esc(r.get("query_param_count","N/A")))
        s += _row("Subdomains", _esc(r.get("num_subdomains","N/A")))
        H.append(_sec("Static URL Analysis","&#x1F52C;",s,False))

        # Redirects
        rd = ''
        rd += _row("Redirect Hops", _esc(r.get("phish_redirect_count","N/A")))
        rd += _row("Final URL", _esc(str(r.get("final_url","N/A"))[:100]))
        rd += _row("Cross-domain", _esc(r.get("phish_cross_domain_redirects","N/A")))
        rd += _row("Open Redirect", _yn(r.get("phish_open_redirect_abuse",0)))
        rd += _row("Redirect Loop", _yn(r.get("phish_redirect_loop",0)))
        vg = r.get("visual_graph","")
        if vg: rd += f'<pre style="margin-top:10px;padding:10px;background:rgba(0,0,0,0.25);border-radius:8px;font-size:11px;overflow-x:auto;color:#a29bfe;">{_esc(vg)}</pre>'
        H.append(_sec("Redirect Chain","&#x1F500;",rd,False))

        # Dynamic
        dy = ''
        dy += _row("HTTP Status", _esc(r.get("web_http_status","N/A")))
        dy += _row("Page Live", _yn(r.get("web_is_live",0)))
        dy += _row("SSL Valid", _yn(r.get("web_ssl_valid",0)))
        dy += _row("Forms", _esc(r.get("web_forms_count","N/A")))
        dy += _row("Password Fields", _esc(r.get("web_password_fields","N/A")), r.get("web_password_fields",0)>0)
        dy += _row("Login Page", _yn(r.get("web_has_login",0)))
        dy += _row("Hidden Iframes", _esc(r.get("web_hidden_iframes","N/A")), r.get("web_hidden_iframes",0)>0)
        dy += _row("Suspicious JS APIs", _esc(r.get("web_suspicious_js_apis","N/A")))
        H.append(_sec("Dynamic Analysis","&#x1F916;",dy,False))

        # Anomaly
        an = ''
        asc = r.get("anomaly_score",0.0); ap = r.get("anomaly_percentile",0.0); ia = r.get("is_anomaly",0)
        an += _row("Anomaly Score", f"{asc:.4f}")
        an += _row("Percentile", f"{ap:.1f}%")
        an += _row("Verdict", '<span class="tag-bad">&#x26A0; ANOMALOUS</span>' if ia else '<span class="tag-ok">&#x2705; Normal</span>')
        H.append(_sec("Anomaly Detection","&#x1F52E;",an,False))

        # ML with probability bars
        ml = ''
        mp = r.get("ml_prediction","unknown"); mc = r.get("ml_confidence",0.0)
        mpr = r.get("ml_probabilities",{})
        pc = "#ff4757" if mp.lower() in ("phishing","malware","defacement") else "#2ed573"
        ml += f'<div style="text-align:center;padding:12px 0;"><span style="font-size:22px;font-weight:800;color:{pc};">{_esc(mp.upper())}</span><br><span style="color:#888;font-size:12px;">Confidence: {mc:.1%}</span></div>'
        if mpr:
            colors = {"benign":"#2ed573","defacement":"#ffa502","phishing":"#ff4757","malware":"#e84393"}
            ml += '<div style="margin-top:8px;">'
            for cls, prob in mpr.items():
                ml += _prob_bar(cls.title(), prob, colors.get(cls,"#a29bfe"))
            ml += '</div>'
        H.append(_sec("ML Classifier (XGBoost)","&#x1F9E0;",ml))

        # Risk signals
        sigs = r.get("risk_signals",[])
        if sigs:
            sc = ''
            for sig in sigs:
                if isinstance(sig,(list,tuple)) and len(sig)>=2: pts,reason = sig[0],sig[1]
                elif isinstance(sig,dict): pts,reason = sig.get("points",0),sig.get("reason","")
                else: continue
                sc += f'<div class="sig"><span class="sig-pts">+{pts}</span><span>{_esc(reason)}</span></div>'
            H.append(_sec(f"Risk Signals ({len(sigs)})","&#x1F3AF;",sc))

        # Screenshot
        ss = r.get("web_screenshot_path","")
        if ss and os.path.isfile(ss):
            with open(ss,"rb") as f: b64 = base64.b64encode(f.read()).decode()
            H.append(_sec("Screenshot","&#x1F4F8;",f'<img src="data:image/png;base64,{b64}" style="max-width:100%;border-radius:8px;border:1px solid rgba(255,255,255,0.1);" alt="Screenshot">'))

        # Download detection
        if r.get("file_download_detected") or r.get("dl_filename"):
            dl = ''
            dl += _row("Download Detected", _yn(r.get("file_download_detected",0)))
            if r.get("dl_filename"):
                dl += _row("Filename", _esc(r.get("dl_filename","")))
                dl += _row("SHA256", f'<code style="font-size:10px;">{_esc(r.get("dl_sha256",""))}</code>')
                dl += _row("Executable", _yn(r.get("dl_is_executable",0)))
            H.append(_sec("Download Detection","&#x2B07;",dl))

        H.append('</div></div>')  # close ucard-body, ucard

    # Footer
    H.append(f'<div class="footer">KNOWHOW Threat Intelligence Platform v4.0 &bull; {_esc(ts)}</div></div></body></html>')

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path,"w",encoding="utf-8") as f: f.write("\n".join(H))
    print(f"[URL-HTML] Dashboard saved: {output_path}")
    return output_path
