# Phishing URL Analysis Pipeline — Full Summary

> **Project Path:** `c:\Users\hadyh\Desktop\URLLLL`  
> **Python venv:** `.venv\Scripts\python.exe`  
> **Last Updated:** 2026-05-10

---

## 1. Architecture Overview

A **hybrid ML + rule-based** phishing detection pipeline that accepts URLs (standalone, from email text, HTML, or `.eml` files), runs 13 analysis stages, and produces a composite risk score (0–100).

```
Input (URL / Email / HTML / .eml file)
   │
   ▼
┌─────────────────────────────────────────────────┐
│  main.py — Interactive CLI                      │
│  Auto-detects input type, asks Fast/Full mode   │
│  Calls dashboard.py → pipeline.py               │
└─────────────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────────────┐
│  pipeline.py — 13-Stage Orchestrator            │
│                                                 │
│  1. SSRF Guard (blocks internal IPs)            │
│  2. URL Normalization                           │
│  3. VirusTotal Reputation (needs API key)       │
│  4. Domain Intelligence (WHOIS + DNS + typo)    │
│  5. Static/Lexical URL Analysis (41 features)   │
│  6. Redirect Graph Analysis                     │
│  7-10. Dynamic Analysis + API Monitor           │
│        (Playwright headless browser)            │
│  11. Anomaly Detection (Isolation Forest)       │
│  12. ML Classifier (XGBoost, 4-class)           │
│  13. Composite Risk Scorer (multi-signal)       │
└─────────────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────────────┐
│  Output: Risk Score 0–100                       │
│  Levels: clean / low / medium / high / critical │
│  + detailed signals explaining the score        │
│  + full JSON feature report                     │
└─────────────────────────────────────────────────┘
```

---

## 2. File Structure

### Entry Points
| File | Purpose |
|------|---------|
| `main.py` | Interactive CLI — auto-detects URL/email/HTML/.eml input, asks fast/full mode |
| `dashboard.py` | Terminal dashboard — prints formatted analysis report with box-drawing characters |

### Pipeline Package (`phishing_pipeline/`)
| File | Stage | Purpose |
|------|-------|---------|
| `pipeline.py` | Orchestrator | Chains all 13 stages, merges results into flat dict |
| `ssrf_guard.py` | Stage 1 | Blocks internal/private IPs (192.168.x.x, 10.x.x.x, etc.) |
| `url_normalizer.py` | Stage 2 | Strips tracking params, normalizes scheme/case |
| `reputation.py` | Stage 3 | VirusTotal URL scan — submit URL, poll results |
| `domain_intel.py` | Stage 4 | WHOIS age, registrar, DNS records, MX, fast-flux, typosquatting detection |
| `static_analysis.py` | Stage 5 | 60+ lexical URL features — character counts, entropy, brand detection, keywords |
| `redirect_graph.py` | Stage 6 | Follow redirect chain, count hops, detect cross-domain/loop/open-redirect |
| `dynamic_analysis.py` | Stage 7-10 | Playwright browser: DOM analysis, login detection, hidden iframes, JS APIs, screenshots |
| `api_monitor.py` | Stage 7-10 | CDP-based network monitor: XHR/POST tracking, WebSocket, credential exfiltration |
| `defacement_detector.py` | Stage 7-10 | Detects hacked/defaced pages via keyword analysis |
| `download_analyzer.py` | Stage 7-10 | Detects executable download links (.exe, .msi, .bat, etc.) |
| `anomaly_detector.py` | Stage 11 | Isolation Forest unsupervised model — trained on pipeline feature distribution |
| `ml_model.py` | Stage 12 | XGBoost 4-class classifier (benign/phishing/malware/defacement) |
| `risk_scorer.py` | Stage 13 | Composite scoring engine — 9 signal categories, corroboration gate for ML |
| `feature_mapper.py` | Utility | Maps pipeline feature keys to CSV/model column names |
| `url_extractor.py` | Utility | Regex-based URL extraction from text/HTML (defanged, base64, bare URLs) |
| `href_mismatch.py` | Utility | Detects display text ≠ href URL mismatches in HTML |
| `config.py` | Config | API keys, timeouts, TLD lists, shortener domains, download extensions |
| `logger.py` | Utility | Centralized logging setup |

### Models & Data
| Path | Description |
|------|-------------|
| `phishing_pipeline/models/xgb_classifier.pkl` | Trained XGBoost model (10.9 MB) |
| `Full Dataset/final_dataset_with_all_features_v3.1.csv` | Training dataset (651K samples) |

---

## 3. ML Model Details

### Architecture
- **Algorithm:** XGBoost multi-class classifier (`multi:softprob`)
- **Classes:** benign, phishing, malware, defacement (4 classes)
- **Features:** 41 URL-level lexical/structural features (NO browser features)
- **Training data:** 651,191 samples (520,952 train / 130,239 test split)
- **Class weighting:** Sqrt-balanced (~2.1x for minority classes)

### Performance
| Metric | Value |
|--------|-------|
| Overall accuracy | 86.4% |
| Phishing precision | 62.5% |
| Phishing recall | 58.3% |
| Phishing F1 | 60.3% |

### Feature Set (41 features)
```
Character counts (15):
  url_len, @, ?, -, =, ., #, %, +, $, !, *, ,, digits, letters

Structural flags (2):
  Shortining_Service, having_ip_address

Phishing keywords (4):
  phish_urgency_words, phish_security_words,
  phish_brand_mentions, phish_brand_hijack

Structural risk (4):
  phish_multiple_subdomains, phish_long_path,
  phish_many_params, phish_suspicious_tld

Advanced structural (12):
  phish_adv_exact_brand_match, phish_adv_brand_in_subdomain,
  phish_adv_brand_in_path, phish_adv_hyphen_count,
  phish_adv_number_count, phish_adv_suspicious_tld,
  phish_adv_long_domain, phish_adv_many_subdomains,
  phish_adv_encoded_chars, phish_adv_path_keywords,
  phish_adv_has_redirect, phish_adv_many_params

Path/extension (4):
  path_has_hacked_terms, suspicious_extension,
  path_underscore_count, is_gov_edu
```

### Dataset Artifact Fixes (Train/Inference Parity)
Three features were **removed from ML** because they cause train/inference mismatch:

| Feature | Issue | Action |
|---------|-------|--------|
| `abnormal_url` | 91.7% of benign URLs have it in dataset | Excluded from model |
| `https` | 99.5% of dataset URLs lack scheme prefix but inference always has `https://` | Excluded from model |
| `//` | Same scheme-prefix artifact as `https` | Excluded from model |

**Scheme stripping:** Character counts (`url_len`, `digits`, `letters`) are computed on the URL **after stripping `http://` or `https://`** to match how the dataset was built.

---

## 4. Risk Scoring Engine

### Score Levels
| Score Range | Level | Meaning |
|-------------|-------|---------|
| 0–4 | clean | No risk signals |
| 5–14 | low | Minor signals, likely benign |
| 15–34 | medium | Warrants investigation |
| 35–59 | high | Likely malicious |
| 60–100 | critical | Strong malicious indicators |

### Signal Categories (9 scoring functions)

#### 1. `_score_reputation` — VirusTotal
| Condition | Points |
|-----------|--------|
| VT ≥5 engines malicious | +30 |
| VT ≥1 engines malicious | +20 |
| VT ≥3 engines suspicious | +10 |
| VT ≥1 engine suspicious | +5 |

#### 2. `_score_domain` — Domain Intelligence
| Condition | Points |
|-----------|--------|
| Domain age < 7 days | +20 |
| Domain age < 30 days | +12 |
| Domain age < 90 days | +5 |
| Suspicious TLD (.tk, .ml, etc.) | +8 |
| Multiple subdomains | +5 |
| Long domain name | +4 |
| Fast-flux DNS | +15 |
| Typosquat distance ≤ 1 | +18 |
| Typosquat distance = 2 | +10 |

**Removed signals:** WHOIS privacy (too common on legit sites), typosquat distance 3 (too many false matches like `go→aol`).

#### 3. `_score_static` — URL Lexical Features
| Condition | Points |
|-----------|--------|
| IP address as hostname | +12 |
| URL shortener | +8 |
| `@` in URL | +10 |
| ≥4 suspicious keywords | +10 |
| ≥2 suspicious keywords | +4 |
| URL entropy > 4.8 | +6 |
| URL length > 150 | +5 |
| Encoded non-ASCII chars | +8 |

**Removed signals:** `abnormal_url` (triggers on too many benign sites). Keyword threshold raised from 1→2 minimum. Entropy threshold raised from 4.5→4.8.

#### 4. `_score_redirects` — Redirect Behavior
| Condition | Points |
|-----------|--------|
| ≥5 redirect hops | +15 |
| ≥3 redirect hops | +8 |
| ≥2 cross-domain redirects | +10 |
| Open redirect abuse | +15 |
| Redirect loop | +12 |
| JS redirect | +8 |
| Meta refresh redirect | +6 |

#### 5. `_score_dynamic` — Browser/DOM Analysis
| Condition | Points |
|-----------|--------|
| Password field WITHOUT SSL | +18 |
| Password field on suspicious TLD | +12 |
| Login form + VT malicious | +15 |
| ≥5 hidden form inputs | +6 |
| External request ratio > 85% | +8 |
| Defacement detected | +20 |
| Executable download link | +6 |
| ≥3 suspicious JS APIs | +8 |

**Tuned:** External ratio threshold raised from 70%→85% (CDN-heavy sites exceed 70%). JS APIs reduced to only truly suspicious ones (removed localStorage, XMLHttpRequest, atob, FormData — used by every modern site). Download extensions restricted to executables only (removed .pdf, .doc, .js).

#### 6. `_score_anomaly` — Isolation Forest
| Condition | Points |
|-----------|--------|
| Anomaly percentile ≥ 90% | +8 |
| Anomaly percentile ≥ 80% | +4 |
| Below 80% | suppressed |

**Tuned:** Threshold raised from any `is_anomaly=1` to 80th+ percentile. Many benign sites were triggering at 50-65%.

#### 7. `_score_href_mismatch` — Display vs Href
| Condition | Points |
|-----------|--------|
| ≥1 display-text ≠ href URL | +20 |

#### 8. `_score_ml` — XGBoost Classifier (3-tier corroboration gate)
The ML prediction is NOT trusted blindly. It uses a **corroboration gate**:

**Tier 1 — Corroborated (rule signals present):**
| ML Confidence | Points |
|---------------|--------|
| ≥ 90% | +20 |
| ≥ 70% | +12 |
| ≥ 55% | +6 |

**Tier 2 — Uncorroborated but very high confidence:**
| ML Confidence | Points |
|---------------|--------|
| ≥ 90% | +8 |

**Tier 3 — Uncorroborated and < 90%:** → **Suppressed entirely (0 pts)**

Corroboration triggers (at least one must be true):
- Suspicious TLD
- Typosquat distance ≤ 2
- Newly registered domain (< 7 days)
- VirusTotal malicious > 0
- IP address in hostname
- Password fields in DOM
- ≥3 suspicious keywords
- Display-vs-href mismatch
- Brand hijacking detected
- Many subdomains (4+)

**Design rationale:** google.com gets ML=phishing at 96% confidence (dataset artifact), but the corroboration gate suppresses it to 8pts (uncorroborated tier) → final score stays 8/100 (LOW) instead of falsely escalating.

#### 9. `_score_api_behavior` — Network API Monitoring
| Condition | Points |
|-----------|--------|
| Credential data in POST body | +25 |
| ≥3 external POST requests | +10 |
| ≥2 suspicious API patterns | +8 |
| WebSocket + 3+ target domains | +6 |

---

## 5. Suspicious JS API List (Dynamic Analysis)

Only **genuinely suspicious** APIs are flagged (common ones removed to prevent false positives):

```python
# FLAGGED (truly suspicious):
eval(), unescape(), document.cookie,
navigator.sendBeacon, document.execCommand,
postMessage(), window.opener

# NOT FLAGGED (too common on legitimate sites):
localStorage, sessionStorage, XMLHttpRequest,
atob(), FormData
```

---

## 6. Download Detection

Only **executable extensions** trigger the download flag:
```
.exe, .msi, .apk, .dmg, .pkg,
.scr, .bat, .cmd, .vbs, .ps1,
.deb, .run
```

**NOT flagged:** `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.js`, `.zip`, `.rar`, `.7z`, `.tar`, `.gz` — these exist on virtually every legitimate website.

---

## 7. URL Extractor Capabilities

`url_extractor.py` supports:
1. **Full URLs** with scheme: `https://example.com/path`
2. **Bare URLs** without scheme: `example.com/path` → auto-prepends `https://`
3. **HTML content**: `<a href="...">`, `<form action="...">`, `<img src="...">`, `<iframe src="...">`
4. **Defanged URLs**: `hxxp://evil[.]com` → `http://evil.com`
5. **Base64-encoded URLs**: `aHR0cDovL...` → decoded URL

---

## 8. Validated Test Results (2026-05-09)

### Benign URL Batch (20 URLs from dataset, fast mode)
- **False positives at score ≥ 15:** 1/20 (5%)
- **Maximum benign score:** 10/100 (espn.go.com — typosquat dist=2 false match on "aol")

### Phishing URL Batch (15 URLs from dataset, fast mode)
- **Detected at score ≥ 5:** 10/15 (67%)
- **Missed (false negatives):** 5/15 — all are compromised legitimate domains undetectable without VirusTotal or dynamic browser analysis

### Key Validation Points
| URL | Expected | Actual | Notes |
|-----|----------|--------|-------|
| google.com | CLEAN | 0/100 CLEAN ✅ | ML says phishing@96% but corroboration gate suppresses |
| paypal-secure-login.suspicious-site.tk | HIGH | 54/100 HIGH ✅ | 5 signals: TLD + typosquat + keywords + entropy + ML |

---

## 9. Configuration

### Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `VT_API_KEY` | No (but recommended) | VirusTotal API key. Free tier: 4 req/min, 500/day |

### Key Config (`phishing_pipeline/config.py`)
| Setting | Value |
|---------|-------|
| `REQUEST_TIMEOUT` | 10 seconds |
| `VT_POLL_WAIT` | 15 seconds |
| `PLAYWRIGHT_TIMEOUT` | 20,000 ms |
| `SCREENSHOTS_DIR` | `./screenshots/` |

---

## 10. Dependencies

```
xgboost>=3.2.0
scikit-learn
pandas
numpy
tldextract
python-whois
requests
beautifulsoup4
playwright          # + `playwright install chromium`
```

---

## 11. Commands

```bash
# Run interactive CLI
.venv\Scripts\python.exe main.py

# Analyze a URL directly
.venv\Scripts\python.exe main.py "https://example.com"

# Retrain the ML model
.venv\Scripts\python.exe -m phishing_pipeline.ml_model train

# Programmatic usage
from phishing_pipeline.pipeline import analyze_url
result = analyze_url("https://example.com", skip_dynamic=True)
```

---

## 12. Known Limitations

1. **VirusTotal disabled by default** — needs API key via `$env:VT_API_KEY`. Without it, compromised-but-legitimate-looking domains slip through.
2. **ML false positives on popular domains** — google.com, linkedin.com get ML=phishing at high confidence due to dataset distribution bias. Mitigated by the corroboration gate (only 0-8pts uncorroborated).
3. **Static-only mode misses credential harvesting** — phishing pages hosted on clean-looking domains can only be caught with dynamic analysis (browser detects login forms, password fields).
4. **Dataset has scheme-prefix artifacts** — training URLs lack `http://`/`https://` prefix, so character counts are computed on stripped URLs to maintain parity.
5. **Typosquat matching is approximate** — Levenshtein distance-based, can produce false matches on short domain names. Restricted to distance ≤ 2 to reduce false positives.

---

## 13. Design Decisions Log

| Decision | Rationale |
|----------|-----------|
| ML is ONE signal, not the oracle | Prevents dataset bias from dominating. ML contributes 6-20pts max out of 100 |
| 3-tier ML corroboration gate | Balances precision (no FP on google.com) with recall (95%+ ML still scores 8pts) |
| Removed `abnormal_url` from scoring | 91.7% of benign URLs have it — noise signal |
| Removed `https`, `//` from ML features | Dataset artifact: training URLs lack scheme, inference URLs always have it |
| Sqrt-balanced class weights (not full balanced) | Full balanced 4.5x overfit minority classes → 46% precision. Sqrt 2.1x → 62.5% |
| Download extensions restricted to executables | `.pdf`, `.doc`, `.js` on every website → massive false positives |
| Suspicious JS APIs narrowed to 7 | `localStorage`, `XMLHttpRequest` on every modern website → false positives |
| Entropy threshold raised to 4.8 | Long benign URLs (news articles, Wikipedia) regularly hit 4.5-4.6 |
| WHOIS privacy not scored | Too many legitimate sites use privacy/proxy registration |
| Typosquat distance 3 removed | False matches: `go→aol`, `sheknows→ups`, `192→aol` |
| External request ratio raised to 85% | CDN-heavy news sites exceed 70% external requests |
| Anomaly threshold raised to 80th percentile | Benign sites regularly triggered at 50-65% percentile |
