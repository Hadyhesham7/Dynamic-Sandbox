"""
feature_mapper.py — Bridge between pipeline output and ML model features.

Maps the pipeline's output dict keys to the CSV dataset column names used
during training. Ensures consistent feature ordering and handles missing
values.

Dataset CSV columns (v3.1):
    url, type, url_len, @, ?, -, =, ., digits, letters, domain,
    abnormal_url, Shortining_Service, having_ip_address, web_http_status,
    web_is_live, web_ext_ratio, web_unique_domains, web_forms_count,
    web_password_fields, web_hidden_inputs, web_has_login, web_ssl_valid,
    phish_multiple_subdomains, phish_long_path, phish_many_params,
    phish_suspicious_tld, phish_adv_hyphen_count, phish_adv_number_count,
    phish_adv_long_domain, phish_redirect_count, is_gov_edu,
    file_download_detected
"""

from __future__ import annotations

from .logger import get_logger

log = get_logger("feature_mapper")

# ─────────────────────────────────────────────────────────────────────────────
# Mapping: pipeline key → CSV column name
# ─────────────────────────────────────────────────────────────────────────────

_PIPELINE_TO_CSV: dict[str, str] = {
    "url_len":                   "url_len",
    "at_sign":                   "@",
    "question_mark":             "?",
    "hyphen":                    "-",
    "equals":                    "=",
    "dots":                      ".",
    "digits":                    "digits",
    "letters":                   "letters",
    "abnormal_url":              "abnormal_url",
    "shortening_service":        "Shortining_Service",
    "having_ip_address":         "having_ip_address",
    "web_http_status":           "web_http_status",
    "web_is_live":               "web_is_live",
    "web_ext_ratio":             "web_ext_ratio",
    "web_unique_domains":        "web_unique_domains",
    "web_forms_count":           "web_forms_count",
    "web_password_fields":       "web_password_fields",
    "web_hidden_inputs":         "web_hidden_inputs",
    "web_has_login":             "web_has_login",
    "web_ssl_valid":             "web_ssl_valid",
    "phish_multiple_subdomains": "phish_multiple_subdomains",
    "path_depth":                "phish_long_path",
    "query_param_count":         "phish_many_params",
    "phish_suspicious_tld":      "phish_suspicious_tld",
    "phish_adv_hyphen_count":    "phish_adv_hyphen_count",
    "phish_adv_number_count":    "phish_adv_number_count",
    "phish_adv_long_domain":     "phish_adv_long_domain",
    "phish_redirect_count":      "phish_redirect_count",
    "is_gov_edu":                "is_gov_edu",
    "file_download_detected":    "file_download_detected",
}

# Ordered list of CSV feature columns used for ML (excludes 'url', 'type', 'domain')
FEATURE_COLUMNS: list[str] = [
    "url_len", "@", "?", "-", "=", ".", "digits", "letters",
    "abnormal_url", "Shortining_Service", "having_ip_address",
    "web_http_status", "web_is_live", "web_ext_ratio", "web_unique_domains",
    "web_forms_count", "web_password_fields", "web_hidden_inputs",
    "web_has_login", "web_ssl_valid",
    "phish_multiple_subdomains", "phish_long_path", "phish_many_params",
    "phish_suspicious_tld", "phish_adv_hyphen_count", "phish_adv_number_count",
    "phish_adv_long_domain", "phish_redirect_count", "is_gov_edu",
    "file_download_detected",
]

# Reverse mapping: CSV column → pipeline key
_CSV_TO_PIPELINE: dict[str, str] = {v: k for k, v in _PIPELINE_TO_CSV.items()}


def pipeline_to_feature_vector(report: dict) -> list[float]:
    """
    Convert a pipeline report dict into an ordered feature vector
    matching the CSV training schema.

    Args:
        report: The merged dict from analyze_url().

    Returns:
        List of floats in FEATURE_COLUMNS order.
        Missing features default to 0.
    """
    vector: list[float] = []

    for csv_col in FEATURE_COLUMNS:
        pipeline_key = _CSV_TO_PIPELINE.get(csv_col, csv_col)
        val = report.get(pipeline_key, 0)

        # Ensure numeric
        try:
            val = float(val)
        except (ValueError, TypeError):
            val = 0.0

        vector.append(val)

    log.debug("Feature vector (%d features): %s", len(vector), vector)
    return vector


def pipeline_to_csv_row(report: dict) -> dict:
    """
    Convert pipeline output to a dict with CSV-compatible column names.
    Useful for appending pipeline results to the training dataset.

    Args:
        report: The merged dict from analyze_url().

    Returns:
        Dict with CSV column names as keys.
    """
    row: dict = {}
    row["url"] = report.get("url", "")
    row["domain"] = report.get("domain", "")

    for pipeline_key, csv_col in _PIPELINE_TO_CSV.items():
        val = report.get(pipeline_key, 0)
        try:
            row[csv_col] = float(val)
        except (ValueError, TypeError):
            row[csv_col] = 0

    return row
