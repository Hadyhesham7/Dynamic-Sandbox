"""
ml_model.py — XGBoost classifier for URL phishing detection.

Design principles:
  1. ML receives ONLY URL-level lexical/structural features (~40 features)
  2. Dynamic/behavioral features (web_*, downloads, redirects) stay in risk_scorer.py
  3. ML is ONE signal in the risk scorer — not the sole decision maker

Usage:
    Training:  python -m phishing_pipeline.ml_model train
    Inference: from phishing_pipeline.ml_model import predict
"""

from __future__ import annotations

import os
import pickle
import sys
from pathlib import Path

import numpy as np

from .logger import get_logger

log = get_logger("ml_model")

_MODEL_DIR = Path(__file__).parent / "models"
_MODEL_PATH = _MODEL_DIR / "xgb_classifier.pkl"

# ─────────────────────────────────────────────────────────────────────────────
# Feature definitions — STRICT separation
# ─────────────────────────────────────────────────────────────────────────────

# These are the ONLY features the ML model sees.
# They are ALL derivable from the URL string alone — no browser needed.
ML_FEATURE_COLUMNS: list[str] = [
    # Character counts
    "url_len", "@", "?", "-", "=", ".", "#", "%", "+", "$", "!", "*", ",",
    "digits", "letters",
    # Structural flags
    # NOTE: abnormal_url EXCLUDED — 91.7% of benign URLs have it = noise
    # NOTE: https EXCLUDED — 99.5% of dataset benign URLs lack scheme prefix,
    #   but inference URLs always have https://, causing train/inference mismatch
    # NOTE: // EXCLUDED — same scheme-prefix artifact as https
    "Shortining_Service", "having_ip_address",
    # Phishing linguistic signals
    "phish_urgency_words", "phish_security_words",
    "phish_brand_mentions", "phish_brand_hijack",
    # Structural risk indicators
    "phish_multiple_subdomains", "phish_long_path", "phish_many_params",
    "phish_suspicious_tld",
    # Advanced structural features
    "phish_adv_exact_brand_match", "phish_adv_brand_in_subdomain",
    "phish_adv_brand_in_path", "phish_adv_hyphen_count",
    "phish_adv_number_count", "phish_adv_suspicious_tld",
    "phish_adv_long_domain", "phish_adv_many_subdomains",
    "phish_adv_encoded_chars", "phish_adv_path_keywords",
    "phish_adv_has_redirect", "phish_adv_many_params",
    # Path/extension features
    "path_has_hacked_terms", "suspicious_extension",
    "path_underscore_count", "is_gov_edu",
]

# These features are EXCLUDED from ML — they belong to the rule engine
# because they are deterministic, behavioral, or require a browser.
RULE_ONLY_FEATURES: list[str] = [
    "web_http_status",       # deterministic HTTP response
    "web_is_live",           # binary liveness check
    "web_ext_ratio",         # behavioral network telemetry
    "web_unique_domains",    # behavioral network count
    "web_favicon",           # static DOM check
    "web_csp",               # security header — deterministic
    "web_xframe",            # security header — deterministic
    "web_hsts",              # security header — deterministic
    "web_xcontent",          # security header — deterministic
    "web_security_score",    # composite of security headers
    "web_forms_count",       # DOM count — deterministic
    "web_password_fields",   # DOM count — deterministic
    "web_hidden_inputs",     # DOM count — deterministic
    "web_has_login",         # DOM pattern — deterministic
    "web_ssl_valid",         # certificate check — deterministic
]

# Label mapping: type string → integer
LABEL_MAP = {"benign": 0, "defacement": 1, "phishing": 2, "malware": 3}
LABEL_NAMES = ["benign", "defacement", "phishing", "malware"]

# Pipeline key → dataset column name mapping
# Pipeline produces keys like 'at_sign', but dataset CSV has '@'
_PIPELINE_TO_CSV: dict[str, str] = {
    "at_sign": "@",
    "question_mark": "?",
    "hyphen": "-",
    "equals": "=",
    "dots": ".",
    "hash_sign": "#",
    "percent": "%",
    "plus_sign": "+",
    "dollar": "$",
    "exclamation": "!",
    "asterisk": "*",
    "comma": ",",
    "double_slash": "//",
    "shortening_service": "Shortining_Service",
}

# Reverse: CSV column → pipeline key
_CSV_TO_PIPELINE: dict[str, str] = {v: k for k, v in _PIPELINE_TO_CSV.items()}


def _pipeline_key(csv_col: str) -> str:
    """Convert CSV column name to pipeline dict key."""
    return _CSV_TO_PIPELINE.get(csv_col, csv_col)


# ─────────────────────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────────────────────

def train(csv_path: str = "Full Dataset/final_dataset_with_all_features_v3.1.csv") -> dict:
    """
    Train XGBoost classifier on URL-level features only.

    Args:
        csv_path: Path to the full dataset CSV.

    Returns:
        Dict with training metrics and model info.
    """
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    from xgboost import XGBClassifier

    log.info("Loading dataset from: %s", csv_path)
    df = pd.read_csv(csv_path)
    log.info("Dataset: %d rows, %d columns", len(df), len(df.columns))

    # ── Verify all ML features exist in dataset ──────────────────────────────
    missing_cols = [c for c in ML_FEATURE_COLUMNS if c not in df.columns]
    if missing_cols:
        log.error("Missing columns in dataset: %s", missing_cols)
        raise ValueError(f"Dataset is missing columns: {missing_cols}")

    available_cols = [c for c in ML_FEATURE_COLUMNS if c in df.columns]
    log.info("Using %d ML features (excluded %d missing)",
             len(available_cols), len(ML_FEATURE_COLUMNS) - len(available_cols))

    # ── Prepare X and y ──────────────────────────────────────────────────────
    X = df[available_cols].fillna(0).values.astype(np.float32)
    y = df["label"].values.astype(np.int32)

    log.info("Feature matrix: %s, Labels: %s", X.shape, np.bincount(y))

    # ── Train/test split ─────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42,
    )
    log.info("Train: %d, Test: %d", len(X_train), len(X_test))

    # ── Compute class weights ────────────────────────────────────────────────
    class_counts = np.bincount(y_train)
    total = len(y_train)
    n_classes = len(class_counts)
    # Sqrt-balanced weights: sqrt(total / (n_classes * count_per_class))
    # This moderates the aggressive upweighting that caused 46% phishing precision.
    # Full balanced = 4.5x for phishing; sqrt gives ~2.1x = better precision.
    raw_weights = {i: total / (n_classes * class_counts[i]) for i in range(n_classes)}
    sqrt_weights = {i: np.sqrt(w) for i, w in raw_weights.items()}
    log.info("Class weights (sqrt-balanced): %s", {i: round(sqrt_weights[i], 3) for i in range(n_classes)})
    sample_weights = np.array([sqrt_weights[yi] for yi in y_train], dtype=np.float32)

    # ── Train XGBoost ────────────────────────────────────────────────────────
    # Hyperparameters tuned for phishing precision:
    #   - max_depth=8: deeper trees capture feature interactions
    #   - min_child_weight=10: require more samples per leaf
    #   - gamma=0.3: minimum loss reduction for splitting
    #   - reg_alpha/lambda: L1/L2 regularization to reduce overfitting
    #   - abnormal_url REMOVED from features (confounding variable)
    log.info("Training XGBoost classifier...")
    model = XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.7,
        min_child_weight=10,
        gamma=0.3,
        reg_alpha=0.5,
        reg_lambda=2.0,
        objective="multi:softprob",
        num_class=4,
        eval_metric="mlogloss",
        tree_method="hist",
        random_state=42,
        n_jobs=-1,
        verbosity=1,
        early_stopping_rounds=20,
    )

    # Split a validation set for early stopping
    from sklearn.model_selection import train_test_split as _split
    X_tr, X_val, y_tr, y_val, sw_tr, sw_val = _split(
        X_train, y_train, sample_weights, test_size=0.1,
        stratify=y_train, random_state=42,
    )

    model.fit(
        X_tr, y_tr,
        sample_weight=sw_tr,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )
    log.info("Best iteration: %d / %d", model.best_iteration, 500)

    # ── Evaluate ─────────────────────────────────────────────────────────────
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=LABEL_NAMES, output_dict=True)
    report_str = classification_report(y_test, y_pred, target_names=LABEL_NAMES)
    cm = confusion_matrix(y_test, y_pred)

    log.info("Classification Report:\n%s", report_str)
    log.info("Confusion Matrix:\n%s", cm)

    # ── Feature importance ───────────────────────────────────────────────────
    importances = model.feature_importances_
    feat_imp = sorted(zip(available_cols, importances), key=lambda x: x[1], reverse=True)
    log.info("Top 15 features:")
    for name, imp in feat_imp[:15]:
        log.info("  %-35s  %.4f", name, imp)

    # ── Save model artifact ──────────────────────────────────────────────────
    _MODEL_DIR.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": model,
        "feature_columns": available_cols,
        "label_names": LABEL_NAMES,
        "label_map": LABEL_MAP,
        "pipeline_to_csv": _PIPELINE_TO_CSV,
        "training_samples": len(X_train),
        "test_accuracy": float(report["accuracy"]),
    }
    with open(_MODEL_PATH, "wb") as f:
        pickle.dump(artifact, f)

    log.info("Model saved to: %s", _MODEL_PATH)

    return {
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": float(report["accuracy"]),
        "per_class": {name: report[name] for name in LABEL_NAMES},
        "confusion_matrix": cm.tolist(),
        "top_features": feat_imp[:15],
        "model_path": str(_MODEL_PATH),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Inference
# ─────────────────────────────────────────────────────────────────────────────

def predict(report: dict) -> dict:
    """
    Run ML inference on a pipeline report.

    Args:
        report: Merged dict from all pipeline stages.

    Returns:
        Dict with:
            ml_prediction:     str ('benign', 'phishing', 'defacement', 'malware')
            ml_confidence:     float 0-1 (probability of predicted class)
            ml_probabilities:  dict {class_name: probability}
    """
    result = {
        "ml_prediction": "unknown",
        "ml_confidence": 0.0,
        "ml_probabilities": {},
    }

    if not _MODEL_PATH.exists():
        log.debug("No trained ML model found at %s — skipping.", _MODEL_PATH)
        return result

    try:
        with open(_MODEL_PATH, "rb") as f:
            artifact = pickle.load(f)

        model = artifact["model"]
        feature_columns = artifact["feature_columns"]
        label_names = artifact["label_names"]
        pipeline_to_csv = artifact.get("pipeline_to_csv", _PIPELINE_TO_CSV)

        # Build CSV-to-pipeline reverse mapping
        csv_to_pipeline = {v: k for k, v in pipeline_to_csv.items()}

        # Build feature vector in EXACT training order
        vector = []
        for col in feature_columns:
            # Try direct key first, then pipeline key mapping
            pipeline_key = csv_to_pipeline.get(col, col)
            val = report.get(col, report.get(pipeline_key, 0))
            try:
                vector.append(float(val))
            except (ValueError, TypeError):
                vector.append(0.0)

        X = np.array([vector], dtype=np.float32)

        # Predict
        probabilities = model.predict_proba(X)[0]
        predicted_class = int(np.argmax(probabilities))
        confidence = float(probabilities[predicted_class])

        result["ml_prediction"] = label_names[predicted_class]
        result["ml_confidence"] = round(confidence, 4)
        result["ml_probabilities"] = {
            name: round(float(prob), 4)
            for name, prob in zip(label_names, probabilities)
        }

        log.info("ML prediction: %s (confidence=%.2f%%) | probs=%s",
                 result["ml_prediction"],
                 confidence * 100,
                 result["ml_probabilities"])

    except Exception as exc:
        log.warning("ML prediction failed: %s", exc)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "train":
        csv = sys.argv[2] if len(sys.argv) > 2 else "Full Dataset/final_dataset_with_all_features_v3.1.csv"
        result = train(csv)
        print(f"\n{'='*60}")
        print(f"  TRAINING COMPLETE")
        print(f"{'='*60}")
        print(f"  Accuracy:  {result['accuracy']:.4f}")
        print(f"  Train:     {result['training_samples']:,}")
        print(f"  Test:      {result['test_samples']:,}")
        print(f"  Model:     {result['model_path']}")
        print(f"{'='*60}")
        for name in LABEL_NAMES:
            m = result["per_class"][name]
            print(f"  {name:12s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1-score']:.3f}")
        print(f"{'='*60}")
    else:
        print("Usage: python -m phishing_pipeline.ml_model train [csv_path]")
