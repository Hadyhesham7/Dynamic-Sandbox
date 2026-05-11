"""
anomaly_detector.py — Isolation Forest anomaly detection.

This module provides UNSUPERVISED anomaly detection that does NOT require
labeled phishing data. It learns what "normal" URLs look like from the
dataset's benign majority class, then flags anything that deviates
significantly as anomalous.

Key advantage: Works with zero labeled phishing samples.

Usage:
    1. Train on the existing dataset (fit on benign samples)
    2. At inference time, score each new URL's feature vector
    3. Anomalous URLs get an elevated risk signal
"""

from __future__ import annotations

import os
import pickle
from pathlib import Path

from .logger import get_logger

log = get_logger("anomaly_detector")

# Path to persist the trained model
_MODEL_DIR = Path(__file__).parent / "models"
_MODEL_PATH = _MODEL_DIR / "isolation_forest.pkl"


def _get_numeric_features(report: dict) -> list[float]:
    """
    Extract the numeric features used for anomaly detection.
    Uses a subset of the most discriminative features to avoid
    high-dimensional noise.
    """
    keys = [
        "url_len", "at_sign", "dots", "digits", "hyphen",
        "having_ip_address", "shortening_service", "abnormal_url",
        "url_entropy", "suspicious_keyword_count",
        "path_depth", "query_param_count", "num_subdomains",
        "phish_suspicious_tld", "phish_adv_hyphen_count",
        "phish_redirect_count", "phish_cross_domain_redirects",
    ]
    vector = []
    for k in keys:
        val = report.get(k, 0)
        try:
            vector.append(float(val))
        except (ValueError, TypeError):
            vector.append(0.0)
    return vector


def train_from_csv(csv_path: str, label_column: str = "type",
                   benign_label: str = "benign") -> dict:
    """
    Train an Isolation Forest model on benign URLs from the CSV dataset.

    The model learns the "normal" feature distribution from benign samples,
    then anything that deviates significantly is flagged as anomalous.

    Args:
        csv_path:      Path to the CSV dataset.
        label_column:  Name of the label column.
        benign_label:  Value indicating benign samples.

    Returns:
        Dict with training stats.
    """
    try:
        import numpy as np
        import pandas as pd
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError as e:
        log.error("Required packages not installed: %s. "
                  "Run: pip install scikit-learn pandas numpy", e)
        return {"error": str(e)}

    log.info("Loading dataset from: %s", csv_path)
    df = pd.read_csv(csv_path)

    # Feature columns (numeric only, exclude url/type/domain)
    feature_cols = [c for c in df.columns
                    if c not in ("url", "type", "domain")
                    and df[c].dtype in ("int64", "float64", "int32", "float32")]

    log.info("Using %d features: %s", len(feature_cols), feature_cols)

    # Train on benign samples only
    benign_mask = df[label_column] == benign_label
    X_benign = df.loc[benign_mask, feature_cols].fillna(0).values

    log.info("Training on %d benign samples", len(X_benign))

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_benign)

    # Train Isolation Forest
    # contamination=0.05 means we expect ~5% of "benign" data may actually be mislabeled
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    # Save model + scaler + feature columns
    _MODEL_DIR.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": model,
        "scaler": scaler,
        "feature_cols": feature_cols,
    }
    with open(_MODEL_PATH, "wb") as f:
        pickle.dump(artifact, f)

    log.info("Isolation Forest trained and saved to: %s", _MODEL_PATH)

    # Report stats
    scores = model.decision_function(X_scaled)
    return {
        "samples_trained": len(X_benign),
        "features_used": len(feature_cols),
        "feature_names": feature_cols,
        "anomaly_threshold": float(scores.mean() - 2 * scores.std()),
        "model_path": str(_MODEL_PATH),
    }


def score_anomaly(report: dict) -> dict:
    """
    Score a pipeline report against the trained Isolation Forest model.

    Args:
        report: The merged dict from analyze_url().

    Returns:
        Dict with:
            anomaly_score:    float (negative = more anomalous)
            is_anomaly:       1 if anomalous, 0 if normal
            anomaly_percentile: how unusual this URL is (0-100)
    """
    result = {
        "anomaly_score": 0.0,
        "is_anomaly": 0,
        "anomaly_percentile": 0.0,
    }

    if not _MODEL_PATH.exists():
        log.debug("No trained anomaly model found at %s — skipping.", _MODEL_PATH)
        return result

    try:
        import numpy as np

        with open(_MODEL_PATH, "rb") as f:
            artifact = pickle.load(f)

        model = artifact["model"]
        scaler = artifact["scaler"]
        feature_cols = artifact["feature_cols"]

        # Build feature vector from report using the same columns as training
        # Map CSV column names back to pipeline keys
        csv_to_pipeline = {
            "@": "at_sign", "?": "question_mark", "-": "hyphen",
            "=": "equals", ".": "dots",
            "Shortining_Service": "shortening_service",
            "phish_long_path": "path_depth",
            "phish_many_params": "query_param_count",
        }

        vector = []
        for col in feature_cols:
            pipeline_key = csv_to_pipeline.get(col, col)
            val = report.get(pipeline_key, 0)
            try:
                vector.append(float(val))
            except (ValueError, TypeError):
                vector.append(0.0)

        X = np.array([vector])
        X_scaled = scaler.transform(X)

        # Score: negative values = more anomalous
        score = float(model.decision_function(X_scaled)[0])
        prediction = int(model.predict(X_scaled)[0])  # 1=normal, -1=anomaly

        result["anomaly_score"] = round(score, 4)
        result["is_anomaly"] = 1 if prediction == -1 else 0

        # Convert to percentile (0=most normal, 100=most anomalous)
        # Score typically ranges from -0.5 (anomalous) to 0.5 (normal)
        percentile = max(0, min(100, (0.5 - score) * 100))
        result["anomaly_percentile"] = round(percentile, 1)

        if result["is_anomaly"]:
            log.warning("ANOMALY detected: score=%.4f percentile=%.1f%%",
                        score, percentile)
        else:
            log.debug("Normal: score=%.4f percentile=%.1f%%", score, percentile)

    except Exception as exc:
        log.warning("Anomaly scoring failed: %s", exc)

    return result
