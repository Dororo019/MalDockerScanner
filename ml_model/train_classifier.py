#!/usr/bin/env python3
"""
Training the ML classifier on the multi-engine scan features. This ML contribution instead of a hand-tuned threshold on the risk score, a Random Forest (and optional XGBoost) learns from ALL engine signals including Syft package counts and Dockle findings thatcatch EOL images that Trivy can no longer scan.
Usage:
    python3 ml_model/train_classifier.py --input evaluation/<latest>/scan_results.json

Outputs (to ml_model/):
    rf_model.pkl              trained Random Forest
    feature_importance.txt    ranked features
    ml_metrics.txt             P/R/F1 with cross-validation
"""

import argparse
import json
import pickle
import re
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneOut, cross_val_predict, StratifiedKFold
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             accuracy_score, confusion_matrix, roc_auc_score)

ROOT = Path(__file__).resolve().parent.parent

FEATURE_NAMES = [
    "trivy_critical", "trivy_high", "trivy_medium", "trivy_low",
    "clamav_hits", "yara_matches", "falco_alerts",
    "dockle_fatal", "dockle_warn", "syft_highrisk_lic",
    "syft_packages", "aggregated_risk", "eol_age_proxy",
]


def eol_age_proxy(name: str) -> int:
    """
    to manage heuristic staleness score for the base image so it catches EOL images whose CVEs predate Trivy's database coverage (so Trivy returns 0 but the image is genuinely risky). Here's why we have to label them as  Higher means older / riskier.
    """
    m = re.search(r":(\d+)\.?(\d+)?", name)
    if not m:
        return 0
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) else 0
    if "ubuntu" in name and major <= 18:                 return 10
    if "centos" in name and major <= 7:                  return 10
    if "python" in name and major <= 3 and minor <= 6:   return 8
    if "php"    in name and major <= 7:                  return 9
    if "node"   in name and major <= 10:                 return 8
    if "nginx"  in name and major == 1 and minor <= 14:  return 7
    if "mysql"  in name and major <= 5:                  return 7
    if "mongo"  in name and major <= 4:                  return 6
    if "redis"  in name and major <= 5:                  return 6
    if "tomcat" in name and major <= 9:                  return 7
    return 0


def extract_features(scan: dict) -> list:
    ra = scan.get("risk_assessment", {})
    fac = ra.get("factors", {})
    return [
        fac.get("trivy_critical", 0), fac.get("trivy_high", 0),
        fac.get("trivy_medium", 0), fac.get("trivy_low", 0),
        fac.get("clamav_hits", 0), fac.get("yara_matches", 0),
        fac.get("falco_alerts", 0), fac.get("dockle_fatal", 0),
        fac.get("dockle_warn", 0), fac.get("syft_highrisk_lic", 0),
        fac.get("syft_packages", 0), ra.get("aggregated_risk", 0),
        eol_age_proxy(scan.get("image_name", "")),
    ]


def main(input_path: str):
    data = json.loads(Path(input_path).read_text())
    completed = [d for d in data if d.get("status") == "completed"]

    X = np.array([extract_features(d) for d in completed], dtype=float)
    y = np.array([1 if d.get("dataset_label") == "malicious" else 0
                  for d in completed])
    names = [d["image_name"] for d in completed]

    print(f"Training on {len(X)} images "
          f"({int(y.sum())} malicious, {int((1-y).sum())} clean)\n")

    #Baseline: the old threshold rule 
    rule_pred = np.array([1 if d["risk_category"] in ("HIGH", "CRITICAL")
                          else 0 for d in completed])
    print("Baseline — threshold rule (risk_category in HIGH/CRITICAL):")
    print(f"  Acc {accuracy_score(y,rule_pred):.3f}  "
          f"Prec {precision_score(y,rule_pred,zero_division=0):.3f}  "
          f"Rec {recall_score(y,rule_pred,zero_division=0):.3f}  "
          f"F1 {f1_score(y,rule_pred,zero_division=0):.3f}\n")

    # Random Forest with leave-one-out Cross Validation(CV); dataset chon'ani i chose this
    rf = RandomForestClassifier(n_estimators=200, max_depth=6,
                                random_state=42, class_weight="balanced")
    rf_pred = cross_val_predict(rf, X, y, cv=LeaveOneOut())
    rf_proba = cross_val_predict(rf, X, y, cv=LeaveOneOut(),
                                 method="predict_proba")[:, 1]

    acc = accuracy_score(y, rf_pred)
    prec = precision_score(y, rf_pred, zero_division=0)
    rec = recall_score(y, rf_pred, zero_division=0)
    f1 = f1_score(y, rf_pred, zero_division=0)
    auc = roc_auc_score(y, rf_proba)
    cm = confusion_matrix(y, rf_pred)

    print("Random Forest — leave-one-out cross-validation:")
    print(f"  Accuracy:  {acc:.3f}")
    print(f"  Precision: {prec:.3f}")
    print(f"  Recall:    {rec:.3f}")
    print(f"  F1:        {f1:.3f}")
    print(f"  ROC-AUC:   {auc:.3f}\n")

    # here, to train final model on all data, get the feature importance 
    rf.fit(X, y)
    importance = sorted(zip(FEATURE_NAMES, rf.feature_importances_),
                        key=lambda x: -x[1])

    # XGboost
    xgb_line = ""
    try:
        from xgboost import XGBClassifier
        xgb = XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1,
                            random_state=42, eval_metric="logloss")
        xgb_pred = cross_val_predict(xgb, X, y, cv=LeaveOneOut())
        xgb_line = (f"XGBoost — leave-one-out CV:\n"
                    f"  Acc {accuracy_score(y,xgb_pred):.3f}  "
                    f"Prec {precision_score(y,xgb_pred,zero_division=0):.3f}  "
                    f"Rec {recall_score(y,xgb_pred,zero_division=0):.3f}  "
                    f"F1 {f1_score(y,xgb_pred,zero_division=0):.3f}")
        print(xgb_line + "\n")
    except ImportError:
        print("(xgboost not installed — skipping. pip install xgboost to enable)\n")

    #Save model&reports
    out = ROOT / "ml_model"
    with (out / "rf_model.pkl").open("wb") as fh:
        pickle.dump({"model": rf, "features": FEATURE_NAMES}, fh)

    fi_text = "FEATURE IMPORTANCE (Random Forest)\n" + "=" * 40 + "\n\n"
    for name, imp in importance:
        bar = "#" * int(imp * 100)
        fi_text += f"  {name:<18} {imp:.3f}  {bar}\n"
    (out / "feature_importance.txt").write_text(fi_text)

    metrics_text = f"""MALDOCKER ML CLASSIFIER — EVALUATION
{'=' * 50}
Dataset: {len(X)} images ({int(y.sum())} malicious, {int((1-y).sum())} clean)
Validation: leave-one-out cross-validation

THRESHOLD RULE BASELINE
  Accuracy:  {accuracy_score(y,rule_pred):.3f}
  Precision: {precision_score(y,rule_pred,zero_division=0):.3f}
  Recall:    {recall_score(y,rule_pred,zero_division=0):.3f}
  F1:        {f1_score(y,rule_pred,zero_division=0):.3f}

RANDOM FOREST CLASSIFIER
  Accuracy:  {acc:.3f}
  Precision: {prec:.3f}
  Recall:    {rec:.3f}
  F1:        {f1:.3f}
  ROC-AUC:   {auc:.3f}

  Confusion Matrix:
                Predicted
            clean    malicious
  clean     TN={cm[0][0]:<4}   FP={cm[0][1]}
  malicious FN={cm[1][0]:<4}   TP={cm[1][1]}

{xgb_line}

TOP FEATURES
""" + "\n".join(f"  {n:<18} {i:.3f}" for n, i in importance[:6])

    (out / "ml_metrics.txt").write_text(metrics_text)

    print(f"Saved:")
    print(f"  {out}/rf_model.pkl")
    print(f"  {out}/feature_importance.txt")
    print(f"  {out}/ml_metrics.txt")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True,
                    help="scan_results.json with corrected labels")
    args = ap.parse_args()
    main(args.input)
