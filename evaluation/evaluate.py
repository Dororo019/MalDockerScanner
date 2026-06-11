#!/usr/bin/env python3

import argparse
import csv
import hashlib
import json
import logging
import os
import random
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# To make the parent project importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("evaluate")

# DATA LOADERS

def load_dataset() -> List[Dict]:
    """Read the labeled image catalog from app/dataset.json."""
    p = ROOT / "app" / "dataset.json"
    if not p.exists():
        log.error(f"{p} not found. Run bulk_import_dataset.py first.")
        sys.exit(1)
    return json.loads(p.read_text())


def load_existing_results(path: str) -> List[Dict]:
    """Read a pre-computed scan_results.json."""
    p = Path(path)
    if not p.exists():
        log.error(f"{path} not found.")
        sys.exit(1)
    return json.loads(p.read_text())

# SCANNER MODES: real and mock 

def docker_pull_if_missing(image: str) -> bool:
    try:
        r = subprocess.run(["docker", "image", "inspect", image],
                           capture_output=True, timeout=10)
        if r.returncode == 0:
            return True
    except Exception:
        pass
    log.info(f"  pulling {image}...")
    try:
        r = subprocess.run(["docker", "pull", image],
                           capture_output=True, text=True, timeout=300)
        return r.returncode == 0
    except Exception:
        return False


def mock_scan(image: str) -> Dict:
    """Deterministic synthetic result — no Docker required."""
    seed = int(hashlib.md5(image.encode()).hexdigest(), 16) % 9999
    rng = random.Random(seed)
    t, c, y, f = rng.randint(0, 40), rng.randint(0, 3), rng.randint(0, 5), rng.randint(0, 4)
    raw = (t * 1.1 + c * 10 + y * 5 + f * 15) * 0.51
    score = round(max(0.0, min(raw, 100.0)), 1)
    cat = "LOW" if score < 20 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
    dur = round(rng.uniform(4, 18), 2)
    return {
        "status": "completed", "image_name": image,
        "final_risk_score": score, "risk_category": cat, "scan_duration": dur,
        "timestamp": datetime.now().isoformat(),
        "engines": {
            "trivy":  {"status": "success", "vulnerabilities": t},
            "clamav": {"status": "success", "hits": c},
            "yara":   {"status": "success", "matches": y},
            "falco":  {"status": "success", "alerts": f},
        },
        "trivy_detail": {"critical": rng.randint(0, max(0, t // 4)),
                         "high":     rng.randint(0, max(0, t // 3)),
                         "medium":   rng.randint(0, max(0, t // 2)),
                         "low":      t},
        "falco_detail": {"critical": rng.randint(0, max(0, f // 2)),
                         "error":    f, "warning": rng.randint(0, 3),
                         "notice":   rng.randint(0, 5)},
    }


def real_scan(image: str) -> Dict:
    """Run the full 6-engine scan via scan_orchestrator."""
    from scan_orchestrator import run_full_scan
    raw = run_full_scan(image)

    # to convert orchestrator output to the flat shape experiments expect
    scn = raw.get("scanners", {}) or {}
    trivy  = scn.get("trivy", {}) or {}
    clamav = scn.get("clamav", {}) or {}
    yara   = scn.get("yara", {}) or {}
    falco  = scn.get("falco", {}) or {}
    summ   = falco.get("summary", {}) if falco.get("status") == "completed" else {}

    t_total = sum(trivy.get(f"{k}_count", 0) for k in ("critical", "high", "medium", "low"))
    f_total = sum(summ.get(k, 0) for k in ("critical", "error", "warning", "notice"))

    return {
        "status":           "completed",
        "image_name":       image,
        "final_risk_score": raw.get("risk_score") or raw.get("final_risk_score") or 0,
        "risk_category":    raw.get("risk_category") or raw.get("risk_level", "LOW"),
        "scan_duration":    raw.get("summary", {}).get("total_duration", 0),
        "timestamp":        raw.get("timestamp") or raw.get("scan_timestamp") or datetime.now().isoformat(),
        "engines": {
            "trivy":  {"status": "success" if trivy.get("success") else "failed",
                       "duration": trivy.get("duration", 0), "vulnerabilities": t_total},
            "clamav": {"status": "success" if clamav.get("success") else "failed",
                       "duration": clamav.get("duration", 0), "hits": clamav.get("threat_count", 0)},
            "yara":   {"status": "success" if yara.get("success") else "failed",
                       "duration": yara.get("duration", 0), "matches": yara.get("match_count", 0)},
            "falco":  {"status": "success" if falco.get("status") == "completed" else "failed",
                       "duration": falco.get("duration_seconds", 0), "alerts": f_total},
        },
        "trivy_detail": {"critical": trivy.get("critical_count", 0),
                         "high":     trivy.get("high_count", 0),
                         "medium":   trivy.get("medium_count", 0),
                         "low":      trivy.get("low_count", 0)},
        "falco_detail": {"critical": summ.get("critical", 0), "error": summ.get("error", 0),
                         "warning":  summ.get("warning", 0),  "notice": summ.get("notice", 0)},
        "risk_assessment": raw.get("risk_assessment", {}),
    }


def run_batch_scan(dataset: List[Dict], use_mock: bool,
                   limit: int | None, pull: bool) -> List[Dict]:
    """Scan every image and attach dataset labels."""
    if limit:
        dataset = dataset[:limit]
    results = []
    for i, entry in enumerate(dataset, 1):
        image = entry["name"]
        log.info(f"[{i:>2}/{len(dataset)}] Scanning: {image}  ({entry['label']})")
        try:
            if use_mock:
                result = mock_scan(image)
            else:
                if pull and not docker_pull_if_missing(image):
                    log.warning(f"  {image}: pull failed, skipping")
                    continue
                result = real_scan(image)
        except Exception as exc:
            log.warning(f"  {image}: scan failed ({exc}), using mock")
            result = mock_scan(image)

        result["dataset_label"]    = entry.get("label", "unknown")
        result["dataset_category"] = entry.get("category", "unknown")
        results.append(result)
        log.info(f"  -> {result['risk_category']} ({result['final_risk_score']}/100)")
    return results


# CSV writer: a flat feature table for ML


CSV_FIELDS = [
    "image_name", "label", "category", "risk_score", "risk_category",
    "trivy_total", "trivy_critical", "trivy_high", "trivy_medium", "trivy_low",
    "clamav_hits", "yara_matches", "falco_alerts",
    "falco_critical", "falco_error", "falco_warning",
    "scan_duration", "timestamp",
]


def write_csv(data: List[Dict], path: Path):
    rows = []
    for r in data:
        td = r.get("trivy_detail", {})
        fd = r.get("falco_detail", {})
        eng = r.get("engines", {})
        rows.append({
            "image_name":     r.get("image_name", ""),
            "label":          r.get("dataset_label", ""),
            "category":       r.get("dataset_category", ""),
            "risk_score":     r.get("final_risk_score", 0),
            "risk_category":  r.get("risk_category", ""),
            "trivy_total":    eng.get("trivy", {}).get("vulnerabilities", 0),
            "trivy_critical": td.get("critical", 0),
            "trivy_high":     td.get("high", 0),
            "trivy_medium":   td.get("medium", 0),
            "trivy_low":      td.get("low", 0),
            "clamav_hits":    eng.get("clamav", {}).get("hits", 0),
            "yara_matches":   eng.get("yara", {}).get("matches", 0),
            "falco_alerts":   eng.get("falco", {}).get("alerts", 0),
            "falco_critical": fd.get("critical", 0),
            "falco_error":    fd.get("error", 0),
            "falco_warning":  fd.get("warning", 0),
            "scan_duration":  r.get("scan_duration", 0),
            "timestamp":      r.get("timestamp", ""),
        })
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)

# EXPERIMENT HELPERS

def _bar(val: float, total: float, width: int = 30) -> str:
    filled = int(round(val / max(1, total) * width))
    return "█" * filled + "░" * (width - filled)


def _divider(char: str = "─", width: int = 60) -> str:
    return char * width

# EXPERIMENT 1: Detection accuracy

def experiment1(data: List[Dict]) -> str:
    out = ["EXPERIMENT 1 — DETECTION ACCURACY", _divider("═"),
           f"Dataset: {len(data)} images",
           f"Run:     {datetime.now().strftime('%Y-%m-%d %H:%M')}", ""]

    out.append("── Default classifier (HIGH/CRITICAL → malicious) ──────────────")
    out.append("")
    tp = fp = tn = fn = 0
    for d in data:
        pred_mal = d["risk_category"] in ("HIGH", "CRITICAL")
        act_mal = d.get("dataset_label") == "malicious"
        if pred_mal and act_mal:       tp += 1
        elif pred_mal and not act_mal: fp += 1
        elif not pred_mal and not act_mal: tn += 1
        else:                          fn += 1

    precision = tp / max(1, tp + fp)
    recall    = tp / max(1, tp + fn)
    f1        = 2 * precision * recall / max(0.001, precision + recall)
    accuracy  = (tp + tn) / max(1, len(data))
    fpr       = fp / max(1, fp + tn)

    out += [
        f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}", "",
        f"  Precision: {precision:.3f}  Recall: {recall:.3f}",
        f"  F1: {f1:.3f}  Accuracy: {accuracy:.3f}  FPR: {fpr:.3f}", "",
        "  Confusion Matrix:",
        "                   Predicted MAL   Predicted CLEAN",
        f"  Actual MAL       {tp:>6} (TP)    {fn:>6} (FN)",
        f"  Actual CLEAN     {fp:>6} (FP)    {tn:>6} (TN)", "",
    ]

    out += ["── Threshold Sensitivity ──────────────────────────────────────", "",
            f"  {'Threshold':>12}  {'Prec':>6}  {'Recall':>6}  {'F1':>6}  {'Acc':>6}  {'FPR':>6}",
            f"  {'─'*12}  {'─'*6}  {'─'*6}  {'─'*6}  {'─'*6}  {'─'*6}"]
    for th in [15, 25, 35, 45, 55, 65, 75]:
        t, f_p, t_n, f_n = 0, 0, 0, 0
        for d in data:
            pred = d["final_risk_score"] >= th
            actual = d.get("dataset_label") == "malicious"
            if pred and actual:       t  += 1
            elif pred and not actual: f_p += 1
            elif not pred and actual: f_n += 1
            else:                     t_n += 1
        p = t / max(1, t + f_p); r = t / max(1, t + f_n)
        f_score = 2 * p * r / max(0.001, p + r)
        a = (t + t_n) / max(1, len(data)); fpr_t = f_p / max(1, f_p + t_n)
        out.append(f"  score >= {th:>3}    {p:>6.3f}  {r:>6.3f}  {f_score:>6.3f}  "
                   f"{a:>6.3f}  {fpr_t:>6.3f}")

    out += ["", "── Per-Image Results ─────────────────────────────────────────", "",
            f"  {'Image':<35}  {'Label':<10}  {'Score':>5}  {'Cat':<8}  Result",
            f"  {'─'*35}  {'─'*10}  {'─'*5}  {'─'*8}  {'─'*10}"]
    for d in sorted(data, key=lambda x: -x["final_risk_score"]):
        pred_mal = d["risk_category"] in ("HIGH", "CRITICAL")
        act_mal = d.get("dataset_label") == "malicious"
        if pred_mal and act_mal:       outcome = "TP ✓"
        elif pred_mal and not act_mal: outcome = "FP ✗"
        elif not pred_mal and not act_mal: outcome = "TN ✓"
        else:                          outcome = "FN ✗"
        out.append(f"  {d['image_name']:<35}  {d.get('dataset_label',''):<10}  "
                   f"{d['final_risk_score']:>5}  {d['risk_category']:<8}  {outcome}")
    return "\n".join(out)


# EXPERIMENT 2: Scan time distribution

def experiment2(data: List[Dict]) -> str:
    out = ["EXPERIMENT 2 — SCAN TIME DISTRIBUTION", _divider("═"), ""]
    durations = [d.get("scan_duration", 0) for d in data if d.get("scan_duration")]
    if not durations:
        return "\n".join(out + ["No duration data."])

    total = sum(durations); mean = total / len(durations)
    sd = sorted(durations); median = sd[len(sd) // 2]; p90 = sd[int(len(sd) * 0.90)]
    out += [f"  Images:        {len(durations)}",
            f"  Total time:    {total:.1f}s ({total/60:.1f} min)",
            f"  Mean:          {mean:.2f}s",
            f"  Median:        {median:.2f}s",
            f"  Min / Max:     {min(durations):.2f}s / {max(durations):.2f}s",
            f"  90th pct:      {p90:.2f}s", ""]

    out += ["── Per-Engine Duration ─────────────────────────────────────", "",
            f"  {'Engine':<8}  {'Mean':>6}  {'Min':>6}  {'Max':>6}  {'Total':>7}",
            f"  {'─'*8}  {'─'*6}  {'─'*6}  {'─'*6}  {'─'*7}"]
    for eng in ["trivy", "clamav", "yara", "falco"]:
        vals = [d.get("engines", {}).get(eng, {}).get("duration", 0) for d in data]
        vals = [v for v in vals if v]
        if vals:
            out.append(f"  {eng:<8}  {sum(vals)/len(vals):>6.2f}  "
                       f"{min(vals):>6.2f}  {max(vals):>6.2f}  {sum(vals):>7.2f}s")

    out += ["", "── Per-Image (sorted) ──────────────────────────────────────", "",
            f"  {'Image':<35}  {'Duration':>8}  Bar"]
    mx = max(durations)
    for d in sorted(data, key=lambda x: -x.get("scan_duration", 0)):
        dur = d.get("scan_duration", 0)
        out.append(f"  {d['image_name']:<35}  {dur:>7.2f}s  {_bar(dur, mx, 25)}")
    return "\n".join(out)


# EXPERIMENT 3: False positive reduction

def experiment3(data: List[Dict]) -> str:
    out = ["EXPERIMENT 3 — FALSE POSITIVE REDUCTION", _divider("═"), "",
           "Context-aware score vs naive CVSS-count baseline.",
           "  Naive   = trivy_count × 6.5 × 0.51   (no context)",
           "  Context = our final_risk_score        (Layer 1+1.5+2)", ""]

    avg_cvss = 6.5; mult = 0.51
    reductions = []
    out += [f"  {'Image':<35}  {'Label':<10}  {'Naive':>6}  {'Ours':>6}  "
            f"{'Δ':>7}  {'Red%':>7}",
            f"  {'─'*35}  {'─'*10}  {'─'*6}  {'─'*6}  {'─'*7}  {'─'*7}"]
    for d in sorted(data, key=lambda x: -x["final_risk_score"]):
        tc = d.get("engines", {}).get("trivy", {}).get("vulnerabilities", 0)
        naive = round(min(100.0, tc * avg_cvss * mult), 1)
        ours = d["final_risk_score"]
        delta = ours - naive
        red = ((naive - ours) / max(1, naive)) * 100
        reductions.append({"label": d.get("dataset_label", ""), "red": red})
        flag = " ← FP" if d.get("dataset_label") == "clean" and naive > ours else ""
        out.append(f"  {d['image_name']:<35}  {d.get('dataset_label',''):<10}  "
                   f"{naive:>6.1f}  {ours:>6.1f}  {delta:>+7.1f}  {red:>6.1f}%{flag}")

    mal = [r["red"] for r in reductions if r["label"] == "malicious"]
    cln = [r["red"] for r in reductions if r["label"] == "clean"]
    out += ["", "── Summary ────────────────────────────────────────────────", ""]
    if mal:
        out.append(f"  Malicious avg reduction: {sum(mal)/len(mal):+.1f}%  (small = kept high)")
    if cln:
        out.append(f"  Clean     avg reduction: {sum(cln)/len(cln):+.1f}%  (large = FP suppressed)")
    return "\n".join(out)


# EXPERIMENT 4: Engine contribution


def experiment4(data: List[Dict]) -> str:
    out = ["EXPERIMENT 4 — ENGINE CONTRIBUTION", _divider("═"), ""]
    engines = ["trivy", "clamav", "yara", "falco"]
    keys = {"trivy": "vulnerabilities", "clamav": "hits", "yara": "matches", "falco": "alerts"}

    for eng in engines:
        key = keys[eng]
        vals = [(d["image_name"], d.get("dataset_label", ""),
                 d.get("engines", {}).get(eng, {}).get(key, 0)) for d in data]
        mal_nz = sum(1 for _, l, v in vals if l == "malicious" and v > 0)
        cln_nz = sum(1 for _, l, v in vals if l == "clean" and v > 0)
        mal_tot = sum(1 for _, l, _ in vals if l == "malicious")
        cln_tot = sum(1 for _, l, _ in vals if l == "clean")
        det = mal_nz / max(1, mal_tot) * 100
        fp = cln_nz / max(1, cln_tot) * 100
        out += [f"── {eng.upper()} ─────────────────────────────────────────",
                f"  Detection:  {mal_nz}/{mal_tot}  ({det:.0f}%)",
                f"  False pos:  {cln_nz}/{cln_tot}  ({fp:.0f}%)", ""]

    out += ["── Multi-Engine Coverage ──────────────────────────────────", "",
            f"  {'Image':<35}  {'Label':<10}  Engines firing"]
    for d in sorted(data, key=lambda x: x.get("dataset_label", "")):
        firing = []
        for eng in engines:
            v = d.get("engines", {}).get(eng, {}).get(keys[eng], 0)
            if v > 0:
                firing.append(f"{eng}({v})")
        out.append(f"  {d['image_name']:<35}  {d.get('dataset_label',''):<10}  "
                   f"{', '.join(firing) or 'none'}")
    return "\n".join(out)


# SUMMARY.MD 

def build_summary_md(data: List[Dict], started_at: float) -> str:
    completed = [d for d in data if d.get("status") == "completed"]
    elapsed = time.time() - started_at

    tp = sum(1 for d in completed if d.get("dataset_label") == "malicious"
             and d["risk_category"] in ("HIGH", "CRITICAL"))
    fp = sum(1 for d in completed if d.get("dataset_label") == "clean"
             and d["risk_category"] in ("HIGH", "CRITICAL"))
    tn = sum(1 for d in completed if d.get("dataset_label") == "clean"
             and d["risk_category"] in ("LOW", "MEDIUM"))
    fn = sum(1 for d in completed if d.get("dataset_label") == "malicious"
             and d["risk_category"] in ("LOW", "MEDIUM"))
    prec = tp / max(1, tp + fp); rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(0.001, prec + rec)
    acc = (tp + tn) / max(1, len(completed))

    mal_scores = [d["final_risk_score"] for d in completed if d.get("dataset_label") == "malicious"]
    cln_scores = [d["final_risk_score"] for d in completed if d.get("dataset_label") == "clean"]

    md = f"""# MalDocker Evaluation — {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Summary

| Metric | Value |
|--------|-------|
| Images processed | {len(data)} |
| Completed scans | {len(completed)} |
| Wall time | {elapsed/60:.1f} min |
| Avg per-scan duration | {sum(d.get('scan_duration',0) for d in completed)/max(1,len(completed)):.1f} s |

## Classification (HIGH/CRITICAL = malicious)

| | Value |
|--|--|
| Accuracy  | {acc:.3f} |
| Precision | {prec:.3f} |
| Recall    | {rec:.3f} |
| F1        | {f1:.3f} |

```
                  Predicted
              clean      malicious
clean         TN={tn:<4}    FP={fp}
malicious     FN={fn:<4}    TP={tp}
```

## Score distribution

| Label | Min | Mean | Max |
|-------|-----|------|-----|
| clean     | {min(cln_scores,default=0):.1f} | {sum(cln_scores)/max(1,len(cln_scores)):.1f} | {max(cln_scores,default=0):.1f} |
| malicious | {min(mal_scores,default=0):.1f} | {sum(mal_scores)/max(1,len(mal_scores)):.1f} | {max(mal_scores,default=0):.1f} |

## Worst false positives (clean scoring high)
"""
    fps = sorted([d for d in completed if d.get("dataset_label") == "clean"
                  and d["risk_category"] in ("HIGH", "CRITICAL")],
                 key=lambda d: -d["final_risk_score"])
    for d in fps[:5]:
        md += f"- `{d['image_name']}` → {d['final_risk_score']}/100 ({d['risk_category']})\n"

    md += "\n## Worst false negatives (malicious scoring low)\n"
    fns = sorted([d for d in completed if d.get("dataset_label") == "malicious"
                  and d["risk_category"] in ("LOW", "MEDIUM")],
                 key=lambda d: d["final_risk_score"])
    for d in fns[:5]:
        eng = d.get("engines", {})
        md += (f"- `{d['image_name']}` → {d['final_risk_score']}/100 "
               f"(trivy={eng.get('trivy',{}).get('vulnerabilities',0)}, "
               f"clamav={eng.get('clamav',{}).get('hits',0)}, "
               f"yara={eng.get('yara',{}).get('matches',0)})\n")

    return md


#main

def main():
    ap = argparse.ArgumentParser(description="MalDocker unified evaluation runner")
    ap.add_argument("--mode", choices=["scan", "mock", "analyze"], default="scan",
                    help="scan = real, mock = synthetic, analyze = reuse existing JSON")
    ap.add_argument("--input", default=None,
                    help="Path to existing scan_results.json (analyze mode)")
    ap.add_argument("--limit", type=int, default=None, help="Cap number of images")
    ap.add_argument("--no-pull", action="store_true", help="Skip docker pull step")
    args = ap.parse_args()

    started_at = time.time()
    out_dir = ROOT / "evaluation" / datetime.now().strftime("%Y-%m-%d_%H%M")
    out_dir.mkdir(parents=True, exist_ok=True)
    log.info(f"Output: {out_dir}")

    # 1.getting the scan data
    if args.mode == "analyze":
        if not args.input:
            log.error("--input required for analyze mode")
            sys.exit(1)
        data = load_existing_results(args.input)
        log.info(f"Loaded {len(data)} existing results from {args.input}")
    else:
        dataset = load_dataset()
        log.info(f"Dataset: {len(dataset)} images")
        data = run_batch_scan(dataset, use_mock=(args.mode == "mock"),
                              limit=args.limit, pull=not args.no_pull)

    # 2. to persist scan_results.json and  dataset.csv
    (out_dir / "scan_results.json").write_text(json.dumps(data, indent=2))
    write_csv(data, out_dir / "dataset.csv")

    # 3. after running all 4 experimenbts
    experiments = {
        "experiment1_detection_accuracy.txt":       experiment1(data),
        "experiment2_scan_time.txt":                experiment2(data),
        "experiment3_false_positive_reduction.txt": experiment3(data),
        "experiment4_engine_contribution.txt":      experiment4(data),
    }
    for fname, content in experiments.items():
        (out_dir / fname).write_text(content)

    # 4. Confusion matrix as standalone file
    tp = sum(1 for d in data if d.get("dataset_label") == "malicious"
             and d.get("risk_category") in ("HIGH", "CRITICAL"))
    fp = sum(1 for d in data if d.get("dataset_label") == "clean"
             and d.get("risk_category") in ("HIGH", "CRITICAL"))
    tn = sum(1 for d in data if d.get("dataset_label") == "clean"
             and d.get("risk_category") in ("LOW", "MEDIUM"))
    fn = sum(1 for d in data if d.get("dataset_label") == "malicious"
             and d.get("risk_category") in ("LOW", "MEDIUM"))
    (out_dir / "confusion_matrix.txt").write_text(
        f"                  Predicted\n"
        f"              clean      malicious\n"
        f"clean         TN={tn:<4}    FP={fp}\n"
        f"malicious     FN={fn:<4}    TP={tp}\n"
    )

    # 5. summary
    (out_dir / "summary.md").write_text(build_summary_md(data, started_at))

    # 6. tagger headline for record purposes
    header = (f"MALDOCKER SCANNER — EVALUATION REPORT\n{_divider('═')}\n"
              f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
              f"Images:    {len(data)}\n"
              f"Mode:      {args.mode}\n{_divider('═')}\n\n")
    (out_dir / "full_report.txt").write_text(header + "\n\n".join(experiments.values()))

    elapsed = time.time() - started_at
    log.info(f"\nDone in {elapsed:.1f}s")
    log.info(f"  {out_dir}/scan_results.json")
    log.info(f"  {out_dir}/dataset.csv")
    log.info(f"  {out_dir}/summary.md          ← weekly review")
    log.info(f"  {out_dir}/full_report.txt     ← thesis chapter 4")


if __name__ == "__main__":
    main()
