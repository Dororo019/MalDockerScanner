from pathlib import Path
"""
Here's the most important, we coordinate all 6 scanner modules, aggregates results, and computes the final risk score using the two-layer model:
  Layer 1   - RiskScorer.score()            per-CVE context-aware
  Layer 1.5 - RiskAggregator.aggregate()    image-level (max+mean blend)
  Layer 2   - engine penalty boosts         this file
  Final     - clamp((agg_risk + boost + floor) * 0.65, 0, 100), phase 1 --> i used 0:51 first then --> 58 for 4 engines
"""

import time
import logging
import sys
import json
from datetime import datetime
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

#Static scanners
from static_scan.trivy_scan  import run_trivy_scan
from static_scan.syft_scan   import run_syft_scan
from static_scan.clamav_scan import run_clamav_scan
from static_scan.yara_scan   import run_yara_scan
from static_scan.dockle_scan import run_dockle_scan

#Dynamic scanner
from dynamic_scan.falco_monitor import run_falco_scan

#ML scoring (thesis contribution)
from ml_model.risk_scorer     import VulnerabilityContext
from ml_model.risk_aggregator import RiskAggregator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

#Module-level singleton  i mean i will be reusing one aggregator across scans
_AGGREGATOR = RiskAggregator()


#ORCHESTRATOR: main backbone 


class ScanOrchestrator:
    """this one orchestrates multi-engine security scanning across all 6 engines."""

    def __init__(self,
                 yara_rules_file: str = 'static_scan/malware_rules.yar',
                 falco_duration:  int = 10):
        self.yara_rules_file = yara_rules_file
        self.falco_duration  = falco_duration

    def run_scan(self, image_name: str, parallel: bool = True) -> Dict:
        """Running all 6 scanners and return aggregated results."""
        logger.info(f"Starting comprehensive scan: {image_name}")
        start_time = time.time()

        results = {
            'image_name':     image_name,
            'scan_timestamp': datetime.now().isoformat(),
            'scanners':       {},
            'summary': {
                'success':            False,
                'scanners_completed': 0,
                'scanners_failed':    0,
                'total_duration':     0,
            },
        }

        if parallel:
            results['scanners'] = self._run_parallel(image_name)
        else:
            results['scanners'] = self._run_sequential(image_name)

        # to tally success/failure but Falco uses 'status' not 'success'
        for name, res in results['scanners'].items():
            ok = res.get('success', False) or res.get('status') == 'completed'
            if ok:
                results['summary']['scanners_completed'] += 1
            else:
                results['summary']['scanners_failed'] += 1

        results['summary']['total_duration'] = int(time.time() - start_time)
        results['summary']['success'] = results['summary']['scanners_failed'] == 0

        logger.info(
            f"Scan complete: {results['summary']['scanners_completed']}/6 "
            f"scanners succeeded in {results['summary']['total_duration']}s"
        )
        return results

    def _run_parallel(self, image_name: str) -> Dict:
        """Running all 6 scanners in parallel."""
        logger.info("Running scanners in parallel...")
        scanner_results = {}

        with ThreadPoolExecutor(max_workers=6) as executor:
            future_to_scanner = {
                executor.submit(run_trivy_scan,  image_name):                          'trivy',
                executor.submit(run_syft_scan,   image_name):                          'syft',
                executor.submit(run_dockle_scan, image_name):                          'dockle',
                executor.submit(run_yara_scan,   image_name, self.yara_rules_file):    'yara',
                executor.submit(run_clamav_scan, image_name):                          'clamav',
                executor.submit(run_falco_scan,  image_name, self.falco_duration):     'falco',
            }

            for future in as_completed(future_to_scanner):
                name = future_to_scanner[future]
                try:
                    result = future.result(timeout=180)
                    scanner_results[name] = result
                    ok = result.get('success', False) or result.get('status') == 'completed'
                    logger.info(f"{'OK' if ok else 'FAIL'} {name.capitalize()} completed")
                except Exception as e:
                    logger.error(f"FAIL {name.capitalize()} failed: {e}")
                    scanner_results[name] = {
                        'scanner': name,
                        'success': False,
                        'error':   str(e),
                    }

        return scanner_results

    def _run_sequential(self, image_name: str) -> Dict:
        """running all 6 scanners sequentially (debug/low-mem mode)."""
        logger.info("Running scanners sequentially...")
        scanner_results = {}

        tasks = [
            ('trivy',  lambda: run_trivy_scan(image_name)),
            ('syft',   lambda: run_syft_scan(image_name)),
            ('dockle', lambda: run_dockle_scan(image_name)),
            ('yara',   lambda: run_yara_scan(image_name, self.yara_rules_file)),
            ('clamav', lambda: run_clamav_scan(image_name)),
            ('falco',  lambda: run_falco_scan(image_name, self.falco_duration)),
        ]

        for name, fn in tasks:
            try:
                logger.info(f"Running {name.capitalize()}...")
                scanner_results[name] = fn()
            except Exception as e:
                logger.error(f"{name.capitalize()} failed: {e}")
                scanner_results[name] = {
                    'scanner': name, 'success': False, 'error': str(e)
                }

        return scanner_results


# to convert Trivy output to VulnerabilityContext list

def _build_vuln_contexts(trivy_result: Dict) -> List[VulnerabilityContext]:
    """
    Convert Trivy's CVE list into VulnerabilityContext objects for
    the ML risk scorer. Fills in conservative defaults for context
    fields Trivy doesn't provide (in_use, environment, etc.).
    """
    contexts = []
    vulns = trivy_result.get('vulnerabilities', []) or []
    total_layers = trivy_result.get('total_layers', 1)

    for v in vulns:
        # CVSS score - if missing, approximate from severity bucket
        cvss = float(v.get('cvss_score') or 0.0)
        if cvss == 0.0:
            sev = (v.get('severity') or '').upper()
            cvss = {'CRITICAL': 9.5, 'HIGH': 7.5,
                    'MEDIUM': 5.0, 'LOW': 2.5}.get(sev, 0.0)

        ctx = VulnerabilityContext(
            cve_id            = v.get('vulnerability_id') or v.get('cve_id', 'UNKNOWN'),
            cvss_score        = cvss,
            cvss_vector       = v.get('cvss_vector') or
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:L/I:L/A:L',
            package_name      = v.get('pkg_name', ''),
            package_type      = v.get('pkg_type', 'os'),
            layer_index       = v.get('layer_index', 0),
            total_layers      = total_layers,
            in_use            = True,
            is_dev_dependency = False,
            environment       = 'production',
            patch_available   = bool(v.get('fixed_version')),
            public_exploit    = bool(v.get('public_exploit', False)),
            age_days          = int(v.get('age_days', 180)),
        )
        contexts.append(ctx)

    return contexts


# RISK SCORE - Layer 1 (ml_model) + Layer 2 (boosts) + floor

def calculate_risk_score(scan_results: Dict) -> Dict:
    """
    Compute the final risk score using the two-layer model.

      Layer 1 + 1.5 : RiskAggregator   -> aggregated_risk (0-100)
      Layer 2       : engine boosts    -> boost
      Floor         : engines_ok x 2   -> base_floor (prevents 0 on EOL images)

      final = clamp((aggregated_risk + boost + base_floor) * 0.65, 0, 100)
    """
    scanners = scan_results.get('scanners', {})
    image_name = scan_results.get('image_name', '')

    trivy  = scanners.get('trivy',  {}) or {}
    clamav = scanners.get('clamav', {}) or {}
    yara   = scanners.get('yara',   {}) or {}
    dockle = scanners.get('dockle', {}) or {}
    syft   = scanners.get('syft',   {}) or {}
    falco  = scanners.get('falco',  {}) or {}

    # Layer 1 + 1.5: per-CVE scoring + image aggregation
    contexts   = _build_vuln_contexts(trivy)
    image_risk = _AGGREGATOR.aggregate_image_risk(image_name, contexts)
    aggregated_risk = image_risk.aggregated_risk

    # Layer 2: engine penalty boosts
    # Read with fallback keys - different scanner versions use different names
    clamav_hits   = clamav.get('threat_count', clamav.get('threats_found', 0))
    yara_matches  = yara.get('match_count', 0)
    dockle_fatal  = dockle.get('fatal_count', 0)
    dockle_warn   = dockle.get('warn_count', 0)
    syft_packages = syft.get('package_count', syft.get('total_packages', 0))
    syft_highrisk = syft.get('high_risk_licenses', 0)

    # Falco: total alert count across all priorities
    falco_alerts = 0
    if falco.get('status') == 'completed':
        s = falco.get('summary', {})
        falco_alerts = (s.get('critical', 0) + s.get('error', 0)
                      + s.get('warning', 0) + s.get('notice', 0))

    boost = 0
    if clamav_hits  > 0: boost += 10
    if yara_matches > 0: boost += 5
    if falco_alerts > 0: boost += 15
    boost += min(24, dockle_fatal * 8)
    boost += min(9,  dockle_warn  * 3)
    if syft_highrisk > 0:   boost += 6
    if syft_packages > 200: boost += 4

    # Floor: stops EOL images scoring 0 when Trivy DB has gaps
    engines_ok = sum([
        1 if trivy.get('success')  else 0,
        1 if clamav.get('success') else 0,
        1 if yara.get('success')   else 0,
        1 if dockle.get('success') else 0,
        1 if syft.get('success')   else 0,
        1 if falco.get('status') == 'completed' else 0,
    ])
    base_floor = engines_ok * 2     # max +12 when all 6 run

    # Final
    raw   = aggregated_risk + boost + base_floor
    final = max(0.0, min(round(raw * 0.65, 1), 100.0))

    if   final < 20: risk_level = 'LOW'
    elif final < 50: risk_level = 'MEDIUM'
    elif final < 80: risk_level = 'HIGH'
    else:            risk_level = 'CRITICAL'

    return {
        'risk_score':      final,
        'risk_level':      risk_level,
        'max_score':       100.0,
        'aggregated_risk': aggregated_risk,
        'boost':           boost,
        'base_floor':      base_floor,
        'image_risk_detail': {
            'vuln_count': image_risk.vuln_count,
            'max_single': image_risk.max_single,
            'mean_score': image_risk.mean_score,
        },
        'factors': {
            'trivy_critical':    trivy.get('critical_count', 0),
            'trivy_high':        trivy.get('high_count', 0),
            'trivy_medium':      trivy.get('medium_count', 0),
            'trivy_low':         trivy.get('low_count', 0),
            'clamav_hits':       clamav_hits,
            'yara_matches':      yara_matches,
            'falco_alerts':      falco_alerts,
            'dockle_fatal':      dockle_fatal,
            'dockle_warn':       dockle_warn,
            'syft_highrisk_lic': syft_highrisk,
            'syft_packages':     syft_packages,
        },
    }


# to normalize raw scanner output into the engines.* ; shaping the dashboards / CSV writers / evaluators. Last time, it wasn't successful if it is not called from inside run_full_scan(), thus do that every caller to get the both shapes.


def _attach_engines_shape(results: Dict) -> None:
    """Mutates results in place to add engines.*  + flat fields."""
    scn = results.get("scanners", {}) or {}
    trivy  = scn.get("trivy",  {}) or {}
    clamav = scn.get("clamav", {}) or {}
    yara   = scn.get("yara",   {}) or {}
    syft   = scn.get("syft",   {}) or {}
    dockle = scn.get("dockle", {}) or {}
    falco  = scn.get("falco",  {}) or {}

    t_total = (trivy.get("critical_count", 0) + trivy.get("high_count", 0)
             + trivy.get("medium_count", 0) + trivy.get("low_count", 0))
    falco_summary = falco.get("summary", {}) if falco.get("status") == "completed" else {}
    f_total = sum(falco_summary.get(k, 0) for k in ("critical", "error", "warning", "notice"))

    results["engines"] = {
        "trivy":  {"status": "success" if trivy.get("success")  else "failed",
                   "duration": trivy.get("duration", 0),
                   "vulnerabilities": t_total},
        "syft":   {"status": "success" if syft.get("success")   else "failed",
                   "duration": syft.get("duration", 0),
                   "total_packages":     syft.get("package_count", 0),
                   "high_risk_licenses": syft.get("high_risk_licenses", 0)},
        "clamav": {"status": "success" if clamav.get("success") else "failed",
                   "duration": clamav.get("duration", 0),
                   "hits": clamav.get("threat_count", 0)},
        "yara":   {"status": "success" if yara.get("success")   else "failed",
                   "duration": yara.get("duration", 0),
                   "matches": yara.get("match_count", 0)},
        "dockle": {"status": "success" if dockle.get("success") else "failed",
                   "duration": dockle.get("duration", 0),
                   "fatal": dockle.get("fatal_count", 0),
                   "warn":  dockle.get("warn_count", 0)},
        "falco":  {"status": "success" if falco.get("status") == "completed" else "failed",
                   "duration": falco.get("duration_seconds", 0),
                   "alerts": f_total},
    }
    results["trivy_detail"] = {
        "critical": trivy.get("critical_count", 0),
        "high":     trivy.get("high_count", 0),
        "medium":   trivy.get("medium_count", 0),
        "low":      trivy.get("low_count", 0),
    }
    results["falco_detail"] = {
        "critical": falco_summary.get("critical", 0),
        "error":    falco_summary.get("error", 0),
        "warning":  falco_summary.get("warning", 0),
        "notice":   falco_summary.get("notice", 0),
    }

def run_full_scan(image_name: str, parallel: bool = True,
                  yara_rules_file: str = 'static_scan/malware_rules.yar',
                  falco_duration: int = 10) -> Dict:
    """
    Convenience wrapper for end-to-end scanning:
      1. Runs all 6 engines
      2. Computes the two-layer risk score
      3. Returns a flat dict with everything merged

    This is the function batch_scan.py and the Flask app import.
    """
    orchestrator = ScanOrchestrator(yara_rules_file=yara_rules_file,
                                    falco_duration=falco_duration)
    results = orchestrator.run_scan(image_name, parallel=parallel)
    risk_info = calculate_risk_score(results)
    results['risk_assessment'] = risk_info

    # Flatten the fields batch_scan / dashboard look for at the top level
    results['risk_score']    = risk_info['risk_score']
    results['risk_level']    = risk_info['risk_level']
    results['risk_category'] = risk_info['risk_level']     # dashboard alias
    return results

run_complete_scan = run_full_scan


#CLI ENTRY POINT

if __name__ == "__main__":
    test_image = sys.argv[1] if len(sys.argv) > 1 else "alpine:latest"

    print("===========================================")
    print("  MalDocker Scanner - Complete Scan        ")
    print("===========================================")
    print(f"\nImage: {test_image}")
    print("-" * 50)

    orchestrator = ScanOrchestrator()
    results = orchestrator.run_scan(test_image, parallel=True)

    risk_info = calculate_risk_score(results)
    results['risk_assessment'] = risk_info

    # Summary
    print(f"\n{'=' * 50}")
    print("SCAN SUMMARY")
    print(f"{'=' * 50}")

    for name, res in results['scanners'].items():
        ok = res.get('success') or res.get('status') == 'completed'
        symbol = "[OK]" if ok else "[FAIL]"
        err = ""
        if not ok:
            err_msg = res.get('error') or res.get('note', '')
            if err_msg:
                err = f" - {err_msg[:60]}"
        print(f"{symbol} {name.upper():<10}{err}")

    print(f"\n{'-' * 50}")
    print(f"Risk Score: {risk_info['risk_score']}/100 ({risk_info['risk_level']})")
    print(f"  aggregated_risk (Layer 1+1.5): {risk_info['aggregated_risk']}")
    print(f"  boost           (Layer 2)    : +{risk_info['boost']}")
    print(f"  base_floor                   : +{risk_info['base_floor']}")
    print(f"Duration: {results['summary']['total_duration']}s")
    print(f"{'-' * 50}")

    # then save the results in JSON
    Path("output").mkdir(exist_ok=True)
    output_file = f"output/scan_{test_image.replace(':', '_').replace('/', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {output_file}")
