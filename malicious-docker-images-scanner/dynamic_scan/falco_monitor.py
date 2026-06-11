"""
falco_monitor spins up a Docker container, monitors it with Falco for N seconds,
then tears it down and returns a structured alert summary.

Falco must be installed on the HOST (not inside the container):
    https://falco.org/docs/getting-started/installation/
    Ubuntu: sudo apt install falco

Why host-only: Falco works at the kernel syscall level using eBPF.
It cannot run inside a container without privileged access,
and it is not available in GitHub Actions runners.
"""

import json
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

#Falco output format
FALCO_JSON_FORMAT = "json"

#Priority levels Falco uses
PRIORITY_MAP = {
    "EMERGENCY": "critical",
    "ALERT":     "critical",
    "CRITICAL":  "critical",
    "ERROR":     "error",
    "WARNING":   "warning",
    "NOTICE":    "notice",
    "INFO":      "notice",
    "DEBUG":     "notice",
}


def _falco_available() -> bool:
    """Check whether falco is installed on the host."""
    try:
        result = subprocess.run(
            ["falco", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_container_detached(image_name: str) -> str:
    """Start the container in detached mode and return its container ID."""
    result = subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", f"maldocker_scan_{int(time.time())}",
         image_name],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker run failed: {result.stderr[:200]}")
    return result.stdout.strip()


def _stop_container(container_id: str) -> None:
    """Stop and remove the container quietly."""
    subprocess.run(
        ["docker", "kill", container_id],
        capture_output=True, timeout=30,
    )


def _collect_falco_alerts(output_file: str, duration: int) -> List[Dict]:
    """
    Run Falco in the background for `duration` seconds capturing JSON output.
    Returns parsed alert list.
    """
    alerts: List[Dict] = []

    try:
        proc = subprocess.Popen(
            [
                "falco",
                "--output-format", FALCO_JSON_FORMAT,
                "--unbuffered",
                "-o", f"file_output.enabled=true",
                "-o", f"file_output.filename={output_file}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
    except Exception as e:
        logger.warning(f"[falco] Monitor error: {e}")

    # Parse captured output
    if os.path.exists(output_file):
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    alerts.append({
                        "priority": alert.get("priority", "").upper(),
                        "rule":     alert.get("rule", ""),
                        "output":   alert.get("output", ""),
                        "time":     alert.get("time", ""),
                    })
                except json.JSONDecodeError:
                    # Some Falco output lines are not JSON (startup messages)
                    pass
    return alerts


def run_falco_scan(
    image_name: str,
    duration_seconds: int = 10,
) -> Dict[str, Any]:
    """
    Main entry point for Falco dynamic scanning.

    1. Checks Falco is installed.
    2. Starts the container.
    3. Runs Falco for duration_seconds.
    4. Stops the container.
    5. Returns structured summary + raw alerts.
    """
    logger.info(f"[falco] Scanning {image_name} for {duration_seconds}s")

    if not _falco_available():
        logger.warning("[falco] Falco not installed — returning zero alerts")
        return {
            "status":           "falco_not_installed",
            "image_name":       image_name,
            "duration_seconds": duration_seconds,
            "note":             (
                "Falco requires installation on the host VM. "
                "Not available in GitHub Actions or Render.com. "
                "Install: https://falco.org/docs/getting-started/installation/"
            ),
            "summary":          {"critical": 0, "error": 0, "warning": 0, "notice": 0},
            "alerts":           [],
        }

    container_id = None
    output_file  = tempfile.mktemp(suffix="_falco.json")

    try:
        # Start container
        container_id = _run_container_detached(image_name)
        logger.info(f"[falco] Container started: {container_id[:12]}")

        # Run Falco monitoring in a thread while container runs
        alerts = _collect_falco_alerts(output_file, duration_seconds)

    except Exception as e:
        logger.error(f"[falco] Scan error: {e}")
        return {
            "status":           "error",
            "image_name":       image_name,
            "duration_seconds": duration_seconds,
            "error":            str(e),
            "summary":          {"critical": 0, "error": 0, "warning": 0, "notice": 0},
            "alerts":           [],
        }
    finally:
        if container_id:
            _stop_container(container_id)
        try:
            os.unlink(output_file)
        except OSError:
            pass

    # Build summary counts
    summary = {"critical": 0, "error": 0, "warning": 0, "notice": 0}
    for alert in alerts:
        bucket = PRIORITY_MAP.get(alert.get("priority", ""), "notice")
        summary[bucket] += 1

    logger.info(
        f"[falco] Done — critical={summary['critical']} "
        f"error={summary['error']} warning={summary['warning']}"
    )

    return {
        "status":           "completed",
        "image_name":       image_name,
        "duration_seconds": duration_seconds,
        "summary":          summary,
        "alerts":           alerts,
    }
