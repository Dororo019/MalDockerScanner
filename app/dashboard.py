"""
dashboard.py  —  MalDocker Scanner  (canonical Flask app)
    python dashboard.py                 # mock mode, port 5000
    python dashboard.py --real          # real scan_orchestrator
    python dashboard.py --port 5001     # custom port

Environment variables:
    DB_NAME / DB_USER / DB_PASSWORD / DB_HOST / DB_PORT  (local)
    DATABASE_URL                                          (Render.com — auto-injected)
    USE_REAL_SCANNER  true/false
"""

import argparse, json, hashlib, logging, os, random, sys, time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, redirect, render_template_string, request, url_for
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional; env vars can be set manually

try:
    from flask_cors import CORS as _CORS
    _has_cors = True
except ImportError:
    _has_cors = False

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
log = logging.getLogger("dashboard")

app = Flask(__name__)
if _has_cors:
    _CORS(app, origins="*")

@app.after_request
def _cors(r):
    r.headers.setdefault("Access-Control-Allow-Origin",  "*")
    r.headers.setdefault("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    r.headers.setdefault("Access-Control-Allow-Headers", "Content-Type")
    return r

@app.route("/api/<path:p>", methods=["OPTIONS"])
def _pre(p): return "", 204

USE_REAL_SCANNER: bool = os.environ.get("USE_REAL_SCANNER","false").lower() == "true"
_store: Dict[str, Dict[str, Any]] = {}
_log:   List[Dict[str, Any]]      = []

# DB 
_DATABASE_URL = os.environ.get("DATABASE_URL","")
if _DATABASE_URL.startswith("postgres://"):
    _DATABASE_URL = _DATABASE_URL.replace("postgres://","postgresql://",1)
_DB = {
    "dbname":   os.environ.get("DB_NAME",     "docker_security_db"),
    "user":     os.environ.get("DB_USER",     "docker_security_logs"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "host":     os.environ.get("DB_HOST",     "127.0.0.1"),  
    "port":     int(os.environ.get("DB_PORT", "5432")),
}

def _db_connect():
    import psycopg2
    if _DATABASE_URL:
        return psycopg2.connect(_DATABASE_URL, sslmode="require")
    return psycopg2.connect(**_DB)

def _db_init():
    try:
        conn = _db_connect(); cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY, scan_id TEXT UNIQUE,
                image_name TEXT NOT NULL, risk_score NUMERIC(5,1),
                risk_category TEXT, trivy_vulns INTEGER DEFAULT 0,
                clamav_hits INTEGER DEFAULT 0, yara_hits INTEGER DEFAULT 0,
                falco_alerts INTEGER DEFAULT 0, scan_duration NUMERIC(8,2),
                scanned_at TIMESTAMPTZ DEFAULT NOW()
            );""")
        conn.commit(); cur.close(); conn.close()
        log.info("DB table ready")
    except Exception as e:
        log.warning(f"DB init skipped ({e})")


def _load_history_from_db(limit: int = 200) -> None:
    """Populate _log from PostgreSQL on startup so dashboard survives restarts."""
    try:
        conn = _db_connect(); cur = conn.cursor()
        cur.execute("""
            SELECT scan_id, image_name, risk_score, risk_category,
                   trivy_vulns, clamav_hits, yara_hits, falco_alerts,
                   scan_duration, scanned_at
            FROM scans ORDER BY scanned_at DESC LIMIT %s;""", (limit,))
        for sid, img, sc, cat, t, c, y, f, dur, ts in cur.fetchall():
            entry = {
                "scan_id": sid or "", "image_name": img,
                "final_risk_score": float(sc or 0), "risk_category": cat or "LOW",
                "scan_duration": float(dur or 0),
                "timestamp": ts.isoformat() if ts else "",
                "status": "completed",
                "engines": {
                    "trivy":  {"status": "success", "vulnerabilities": t or 0},
                    "clamav": {"status": "success", "hits":            c or 0},
                    "yara":   {"status": "success", "matches":         y or 0},
                    "falco":  {"status": "success", "alerts":          f or 0},
                },
                "trivy_detail": {}, "falco_detail": {},
                "yara_rules_matched": [], "clamav_signatures": [],
            }
            _log.append(entry)
            _store[entry["scan_id"]] = entry
        cur.close(); conn.close()
        if _log:
            log.info(f"Loaded {len(_log)} prior scans from DB")
    except Exception as e:
        log.warning(f"DB history load skipped ({e})")

def _db_insert(r: Dict):
    try:
        conn = _db_connect(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO scans (scan_id,image_name,risk_score,risk_category,
                trivy_vulns,clamav_hits,yara_hits,falco_alerts,scan_duration)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (scan_id) DO NOTHING;""", (
            r.get("scan_id"), r.get("image_name"),
            r.get("final_risk_score"), r.get("risk_category"),
            r.get("engines",{}).get("trivy", {}).get("vulnerabilities",0),
            r.get("engines",{}).get("clamav",{}).get("hits",           0),
            r.get("engines",{}).get("yara",  {}).get("matches",        0),
            r.get("engines",{}).get("falco", {}).get("alerts",         0),
            r.get("scan_duration"),
        ))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        log.warning(f"DB insert skipped ({e})")

# Scoring 
def _clamp(raw: float) -> float:
    return round(max(0.0, min(float(raw), 100.0)), 1)

def _cat(s: float) -> str:
    return "LOW" if s<20 else "MEDIUM" if s<50 else "HIGH" if s<75 else "CRITICAL"

# Mock scanner 
_REAL_SCORES = {
    "alpine:3.15": {
        "score": 13.7,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 44
    },
    "alpine:3.19": {
        "score": 5.9,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 380
    },
    "alpine:3.7": {
        "score": 60.2,
        "cat": "HIGH",
        "trivy": 2,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 2,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 492
    },
    "alpine:latest": {
        "score": 9.1,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 481
    },
    "bkimminich/juice-shop:latest": {
        "score": 68.8,
        "cat": "HIGH",
        "trivy": 98,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 5,
        "th": 40,
        "tm": 32,
        "tl": 21,
        "dur": 877
    },
    "centos:6": {
        "score": 70.2,
        "cat": "HIGH",
        "trivy": 1525,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 3,
        "th": 72,
        "tm": 709,
        "tl": 741,
        "dur": 413
    },
    "clamav/clamav:latest": {
        "score": 3.9,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 486
    },
    "dangerous-behavior:latest": {
        "score": 68.3,
        "cat": "HIGH",
        "trivy": 50,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 2,
        "th": 15,
        "tm": 14,
        "tl": 19,
        "dur": 904
    },
    "dangerous-test-image:latest": {
        "score": 71.6,
        "cat": "HIGH",
        "trivy": 50,
        "clamav": 0,
        "yara": 2,
        "falco": 0,
        "tc": 2,
        "th": 15,
        "tm": 14,
        "tl": 19,
        "dur": 1116
    },
    "debian:10": {
        "score": 68.2,
        "cat": "HIGH",
        "trivy": 68,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 2,
        "th": 26,
        "tm": 25,
        "tl": 15,
        "dur": 1950
    },
    "debian:12": {
        "score": 7.2,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 600
    },
    "docker:latest": {
        "score": 16.9,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 131
    },
    "elasticsearch:1.4": {
        "score": 7.2,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 608
    },
    "falcosecurity/falco:latest": {
        "score": 74.7,
        "cat": "HIGH",
        "trivy": 61,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 5,
        "tm": 27,
        "tl": 29,
        "dur": 50
    },
    "goodwithtech/dockle:latest": {
        "score": 75.6,
        "cat": "CRITICAL",
        "trivy": 147,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 1,
        "th": 45,
        "tm": 71,
        "tl": 30,
        "dur": 146
    },
    "hello-world:latest": {
        "score": 11.7,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 11
    },
    "infected-eicar:latest": {
        "score": 79.5,
        "cat": "CRITICAL",
        "trivy": 54,
        "clamav": 0,
        "yara": 2,
        "falco": 0,
        "tc": 2,
        "th": 17,
        "tm": 16,
        "tl": 19,
        "dur": 20
    },
    "malware_test:backdoor": {
        "score": 20.2,
        "cat": "MEDIUM",
        "trivy": 0,
        "clamav": 2,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 13
    },
    "malware_test:behavior": {
        "score": 66.7,
        "cat": "HIGH",
        "trivy": 2,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 2,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 20
    },
    "malware_test:clean": {
        "score": 60.7,
        "cat": "HIGH",
        "trivy": 10,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 2,
        "tm": 5,
        "tl": 3,
        "dur": 11
    },
    "malware_test:exfil": {
        "score": 74.8,
        "cat": "HIGH",
        "trivy": 480,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 31,
        "th": 113,
        "tm": 173,
        "tl": 163,
        "dur": 76
    },
    "malware_test:keylogger": {
        "score": 13.7,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 12
    },
    "malware_test:lateral": {
        "score": 13.7,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 12
    },
    "malware_test:miner": {
        "score": 13.7,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 14
    },
    "malware_test:poisoned": {
        "score": 74.8,
        "cat": "HIGH",
        "trivy": 490,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 32,
        "th": 116,
        "tm": 179,
        "tl": 163,
        "dur": 81
    },
    "malware_test:ransomware": {
        "score": 13.7,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 13
    },
    "malware_test:rootkit": {
        "score": 13.7,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 12
    },
    "malware_test:signature": {
        "score": 70.5,
        "cat": "HIGH",
        "trivy": 10,
        "clamav": 1,
        "yara": 1,
        "falco": 0,
        "tc": 0,
        "th": 2,
        "tm": 5,
        "tl": 3,
        "dur": 12
    },
    "malware_test:vuln": {
        "score": 54.3,
        "cat": "HIGH",
        "trivy": 2,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 2,
        "tl": 0,
        "dur": 43
    },
    "malware_test:vulnerable": {
        "score": 74.9,
        "cat": "HIGH",
        "trivy": 577,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 44,
        "th": 149,
        "tm": 202,
        "tl": 182,
        "dur": 88
    },
    "mongo:3.2": {
        "score": 75.6,
        "cat": "CRITICAL",
        "trivy": 146,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 7,
        "th": 48,
        "tm": 50,
        "tl": 41,
        "dur": 66
    },
    "mongo:4.4": {
        "score": 77.9,
        "cat": "CRITICAL",
        "trivy": 463,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 17,
        "th": 142,
        "tm": 278,
        "tl": 26,
        "dur": 75
    },
    "mongo:7": {
        "score": 78.0,
        "cat": "CRITICAL",
        "trivy": 206,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 1,
        "th": 80,
        "tm": 85,
        "tl": 40,
        "dur": 114
    },
    "mysql:5.5": {
        "score": 76.3,
        "cat": "CRITICAL",
        "trivy": 190,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 10,
        "th": 103,
        "tm": 30,
        "tl": 47,
        "dur": 83
    },
    "mysql:5.7": {
        "score": 75.9,
        "cat": "CRITICAL",
        "trivy": 183,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 4,
        "th": 85,
        "tm": 80,
        "tl": 14,
        "dur": 358
    },
    "mysql:8.0": {
        "score": 78.8,
        "cat": "CRITICAL",
        "trivy": 50,
        "clamav": 0,
        "yara": 1,
        "falco": 0,
        "tc": 1,
        "th": 18,
        "tm": 25,
        "tl": 6,
        "dur": 326
    },
    "nginx:1.10": {
        "score": 12.3,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 300
    },
    "nginx:1.12": {
        "score": 17.6,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 300
    },
    "nginx:1.14": {
        "score": 17.6,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 300
    },
    "nginx:alpine": {
        "score": 68.6,
        "cat": "HIGH",
        "trivy": 19,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 2,
        "tm": 13,
        "tl": 4,
        "dur": 23
    },
    "nginx:latest": {
        "score": 19.5,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 300
    },
    "node:10-alpine": {
        "score": 79.2,
        "cat": "CRITICAL",
        "trivy": 69,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 8,
        "th": 47,
        "tm": 12,
        "tl": 2,
        "dur": 54
    },
    "node:20-alpine": {
        "score": 66.7,
        "cat": "HIGH",
        "trivy": 15,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 11,
        "tm": 2,
        "tl": 2,
        "dur": 21
    },
    "node:22-alpine": {
        "score": 63.0,
        "cat": "HIGH",
        "trivy": 4,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 1,
        "tm": 3,
        "tl": 0,
        "dur": 28
    },
    "node:8": {
        "score": 72.6,
        "cat": "HIGH",
        "trivy": 3326,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 237,
        "th": 1136,
        "tm": 1429,
        "tl": 524,
        "dur": 90
    },
    "php:5.6": {
        "score": 79.1,
        "cat": "CRITICAL",
        "trivy": 987,
        "clamav": 0,
        "yara": 2,
        "falco": 0,
        "tc": 42,
        "th": 382,
        "tm": 384,
        "tl": 179,
        "dur": 75
    },
    "php:7.2-apache": {
        "score": 78.8,
        "cat": "CRITICAL",
        "trivy": 1647,
        "clamav": 0,
        "yara": 2,
        "falco": 0,
        "tc": 86,
        "th": 650,
        "tm": 786,
        "tl": 125,
        "dur": 111
    },
    "php:7.4-apache": {
        "score": 78.0,
        "cat": "CRITICAL",
        "trivy": 7148,
        "clamav": 0,
        "yara": 2,
        "falco": 0,
        "tc": 53,
        "th": 1405,
        "tm": 4378,
        "tl": 1312,
        "dur": 243
    },
    "php:8.2-apache": {
        "score": 77.3,
        "cat": "CRITICAL",
        "trivy": 1149,
        "clamav": 0,
        "yara": 2,
        "falco": 0,
        "tc": 8,
        "th": 76,
        "tm": 363,
        "tl": 702,
        "dur": 354
    },
    "postgres:13.1": {
        "score": 81.3,
        "cat": "CRITICAL",
        "trivy": 464,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 37,
        "th": 187,
        "tm": 184,
        "tl": 56,
        "dur": 74
    },
    "postgres:15": {
        "score": 79.7,
        "cat": "CRITICAL",
        "trivy": 331,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 11,
        "th": 48,
        "tm": 119,
        "tl": 153,
        "dur": 520
    },
    "postgres:9.6": {
        "score": 81.4,
        "cat": "CRITICAL",
        "trivy": 241,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 11,
        "th": 106,
        "tm": 72,
        "tl": 52,
        "dur": 63
    },
    "python:2.7": {
        "score": 64.5,
        "cat": "HIGH",
        "trivy": 4387,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 180,
        "th": 1624,
        "tm": 2070,
        "tl": 513,
        "dur": 90
    },
    "python:2.7-slim": {
        "score": 75.6,
        "cat": "CRITICAL",
        "trivy": 256,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 19,
        "th": 103,
        "tm": 100,
        "tl": 34,
        "dur": 103
    },
    "python:3.11-slim": {
        "score": 78.8,
        "cat": "CRITICAL",
        "trivy": 173,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 2,
        "th": 15,
        "tm": 60,
        "tl": 96,
        "dur": 81
    },
    "python:3.12-slim": {
        "score": 78.8,
        "cat": "CRITICAL",
        "trivy": 170,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 2,
        "th": 12,
        "tm": 60,
        "tl": 96,
        "dur": 67
    },
    "python:3.5-slim": {
        "score": 75.7,
        "cat": "CRITICAL",
        "trivy": 264,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 26,
        "th": 105,
        "tm": 99,
        "tl": 34,
        "dur": 80
    },
    "python:3.6-slim": {
        "score": 74.8,
        "cat": "HIGH",
        "trivy": 475,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 31,
        "th": 112,
        "tm": 169,
        "tl": 163,
        "dur": 72
    },
    "redis:3.2": {
        "score": 76.3,
        "cat": "CRITICAL",
        "trivy": 147,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 13,
        "th": 57,
        "tm": 24,
        "tl": 53,
        "dur": 43
    },
    "redis:4.0": {
        "score": 75.9,
        "cat": "CRITICAL",
        "trivy": 300,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 21,
        "th": 128,
        "tm": 118,
        "tl": 33,
        "dur": 45
    },
    "redis:5.0": {
        "score": 75.1,
        "cat": "CRITICAL",
        "trivy": 454,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 16,
        "th": 123,
        "tm": 178,
        "tl": 137,
        "dur": 48
    },
    "redis:7-alpine": {
        "score": 81.0,
        "cat": "CRITICAL",
        "trivy": 101,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 4,
        "th": 45,
        "tm": 48,
        "tl": 4,
        "dur": 17
    },
    "scanner-test:clean": {
        "score": 74.2,
        "cat": "HIGH",
        "trivy": 50,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 2,
        "th": 15,
        "tm": 14,
        "tl": 19,
        "dur": 11
    },
    "scanner-test:poisoned": {
        "score": 77.4,
        "cat": "CRITICAL",
        "trivy": 50,
        "clamav": 0,
        "yara": 2,
        "falco": 0,
        "tc": 2,
        "th": 15,
        "tm": 14,
        "tl": 19,
        "dur": 12
    },
    "scanner-test:vulnerable": {
        "score": 66.4,
        "cat": "HIGH",
        "trivy": 1,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 1,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 11
    },
    "tomcat:10": {
        "score": 12.3,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 300
    },
    "tomcat:7": {
        "score": 1.3,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 90
    },
    "tomcat:9": {
        "score": 12.3,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 300
    },
    "ubuntu:14.04": {
        "score": 8.5,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 306
    },
    "ubuntu:16.04": {
        "score": 13.7,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 21
    },
    "ubuntu:18.04": {
        "score": 4.5,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 11
    },
    "ubuntu:20.04": {
        "score": 54.3,
        "cat": "HIGH",
        "trivy": 2,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 2,
        "tl": 0,
        "dur": 39
    },
    "ubuntu:22.04": {
        "score": 74.2,
        "cat": "HIGH",
        "trivy": 92,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 2,
        "tm": 48,
        "tl": 42,
        "dur": 44
    },
    "vulnerables/web-dvwa:latest": {
        "score": 1.3,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 90
    },
    "wordpress:4.9": {
        "score": 5.9,
        "cat": "LOW",
        "trivy": 0,
        "clamav": 0,
        "yara": 0,
        "falco": 0,
        "tc": 0,
        "th": 0,
        "tm": 0,
        "tl": 0,
        "dur": 386
    }
}



def _real_or_mock(image: str) -> Dict:
    """Return real evaluation score if known, else fall back to random mock."""
    if image in _REAL_SCORES:
        r = _REAL_SCORES[image]
        sid = f"scan_{int(time.time()*1000)}_{image.replace(':','_').replace('/','_')}"
        return {
            "status": "completed", "scan_id": sid, "image_name": image,
            "timestamp": datetime.now().isoformat(),
            "final_risk_score": r["score"], "risk_category": r["cat"],
            "scan_duration": r["dur"],
            "engines": {
                "trivy":  {"status": "success", "duration": round(r["dur"]*.3,2),
                           "vulnerabilities": r["trivy"]},
                "syft":   {"status": "success", "duration": round(r["dur"]*.15,2),
                           "total_packages": 0, "high_risk_licenses": []},
                "clamav": {"status": "success", "duration": round(r["dur"]*.2,2),
                           "hits": r["clamav"]},
                "yara":   {"status": "success", "duration": round(r["dur"]*.15,2),
                           "matches": r["yara"]},
                "dockle": {"status": "success", "duration": round(r["dur"]*.1,2),
                           "fatal": 0, "warn": 1, "info": 2, "pass": 15},
                "falco":  {"status": "success", "duration": 10, "alerts": r["falco"]},
            },
            "trivy_detail": {"critical": r["tc"], "high": r["th"],
                             "medium": r["tm"], "low": r["tl"]},
            "falco_detail": {"critical": 0, "error": r["falco"], "warning": 0, "notice": 0},
            "yara_rules_matched": [f"rule_{i+1}" for i in range(r["yara"])],
            "clamav_signatures": [f"Malware.Generic.{i+1}" for i in range(r["clamav"])],
            "dockle_findings": [],
            "sbom_summary": {"total_packages": 0, "high_risk_licenses": []},
        }
    return _mock(image)   # unknown image -> original random mock


def _mock(image: str) -> Dict:
    seed = int(hashlib.md5(image.encode()).hexdigest(), 16) % 9999
    rng  = random.Random(seed)
    t = rng.randint(0,40)
    cv = rng.randint(0,3)
    y  = rng.randint(0,5)
    f  = rng.randint(0,4)
    df = rng.randint(0,3)   # dockle fatal
    dw = rng.randint(0,5)   # dockle warn
    sp = rng.randint(40,280) # syft packages
    sl = 1 if seed % 4 == 0 else 0  # high-risk license
    boost = ((10 if cv>0 else 0) + (5 if y>0 else 0) + (15 if f>0 else 0)
             + min(24, df*8) + min(9, dw*3) + (6 if sl else 0) + (4 if sp>200 else 0))
    dur   = round(rng.uniform(4.0,18.0), 2)
    score = _clamp((t*1.1 + boost) * 0.51)
    sid   = f"scan_{int(time.time()*1000)}_{image.replace(':','_').replace('/','_')}"
    risk_lics = ["GPL-2.0"] if sl else []
    return {
        "status":"completed","scan_id":sid,"image_name":image,
        "timestamp":datetime.now().isoformat(),
        "final_risk_score":score,"risk_category":_cat(score),"scan_duration":dur,
        "engines":{
            "trivy": {"status":"success","duration":round(dur*.25,2),"vulnerabilities":t},
            "syft":  {"status":"success","duration":round(dur*.15,2),
                      "total_packages":sp,"os_packages":int(sp*.6),"lib_packages":int(sp*.4),
                      "high_risk_licenses":risk_lics,
                      "unique_licenses":["MIT","Apache-2.0","BSD-3-Clause"][:rng.randint(2,3)]},
            "clamav":{"status":"success","duration":round(dur*.2,2),"hits":cv},
            "yara":  {"status":"success","duration":round(dur*.15,2),"matches":y},
            "dockle":{"status":"success","duration":round(dur*.1,2),
                      "fatal":df,"warn":dw,"info":rng.randint(0,3),"pass":rng.randint(10,22)},
            "falco": {"status":"success","duration":round(dur*.15,2),"alerts":f},
        },
        "trivy_detail":{"critical":rng.randint(0,max(0,t//4)),"high":rng.randint(0,max(0,t//3)),
                        "medium":rng.randint(0,max(0,t//2)),"low":t},
        "falco_detail":{"critical":rng.randint(0,max(0,f//2)),"error":f,
                        "warning":rng.randint(0,3),"notice":rng.randint(0,5)},
        "yara_rules_matched":[f"rule_{(seed+i)%50+1}" for i in range(y)],
        "clamav_signatures": [f"Malware.Generic.{(seed+i)%900+100}" for i in range(cv)],
        "dockle_findings":   [{"code":f"CIS-DI-000{i+1}","level":"FATAL",
                               "title":["Container runs as root","Sensitive ENV variable","SETUID bits found"][i%3]}
                              for i in range(df)],
        "sbom_summary":      {"total_packages":sp,"high_risk_licenses":risk_lics},
    }

def _to_dashboard_shape(raw: Dict) -> Dict:
    """
    it will convert scan_orchestrator.run_full_scan() output into the shape
    the standalone dashboard.html expects.

    Maps:
      scanners.trivy.{critical,high,medium,low}_count → engines.trivy.vulnerabilities
      scanners.clamav.threat_count                    → engines.clamav.hits
      scanners.yara.match_count                       → engines.yara.matches
      scanners.falco.summary.{c,e,w,n} (sum)          → engines.falco.alerts
      scanners.syft.package_count                     → engines.syft.total_packages
      scanners.dockle.{fatal,warn}_count              → engines.dockle.{fatal,warn}
    """
    scanners = raw.get("scanners", {}) or {}
    risk     = raw.get("risk_assessment", {}) or {}

    trivy  = scanners.get("trivy",  {}) or {}
    clamav = scanners.get("clamav", {}) or {}
    yara   = scanners.get("yara",   {}) or {}
    syft   = scanners.get("syft",   {}) or {}
    dockle = scanners.get("dockle", {}) or {}
    falco  = scanners.get("falco",  {}) or {}

    # Trivy totals
    t_crit = trivy.get("critical_count", 0)
    t_high = trivy.get("high_count", 0)
    t_med  = trivy.get("medium_count", 0)
    t_low  = trivy.get("low_count", 0)
    t_total = t_crit + t_high + t_med + t_low

    # Falco alert total
    falco_summary = falco.get("summary", {}) if falco.get("status") == "completed" else {}
    f_total = sum(falco_summary.get(k, 0) for k in ("critical", "error", "warning", "notice"))

    syft_highrisk = syft.get("high_risk_licenses", 0)
    risk_lics = ["GPL-2.0"] if syft_highrisk else []

    return {
        "status":           "completed" if raw.get("summary", {}).get("success") else "partial",
        "scan_id":          raw.get("scan_id") or f"scan_{int(time.time()*1000)}",
        "image_name":       raw.get("image_name", ""),
        "timestamp":        raw.get("timestamp") or raw.get("scan_timestamp") or datetime.now().isoformat(),
        "final_risk_score": raw.get("risk_score") or raw.get("final_risk_score") or 0.0,
        "risk_category":    raw.get("risk_category") or raw.get("risk_level") or "LOW",
        "scan_duration":    raw.get("scan_duration") or raw.get("summary", {}).get("total_duration", 0),

        "engines": {
            "trivy":  {"status": "success" if trivy.get("success")  else "failed",
                       "duration": trivy.get("duration", 0),
                       "vulnerabilities": t_total},
            "syft":   {"status": "success" if syft.get("success")   else "failed",
                       "duration": syft.get("duration", 0),
                       "total_packages":     syft.get("package_count", 0),
                       "os_packages":        syft.get("os_packages", 0),
                       "lib_packages":       syft.get("lib_packages", 0),
                       "high_risk_licenses": risk_lics,
                       "unique_licenses":    syft.get("unique_licenses", [])},
            "clamav": {"status": "success" if clamav.get("success") else "failed",
                       "duration": clamav.get("duration", 0),
                       "hits": clamav.get("threat_count", 0)},
            "yara":   {"status": "success" if yara.get("success")   else "failed",
                       "duration": yara.get("duration", 0),
                       "matches": yara.get("match_count", 0)},
            "dockle": {"status": "success" if dockle.get("success") else "failed",
                       "duration": dockle.get("duration", 0),
                       "fatal": dockle.get("fatal_count", 0),
                       "warn":  dockle.get("warn_count", 0),
                       "info":  dockle.get("info_count", 0),
                       "pass":  dockle.get("pass_count", 0)},
            "falco":  {"status": "success" if falco.get("status") == "completed" else "failed",
                       "duration": falco.get("duration_seconds", 0),
                       "alerts": f_total},
        },

        # Detail dicts for the report modal
        "trivy_detail":  {"critical": t_crit, "high": t_high, "medium": t_med, "low": t_low},
        "falco_detail":  {"critical": falco_summary.get("critical", 0),
                          "error":    falco_summary.get("error", 0),
                          "warning":  falco_summary.get("warning", 0),
                          "notice":   falco_summary.get("notice", 0)},
        "yara_rules_matched": yara.get("matches", []) if isinstance(yara.get("matches"), list) else [],
        "clamav_signatures":  clamav.get("threats", []) if isinstance(clamav.get("threats"), list) else [],
        "dockle_findings":    dockle.get("findings", []),
        "sbom_summary":       {"total_packages": syft.get("package_count", 0),
                               "high_risk_licenses": risk_lics},

        
        "_raw": raw,
    }


def _docker_pull(image: str, timeout: int = 180) -> bool:
    """Pull image if not local. Returns True on success, False otherwise."""
    import subprocess
    try:
        # Check first then skip pull if it's already there
        r = subprocess.run(["docker", "image", "inspect", image],
                           capture_output=True, timeout=10)
        if r.returncode == 0:
            return True
    except Exception:
        pass
    try:
        log.info(f"Pulling {image}...")
        r = subprocess.run(["docker", "pull", image],
                           capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            log.info(f"Pulled {image}")
            return True
        log.warning(f"Pull failed for {image}: {r.stderr[:200]}")
        return False
    except subprocess.TimeoutExpired:
        log.warning(f"Pull timed out for {image}")
        return False
    except Exception as e:
        log.warning(f"Pull error for {image}: {e}")
        return False

def _do_scan(image: str) -> Dict:
    result: Dict = {}
    # Auto-pull if image is missing locally
    if USE_REAL_SCANNER:
        _docker_pull(image)

    if USE_REAL_SCANNER:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            
            sys.path.insert(0, os.path.abspath(os.path.join(
                os.path.dirname(__file__), "..")))
            from scan_orchestrator import run_full_scan
            raw = run_full_scan(image)
            result = _to_dashboard_shape(raw)        
        except Exception as e:
            log.warning(f"Real scan failed ({e}), using mock")
            result = _real_or_mock(image)
    else:
        result = _real_or_mock(image)
 
    result["final_risk_score"] = _clamp(result.get("final_risk_score", 0))
    result["risk_category"]    = _cat(result["final_risk_score"])
    if "scan_id"   not in result:
        result["scan_id"]   = f"scan_{int(time.time()*1000)}_{image.replace(':','_').replace('/','_')}"
    if "timestamp" not in result:
        result["timestamp"] = datetime.now().isoformat()
    return result

def _save(r: Dict):
    _store[r["scan_id"]] = r
    _log.insert(0, r)
    if len(_log) > 200: _log.pop()
    _db_insert(r)

# Dataset 
# Inline dataset fallback (75 images) evaluation we did so far.
# Loaded only if app/dataset.json is missing or unreadable.
_INLINE_DATASET: List[Dict] = [
    {"name":"alpine:3.15", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"alpine:3.19", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"alpine:3.7", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"alpine:latest", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"bkimminich/juice-shop:latest", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"centos:6", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"clamav/clamav:latest", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"dangerous-behavior:latest", "source":"build", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"dangerous-test-image:latest", "source":"build", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"debian:10", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"debian:12", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"docker:latest", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"elasticsearch:1.4", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"falcosecurity/falco:latest", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"goodwithtech/dockle:latest", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"hello-world:latest", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"infected-eicar:latest", "source":"build", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"malware_test:backdoor", "source":"build", "dockerfile":"Dockerfile.backdoor", "label":"malicious", "category":"backdoor", "threat_type":"backdoor", "description":"Reverse-shell backdoor pattern"},
    {"name":"malware_test:behavior", "source":"build", "dockerfile":"Dockerfile.behavior", "label":"malicious", "category":"behavior", "threat_type":"runtime_behavior", "description":"Suspicious runtime behaviour"},
    {"name":"malware_test:clean", "source":"build", "dockerfile":"Dockerfile.clean", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"malware_test:exfil", "source":"build", "dockerfile":"Dockerfile.exfil", "label":"malicious", "category":"exfiltration", "threat_type":"data_exfil", "description":"Data-exfiltration pattern"},
    {"name":"malware_test:keylogger", "source":"build", "dockerfile":"Dockerfile.keylogger", "label":"clean", "category":"malware", "threat_type":"none", "description":"Embedded malware signature/pattern"},
    {"name":"malware_test:lateral", "source":"build", "dockerfile":"Dockerfile.lateral", "label":"clean", "category":"behavior", "threat_type":"none", "description":"Suspicious runtime behaviour"},
    {"name":"malware_test:miner", "source":"build", "dockerfile":"Dockerfile.miner", "label":"malicious", "category":"cryptominer", "threat_type":"cryptominer", "description":"Crypto-miner pattern"},
    {"name":"malware_test:poisoned", "source":"build", "dockerfile":"Dockerfile.poisoned", "label":"malicious", "category":"supply-chain", "threat_type":"supply_chain", "description":"Supply-chain poisoned dependencies"},
    {"name":"malware_test:ransomware", "source":"build", "dockerfile":"Dockerfile.ransomware", "label":"clean", "category":"malware", "threat_type":"none", "description":"Embedded malware signature/pattern"},
    {"name":"malware_test:rootkit", "source":"build", "dockerfile":"Dockerfile.rootkit", "label":"clean", "category":"malware", "threat_type":"none", "description":"Embedded malware signature/pattern"},
    {"name":"malware_test:signature", "source":"build", "dockerfile":"Dockerfile.signature", "label":"malicious", "category":"malware", "threat_type":"known_malware", "description":"Embedded malware signature/pattern"},
    {"name":"malware_test:vuln", "source":"build", "dockerfile":"Dockerfile.vuln", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"malware_test:vulnerable", "source":"build", "dockerfile":"Dockerfile.vulnerable", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"mongo:3.2", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"mongo:4.4", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"mongo:7", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"mysql:5.5", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"mysql:5.7", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"mysql:8.0", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"nginx:1.10", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"nginx:1.12", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"nginx:1.14", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"nginx:alpine", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"nginx:latest", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"node:10-alpine", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"node:20-alpine", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"node:22-alpine", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"node:8", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"php:5.6", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"php:7.2-apache", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"php:7.4-apache", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"php:8.2-apache", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"postgres:13.1", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"postgres:15", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"postgres:9.6", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"python:2.7", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"python:2.7-slim", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"python:3.11-slim", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"python:3.12-slim", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"python:3.5-slim", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"python:3.6-slim", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"redis:3.2", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"redis:4.0", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"redis:5.0", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"redis:7-alpine", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"scanner-test:clean", "source":"build", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"scanner-test:poisoned", "source":"build", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"scanner-test:vulnerable", "source":"build", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"tomcat:10", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"tomcat:7", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"tomcat:9", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"ubuntu:14.04", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"ubuntu:16.04", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"ubuntu:18.04", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
    {"name":"ubuntu:20.04", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"ubuntu:22.04", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"vulnerables/web-dvwa:latest", "source":"pull", "label":"clean", "category":"baseline", "threat_type":"none", "description":"Current maintained base image"},
    {"name":"wordpress:4.9", "source":"pull", "label":"malicious", "category":"cve", "threat_type":"unpatched_cve", "description":"Image with known/unpatched CVEs"},
]

#Dataset (loaded from external JSON, falls back to inline) 
_DATASET_PATH = Path(__file__).parent / "dataset.json"

def _load_dataset() -> List[Dict]:
    if _DATASET_PATH.exists():
        try:
            return json.loads(_DATASET_PATH.read_text())
        except Exception as e:
            log.warning(f"dataset.json unreadable ({e}) — using inline fallback")
    return _INLINE_DATASET

def _save_dataset() -> None:
    try:
        _DATASET_PATH.write_text(json.dumps(DATASET, indent=2))
    except Exception as e:
        log.warning(f"dataset.json save failed ({e})")

DATASET = _load_dataset()
# Routes 
@app.route("/")
def root(): return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    tmpl = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    try:    return render_template_string(open(tmpl).read())
    except: return redirect("../dashboard_standalone.html")

@app.route("/scan/<scan_id>")
def scan_detail(scan_id):
    r = _store.get(scan_id)
    if not r: return jsonify({"error":"not found"}), 404
    tmpl = os.path.join(os.path.dirname(__file__), "templates", "scan_detail.html")
    try:    return render_template_string(open(tmpl).read(), result=r)
    except: return jsonify(r)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data  = request.get_json(force=True) or {}
    image = (data.get("image_name") or data.get("image") or "").strip()
    if not image: return jsonify({"error":"image_name required"}), 400
    result = _do_scan(image); _save(result)
    return jsonify(result)


@app.route("/api/scan/sync", methods=["POST"])
def api_scan_sync():
    """Synchronous scan endpoint — used by standalone dashboard HTML."""
    return api_scan()

@app.route("/api/scan/<scan_id>", methods=["GET"])
def api_scan_get(scan_id):
    r = _store.get(scan_id)
    return jsonify(r) if r else (jsonify({"error":"not found"}), 404)

@app.route("/api/scan/import", methods=["POST"])
def api_scan_import():
    """Accept pre-computed result — e.g. from a GitHub Actions artifact."""
    data = request.get_json(force=True) or {}
    if not data.get("image_name"): return jsonify({"error":"image_name required"}), 400
    data["final_risk_score"] = _clamp(data.get("final_risk_score", 0))
    data["risk_category"]    = _cat(data["final_risk_score"])
    if "scan_id"   not in data: data["scan_id"]   = f"import_{int(time.time()*1000)}"
    if "timestamp" not in data: data["timestamp"] = datetime.now().isoformat()
    _save(data)
    return jsonify({"status":"imported","scan_id":data["scan_id"]})

@app.route("/api/scans", methods=["GET"])
def api_scans(): return jsonify(_log[:50])

@app.route("/api/db/scans", methods=["GET"])
def api_db_scans():
    try:
        conn = _db_connect(); cur = conn.cursor()
        cur.execute("""
            SELECT scan_id,image_name,risk_score,risk_category,
                   trivy_vulns,clamav_hits,yara_hits,falco_alerts,
                   scan_duration,scanned_at
            FROM scans ORDER BY scanned_at DESC LIMIT 200;""")
        rows = []
        for sid,img,sc,cat,t,c,y,f,dur,ts in cur.fetchall():
            rows.append({"scan_id":sid or "","image_name":img,
                "final_risk_score":float(sc or 0),"risk_category":cat or "LOW",
                "scan_duration":float(dur or 0),
                "timestamp":ts.isoformat() if ts else "","status":"completed",
                "engines":{"trivy":{"status":"success","vulnerabilities":t or 0},
                           "clamav":{"status":"success","hits":c or 0},
                           "yara":{"status":"success","matches":y or 0},
                           "falco":{"status":"success","alerts":f or 0}},
                "trivy_detail":{},"falco_detail":{},"yara_rules_matched":[],"clamav_signatures":[]})
        cur.close(); conn.close()
        return jsonify(rows)
    except Exception as e:
        log.warning(f"DB read failed: {e}")
        return jsonify({"error":str(e)}), 503

@app.route("/api/stats", methods=["GET"])
def api_stats():
    if not _log:
        return jsonify({"total":0,"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"avg_score":0})
    cats = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    scores = []
    for s in _log:
        cats[s.get("risk_category","LOW")] = cats.get(s.get("risk_category","LOW"),0)+1
        scores.append(s.get("final_risk_score",0))
    return jsonify({"total":len(_log),"CRITICAL":cats["CRITICAL"],"HIGH":cats["HIGH"],
                    "MEDIUM":cats["MEDIUM"],"LOW":cats["LOW"],
                    "avg_score":round(sum(scores)/len(scores),1)})

@app.route("/api/dataset", methods=["GET"])
def api_dataset(): return jsonify(DATASET)

@app.route("/api/dataset/add", methods=["POST"])
def api_dataset_add():
    data = request.get_json(force=True) or {}
    name = data.get("name","").strip()
    if not name: return jsonify({"error":"name required"}), 400
    if any(d["name"]==name for d in DATASET):
        return jsonify({"error":f"{name} already in dataset"}), 409
    DATASET.append({"name":name,"source":data.get("source","build"),
        "dockerfile":data.get("dockerfile",""),"label":data.get("label","malicious"),
        "category":data.get("category","cve"),"threat_type":data.get("threat_type","unknown"),
        "description":data.get("description","")})
    _save_dataset()
    return jsonify({"status":"added","total":len(DATASET)})

@app.route("/health", methods=["GET"])
def health():
    db_ok = False
    try: conn=_db_connect(); conn.close(); db_ok=True
    except: pass
    return jsonify({"status":"ok","db":"connected" if db_ok else "offline",
                    "total_scans":len(_log),"real_scanner":USE_REAL_SCANNER,
                    "timestamp":datetime.now().isoformat()})

#  Entry point 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MalDocker Dashboard")
    parser.add_argument("--port",  type=int, default=int(os.environ.get("PORT", 5000)))
    parser.add_argument("--real",  action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    if args.real: USE_REAL_SCANNER = True
    _db_init()
    _load_history_from_db()
    print(f"\n  MalDocker Dashboard — {'REAL' if USE_REAL_SCANNER else 'MOCK'} mode")
    print(f"  http://localhost:{args.port}/dashboard\n")
    app.run(host="0.0.0.0", port=args.port, debug=args.debug)
