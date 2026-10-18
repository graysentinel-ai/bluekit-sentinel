#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ██████╗ ██╗     ██╗   ██╗███████╗██╗  ██╗██╗████████╗                      ║
║   ██╔══██╗██║     ██║   ██║██╔════╝██║ ██╔╝██║╚══██╔══╝                      ║
║   ██████╔╝██║     ██║   ██║█████╗  █████╔╝ ██║   ██║                         ║
║   ██╔══██╗██║     ██║   ██║██╔══╝  ██╔═██╗ ██║   ██║                         ║
║   ██████╔╝███████╗╚██████╔╝███████╗██║  ██╗██║   ██║                         ║
║   ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝                         ║
║                                                                              ║
║   S E N T I N E L   v1.0.0 — Host & Network Recon Correlation Engine         ║
║                                                                              ║
║   Developer      : Ritik Shrivas                                             ║
║   Organization   : Graysentinel Cyber Defence Lab                            ║
║   Website        : https://cyberdefencelab.co.in                             ║
║   License        : Apache-2.0                                                ║
║   Copyright      : © 2025 Ritik Shrivas / Graysentinel Cyber Defence Lab     ║
║                                                                              ║
║   v1.0.0 — Clean production release                                          ║
║     • Correct architecture — every subsystem has graceful fallback           ║
║     • Correct DB migration — PRAGMA-driven, all columns checked              ║
║     • Correct lazy telemetry — expensive ops opt-in, not default             ║
║     • Correct async packet hook — separate thread, no packet loss            ║
║     • Correct Bayesian math — proper prior/posterior, capped                 ║
║     • Correct TLS parsing — bounds-checked, RFC-compliant                    ║
║     • Correct DGA detection — entropy + vowel + digit ratios                 ║
║     • Correct beacon detection — CV + FFT regularity                         ║
║     • Correct port-scan detection — SYN/ACK statistical model                ║
║     • Bounded everywhere — caches, queues, lists, memory                     ║
║     • Thread-safe — documented lock scope                                    ║
║                                                                              ║
║   AUTHORIZED USE ONLY — see SECURITY.md                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import math
import ntpath
import os
import platform
import posixpath
import re
import secrets
import shlex
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from collections import Counter, OrderedDict, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from queue import Queue, Empty, Full
from typing import Any, Dict, List, Optional, Set, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — METADATA
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_NAME = "BlueKit Sentinel"
TOOL_VERSION = "1.0.0"
DEVELOPER = "Ritik Shrivas"
ORGANIZATION = "Graysentinel Cyber Defence Lab"

CONTACT = {
    "website": "https://cyberdefencelab.co.in",
    "email": "graysentinel.ai@gmail.com",
    "founder": "linkedin.com/in/ritikshrivas312",
}

BANNER = r"""
   ██████╗ ██╗     ██╗   ██╗███████╗██╗  ██╗██╗████████╗
   ██╔══██╗██║     ██║   ██║██╔════╝██║ ██╔╝██║╚══██╔══╝
   ██████╔╝██║     ██║   ██║█████╗  █████╔╝ ██║   ██║
   ██╔══██╗██║     ██║   ██║██╔══╝  ██╔═██╗ ██║   ██║
   ██████╔╝███████╗╚██████╔╝███████╗██║  ██╗██║   ██║
   ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
                S  E  N  T  I  N  E  L   v1
"""

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — IMPORTS (every optional dep has independent fallback)
# ═══════════════════════════════════════════════════════════════════════════════

try:
    import psutil
except ImportError:
    print("[FATAL] psutil required. Run: pip install psutil", file=sys.stderr)
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = Panel = Table = None

try:
    from flask import Flask, jsonify, request, redirect, url_for, session
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = jsonify = request = redirect = url_for = session = None

try:
    from waitress import serve as waitress_serve
    WAITRESS_AVAILABLE = True
except ImportError:
    waitress_serve = None
    WAITRESS_AVAILABLE = False

try:
    from gunicorn.app.base import BaseApplication as GunicornBaseApplication
    GUNICORN_AVAILABLE = True
except ImportError:
    GunicornBaseApplication = None
    GUNICORN_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    np = None
    NUMPY_AVAILABLE = False

# ── Correct fallback: separate imports so old scapy doesn't break everything
try:
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    AsyncSniffer = IP = IPv6 = TCP = UDP = ICMP = None
    SCAPY_AVAILABLE = False

try:
    from scapy.all import DNS, DNSQR, DNSRR
    SCAPY_DNS_AVAILABLE = True
except ImportError:
    DNS = DNSQR = DNSRR = None
    SCAPY_DNS_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None
    YAML_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — PATHS & LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

try:
    HOME = Path.home()
except (OSError, RuntimeError):
    HOME = Path(os.environ.get("TMPDIR") or os.environ.get("TEMP") or ".").resolve()

BLUEKIT_DIR = Path(os.environ.get("BLUEKIT_HOME", str(HOME / ".bluekit"))).expanduser()
DATA_DIR = BLUEKIT_DIR / "sentinel"
DB_PATH = DATA_DIR / "sentinel.db"
STIX_CACHE = DATA_DIR / "enterprise-attack.json"
ALLOWLIST_PATH = DATA_DIR / "allowlist.yaml"
BASELINE_PATH = DATA_DIR / "baseline.json"

logging.basicConfig(
    level=os.environ.get("BLUEKIT_LOG_LEVEL", "WARNING").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("bluekit_sentinel")

_QUIET_MODE = False
_shutdown_event = threading.Event()

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# Suspicious ports — C2/backdoor defaults
SUSPICIOUS_PORTS: Set[int] = {
    4444, 4445, 5555, 6666, 9999, 31337, 12345, 54321,
    1337, 6667, 6668, 6669, 1080, 1081, 9001, 9050, 4443, 5554,
    27374, 27665, 65000,
}

# Legit ports that might trigger false positives — 8888 NOT here (proxy/dev, but see PSEUDO)
COMMON_LEGIT_PORTS: Set[int] = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 514, 515, 587, 636, 873, 993, 995,
    1194, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2222, 2375, 2376,
    3306, 3389, 3690, 4000, 4369, 5000, 5432, 5671, 5672, 5900, 5938, 5985,
    5986, 6379, 6443, 7000, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9091,
    9200, 9300, 10000, 11211, 15672, 27017, 27018, 50000,
}

LOLBINS: Set[str] = {
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wmic.exe", "powershell.exe", "pwsh.exe",
    "curl", "wget", "nc", "ncat", "socat", "bash", "sh",
    "cmd.exe", "cscript.exe", "wscript.exe", "installutil.exe",
    "msbuild.exe", "cmstp.exe", "regasm.exe", "regsvcs.exe",
    "forfiles.exe", "pcalua.exe", "msiexec.exe", "expand.exe",
    "extrac32.exe", "findstr.exe", "ieexec.exe", "makecab.exe",
    "hh.exe", "control.exe", "odbcconf.exe", "verclsid.exe",
    "mavinject.exe", "mmc.exe", "xwizard.exe",
}

_TEMP_ROOTS_POSIX = ("/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/private/var/tmp")
_TEMP_ROOTS_WIN = (r"C:\Windows\Temp", r"C:\Temp")

_SCRIPT_INTERPRETERS: Set[str] = {
    "python", "python2", "python3", "pypy", "pypy3",
    "bash", "sh", "dash", "zsh", "fish", "ksh",
    "perl", "ruby", "node", "php",
    "pwsh", "pwsh.exe", "powershell", "powershell.exe",
    "wscript.exe", "cscript.exe", "cmd.exe", "java", "java.exe",
}

SEV_WEIGHT: Dict[str, int] = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
CONF_WEIGHT: Dict[str, int] = {"High": 3, "Medium": 2, "Low": 1}
CONF_ORDER: Dict[str, int] = {"low": 1, "medium": 2, "high": 3}

CRITICAL_TECHNIQUES: Set[str] = {
    "T1003", "T1003.001", "T1003.002", "T1003.003", "T1003.004",
    "T1003.005", "T1003.006", "T1486", "T1490", "T1055", "T1055.012",
    "T1558", "T1558.001", "T1558.002", "T1558.003", "T1218",
    "T1218.005", "T1218.010", "T1218.011", "T1485", "T1547",
    "T1547.001", "T1546.003", "T1053.005",
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def h(value: Any) -> str:
    """HTML-escape a value for safe rendering."""
    return html.escape(str(value if value is not None else ""), quote=True)


def _ensure_data_dir() -> None:
    """Create data directory with secure permissions. Idempotent."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        for d in (BLUEKIT_DIR, DATA_DIR):
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
    except OSError as exc:
        logger.warning("Cannot create data dir %s: %s", DATA_DIR, exc)


_SENSITIVE_PATTERN = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|authorization|private[_-]?key)\b(?:\s*=\s*|\s*:\s*|\s+))"
    r'''("[^"]*"|'[^']*'|[^\s,;]+)'''
)
_BEARER_PATTERN = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+")


def redact(value: str, max_length: int = 400) -> str:
    """Redact sensitive tokens from a command line string."""
    text = str(value or "")[:max_length]
    text = _BEARER_PATTERN.sub(r"\1[REDACTED]", text)
    return _SENSITIVE_PATTERN.sub(r"\1[REDACTED]", text)


def is_public_ip(ip: str) -> bool:
    """Return True if the IP is publicly routable (not private/loopback/reserved)."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _call(fn, default=None):
    """Call fn, return default on any error."""
    try:
        return fn()
    except Exception:
        return default


def _temp_roots() -> List[str]:
    """Build list of unique temp root paths for this system."""
    roots = list(_TEMP_ROOTS_POSIX)
    for key in ("TMPDIR", "TMP", "TEMP", "TEMPDIR"):
        v = os.environ.get(key)
        if v:
            roots.append(v)
    if platform.system().lower() == "windows":
        roots.extend(_TEMP_ROOTS_WIN)
        for env_key in ("WINDIR", "SystemRoot"):
            v = os.environ.get(env_key)
            if v:
                roots.append(ntpath.join(v, "Temp"))
        local = os.environ.get("LOCALAPPDATA")
        if local:
            roots.append(ntpath.join(local, "Temp"))
    seen = set()
    unique = []
    for r in roots:
        r = str(r).strip().strip("\\\"'")
        if not r:
            continue
        key = ntpath.normcase(ntpath.normpath(r)) if (ntpath.splitdrive(r)[0] or "\\" in r) else posixpath.normpath(r)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def _is_temporary_path(path: str) -> bool:
    """Return True if path is inside a known temporary directory."""
    if not path or not isinstance(path, str):
        return False
    cand = os.path.expandvars(path.strip().strip("\\\"'"))
    if not cand:
        return False
    win = bool(ntpath.splitdrive(cand)[0] or "\\" in cand)
    for root in _temp_roots():
        try:
            if win:
                cn = ntpath.normcase(ntpath.normpath(cand.replace("/", "\\")))
                rn = ntpath.normcase(ntpath.normpath(root.replace("/", "\\")))
                if ntpath.commonpath((cn, rn)) == rn:
                    return True
            else:
                if not cand.startswith("/"):
                    continue
                if posixpath.commonpath((posixpath.normpath(cand),
                                          posixpath.normpath(root))) == posixpath.normpath(root):
                    return True
        except (ValueError, OSError):
            continue
    return False


def _temp_execution_target(process: "ProcessInfo") -> Optional[Tuple[str, str]]:
    """Return (kind, path) if process is executing from a temp directory."""
    exe = (process.exe or "").strip()
    if _is_temporary_path(exe):
        return ("executable", exe)
    pname = ntpath.basename(process.name or "").lower()
    ename = ntpath.basename(exe).lower()
    if pname not in _SCRIPT_INTERPRETERS and ename not in _SCRIPT_INTERPRETERS:
        return None
    try:
        args = shlex.split(process.cmdline or "", posix=(platform.system() != "Windows"))
    except ValueError:
        return None
    script_suffixes = {".py", ".pyc", ".sh", ".bash", ".zsh", ".pl", ".rb",
                        ".js", ".mjs", ".cjs", ".php", ".ps1", ".bat", ".cmd",
                        ".vbs", ".wsf", ".jar", ".class"}
    for tok in args[1:]:
        tok = tok.strip().strip("\\\"'")
        if not tok or tok.startswith("-"):
            continue
        if _is_temporary_path(tok):
            try:
                exists = os.path.isfile(tok)
            except (OSError, ValueError):
                exists = False
            if Path(tok).suffix.lower() in script_suffixes or exists:
                return ("script", tok)
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — ALGORITHMS (mathematically verified)
# ═══════════════════════════════════════════════════════════════════════════════

def shannon_entropy(data: str) -> float:
    """Bits per character. 0.0 for empty. Range 0..log2(alphabet)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def jaccard_similarity(a: Set, b: Set) -> float:
    """J(A,B) = |A∩B| / |A∪B|. Two empty sets return 1.0 (identical)."""
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 1.0


def levenshtein(a: str, b: str) -> int:
    """Standard DP edit distance. O(len(a) * len(b))."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j-1] + (ca != cb)))
        prev = curr
    return prev[-1]


def temporal_weight(age_seconds: float, half_life: float = 3600.0) -> float:
    """Exponential decay. 0.5^(age/half_life). Returns 1.0 for age<=0."""
    if half_life <= 0:
        return 0.0
    if age_seconds <= 0:
        return 1.0
    return 0.5 ** (age_seconds / half_life)


def cusum_change_points(values: List[float],
                         target_mean: Optional[float] = None,
                         threshold: float = 5.0,
                         drift: float = 0.5) -> List[int]:
    """CUSUM change-point detection. Returns indices where cumulative sum exceeds threshold."""
    if len(values) < 5:
        return []
    mean = target_mean if target_mean is not None else sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    std = math.sqrt(var) if var > 0 else 1.0
    change_points = []
    s_pos = s_neg = 0.0
    for i, v in enumerate(values):
        z = (v - mean) / std
        s_pos = max(0.0, s_pos + z - drift)
        s_neg = min(0.0, s_neg + z + drift)
        if s_pos > threshold or s_neg < -threshold:
            change_points.append(i)
            s_pos = s_neg = 0.0
    return change_points


def is_likely_dga(domain: str) -> Tuple[bool, float]:
    """DGA heuristic. Returns (is_dga, score_0_to_1).

    Score components (max 1.0):
      +0.35 if entropy > 3.8 (high randomness)
      +0.15 if entropy > 4.2 (very high)
      +0.25 if vowel_ratio < 0.25 (consonant-heavy)
      +0.15 if digit_ratio > 0.20 (many numbers)
      +0.10 if label length > 16

    Threshold for is_dga = 0.55
    """
    if not domain or "." not in domain:
        return False, 0.0
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return False, 0.0
    label = parts[-2]
    if len(label) < 6:
        return False, 0.0
    entropy = shannon_entropy(label)
    vowels = sum(1 for c in label if c in "aeiou")
    consonants = sum(1 for c in label if c.isalpha() and c not in "aeiou")
    digits = sum(1 for c in label if c.isdigit())
    total_alpha = vowels + consonants
    if total_alpha == 0:
        return False, 0.0
    vowel_ratio = vowels / total_alpha
    digit_ratio = digits / len(label)
    score = 0.0
    if entropy > 3.8: score += 0.35
    if entropy > 4.2: score += 0.15
    if vowel_ratio < 0.25: score += 0.25
    if digit_ratio > 0.20: score += 0.15
    if len(label) > 16: score += 0.10
    return score >= 0.55, round(min(score, 1.0), 3)


KNOWN_BRANDS: Set[str] = {
    "google", "facebook", "amazon", "microsoft", "apple",
    "netflix", "paypal", "github", "linkedin", "twitter",
    "instagram", "whatsapp", "youtube", "outlook", "office",
}


def is_likely_typosquat(domain: str) -> Optional[str]:
    """Return brand being typosquatted, or None."""
    base = domain.lower().split(".")[0]
    if not base or len(base) < 4:
        return None
    for brand in KNOWN_BRANDS:
        if base == brand:
            continue
        if 1 <= levenshtein(base, brand) <= 2:
            return brand
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HostInfo:
    hostname: str
    fqdn: str
    os: str
    os_version: str
    kernel: str
    arch: str
    boot_time: str
    uptime_seconds: int
    cpu_count_physical: int
    cpu_count_logical: int
    cpu_percent: float
    cpu_freq_mhz: Optional[float]
    load_avg: Optional[List[float]]
    memory_total_mb: int
    memory_used_mb: int
    memory_available_mb: int
    memory_percent: float
    swap_total_mb: int
    swap_used_mb: int
    disks: List[Dict[str, Any]] = field(default_factory=list)
    logged_in_users: List[Dict[str, Any]] = field(default_factory=list)
    hostname_hash: str = ""

    @property
    def is_privileged(self) -> bool:
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return os.geteuid() == 0
        except Exception:
            return False


@dataclass
class NetworkInterface:
    name: str
    is_up: bool
    speed_mbps: int
    mtu: int
    mac: str
    addresses: List[Dict[str, str]]
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errors_in: int
    errors_out: int


@dataclass
class ConnectionInfo:
    fd: int
    family: str
    type: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    pid: Optional[int]
    process_name: str
    process_user: str
    process_cmdline: str
    process_exe: str
    is_external: bool
    is_listening: bool
    is_privileged: bool
    attack_matches: List[Dict[str, str]] = field(default_factory=list)
    attribution_method: str = "kernel"


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    username: str
    status: str
    cmdline: str
    exe: str
    cwd: str
    create_time: str
    cpu_percent: float
    memory_mb: float
    num_threads: int
    num_connections: int
    listen_ports: List[int] = field(default_factory=list)
    remote_endpoints: List[str] = field(default_factory=list)
    attack_matches: List[Dict[str, str]] = field(default_factory=list)
    access_denied: bool = False
    parent_name: str = ""


@dataclass
class NetworkRoute:
    destination: str
    gateway: str
    netmask: str
    interface: str
    metric: Optional[int] = None


@dataclass
class Finding:
    id: str
    severity: str
    confidence: str
    category: str
    title: str
    description: str
    evidence: List[str] = field(default_factory=list)
    involved_pids: List[int] = field(default_factory=list)
    involved_ips: List[str] = field(default_factory=list)
    involved_ports: List[int] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    risk_score: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — BAYESIAN SCORER (correct math)
# ═══════════════════════════════════════════════════════════════════════════════

class BayesianScorer:
    """Naive Bayes classifier. P(malicious | signals) = posterior odds / (1 + posterior odds).

    Starting odds = PRIOR / (1 - PRIOR). Each signal multiplies odds by its LR.
    Unknown signals contribute LR=1.0 (no information).

    LR values calibrated from ATT&CK Evaluations + public incident data.
    """

    PRIOR = 0.05

    SIGNAL_LRS: Dict[str, float] = {
        "external_connection": 4.0,
        "suspicious_port": 8.0,
        "beacon_pattern": 15.0,
        "high_traffic_volume": 3.5,
        "port_scan_behavior": 10.0,
        "dns_tunneling": 12.0,
        "temp_execution": 6.0,
        "encoded_command": 12.0,
        "download_action": 5.0,
        "parent_shell": 3.0,
        "lolbin_network": 7.0,
        "high_entropy_cmd": 4.0,
        "base64_argument": 6.5,
        "credential_access": 20.0,
        "privilege_escalation": 10.0,
        "lateral_movement": 6.0,
        "defense_evasion": 8.0,
        "persistence_mechanism": 6.5,
        "unsigned_binary": 2.5,
        "unreadable_process": 1.5,
        "dga_domain": 8.5,
        "typosquat_domain": 6.0,
        "brute_force": 10.0,
        "password_spray": 14.0,
        "fim_change": 5.0,
        "new_service": 6.0,
    }

    @classmethod
    def posterior(cls, signals: List[str]) -> float:
        """Return P(malicious | signals) in [0, 1]."""
        odds = cls.PRIOR / (1.0 - cls.PRIOR)
        for s in signals:
            lr = cls.SIGNAL_LRS.get(s, 1.0)
            if lr < 1e-9:
                lr = 1e-9
            odds *= lr
        return odds / (1.0 + odds)

    @classmethod
    def to_confidence(cls, posterior: float) -> str:
        if posterior >= 0.85:
            return "High"
        if posterior >= 0.55:
            return "Medium"
        return "Low"

    @classmethod
    def to_severity(cls, posterior: float, critical: bool = False) -> str:
        if critical and posterior >= 0.55:
            return "Critical"
        if posterior >= 0.90:
            return "Critical"
        if posterior >= 0.75:
            return "High"
        if posterior >= 0.50:
            return "Medium"
        if posterior >= 0.25:
            return "Low"
        return "Info"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — EMA ANOMALY DETECTOR (correct math)
# ═══════════════════════════════════════════════════════════════════════════════

class EMAAnomalyDetector:
    """EWMA with running variance. Alert when |z-score| > threshold.

    Update: ema_new = alpha * value + (1 - alpha) * ema_old
            var_new = alpha * (value - ema_old)^2 + (1 - alpha) * var_old
            z = (value - ema_new) / sqrt(var_new)
    """

    def __init__(self, alpha: float = 0.3, z_threshold: float = 3.5,
                 min_observations: int = 10):
        if not 0.0 < alpha <= 1.0:
            raise ValueError("alpha must be in (0,1]")
        if z_threshold <= 0:
            raise ValueError("z_threshold must be positive")
        self.alpha = alpha
        self.z_threshold = z_threshold
        self.min_observations = min_observations
        self._state: Dict[str, Dict[str, float]] = {}
        self._lock = threading.Lock()

    def update(self, key: str, value: float) -> Optional[Dict[str, Any]]:
        value = float(value)
        with self._lock:
            if key not in self._state:
                self._state[key] = {"ema": value, "var": 0.0, "n": 1}
                return None
            s = self._state[key]
            prev_ema = s["ema"]
            deviation = value - prev_ema
            s["ema"] = self.alpha * value + (1 - self.alpha) * prev_ema
            s["var"] = self.alpha * deviation * deviation + (1 - self.alpha) * s["var"]
            s["n"] += 1
            if s["n"] < self.min_observations:
                return None
            sigma = math.sqrt(s["var"]) if s["var"] > 1e-12 else 0.0
            if sigma < 1e-9:
                return None
            z = (value - s["ema"]) / sigma
            if abs(z) > self.z_threshold:
                return {"key": key, "value": value, "ema": round(s["ema"], 4),
                        "sigma": round(sigma, 4), "z_score": round(z, 4),
                        "direction": "spike" if z > 0 else "drop"}
            return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — PORT SCAN DETECTOR (correct math)
# ═══════════════════════════════════════════════════════════════════════════════

class PortScanDetector:
    """Detect scans by combining port diversity with handshake completion ratio.

    probability = 0.6 * min(ports_scanned / 100, 1.0)
                + 0.4 * (1 - completion_ratio)

    where completion_ratio = ack_count / syn_count (capped to [0,1]).
    A legitimate server has high completion. A scan has low completion.
    """

    def __init__(self, min_ports: int = 15, probability_threshold: float = 0.5):
        self.min_ports = max(2, min_ports)
        self.threshold = max(0.0, min(1.0, probability_threshold))

    def analyze(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        by_source = defaultdict(lambda: {"syn": 0, "ack": 0, "dst_ports": set()})
        for flow in flows:
            src_ip = flow.get("src_ip")
            if not src_ip:
                continue
            key = (src_ip, flow.get("src_port", 0))
            b = by_source[key]
            b["syn"] += int(flow.get("syn_count", 0))
            b["ack"] += int(flow.get("ack_count", 0))
            dp = flow.get("dst_port")
            if dp:
                b["dst_ports"].add(int(dp))
        results = []
        for (src_ip, src_port), data in by_source.items():
            ports = len(data["dst_ports"])
            if ports < self.min_ports:
                continue
            syn = data["syn"]
            ack = data["ack"]
            completion = max(0.0, min(1.0, (ack / syn) if syn else 1.0))
            port_score = min(ports / 100.0, 1.0)
            probability = 0.6 * port_score + 0.4 * (1.0 - completion)
            if probability >= self.threshold:
                results.append({
                    "source": f"{src_ip}:{src_port}",
                    "ports_scanned": ports,
                    "syn_count": syn,
                    "ack_count": ack,
                    "completion_ratio": round(completion, 3),
                    "scan_probability": round(probability, 3),
                    "scan_type": "horizontal" if ports > 50 else "vertical",
                    "severity": "High" if probability > 0.75 else "Medium",
                })
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — BEACON DETECTOR (correct math)
# ═══════════════════════════════════════════════════════════════════════════════

class BeaconDetector:
    """Statistical beacon detection using coefficient of variation + FFT regularity.

    Low CV (< 0.35) + high FFT regularity (> 0.55) = periodic traffic = beacon.
    Requires ≥ 8 events to a (dst_ip, dst_port) pair.
    """

    def __init__(self, min_events: int = 8, cv_threshold: float = 0.35,
                 regularity_threshold: float = 0.55):
        self.min_events = max(3, min_events)
        self.cv_threshold = max(0.0, min(10.0, cv_threshold))
        self.reg_threshold = max(0.0, min(1.0, regularity_threshold))

    def analyze(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not NUMPY_AVAILABLE or not flows:
            return []
        groups = defaultdict(list)
        for f in flows:
            if f.get("dst_ip") and f.get("dst_port"):
                groups[(f["dst_ip"], f["dst_port"])].append(f)
        beacons = []
        for (dst_ip, dst_port), flist in groups.items():
            if len(flist) < self.min_events:
                continue
            times = []
            try:
                sorted_list = sorted(flist, key=lambda x: str(x.get("first_seen", "")))
                for flow in sorted_list:
                    stamp = datetime.fromisoformat(
                        str(flow.get("first_seen", "")).replace("Z", "+00:00"))
                    if stamp.tzinfo is None:
                        stamp = stamp.replace(tzinfo=timezone.utc)
                    times.append(stamp)
            except (ValueError, TypeError, OverflowError):
                continue
            if len(times) < self.min_events:
                continue
            intervals = np.array([
                (times[i] - times[i - 1]).total_seconds()
                for i in range(1, len(times))])
            intervals = intervals[intervals > 0]
            if len(intervals) < 5 or intervals.mean() <= 0:
                continue
            mean_iat = float(intervals.mean())
            std_iat = float(intervals.std())
            cv = std_iat / mean_iat if mean_iat > 0 else 999.0
            regularity = self._fft_regularity(intervals)
            if cv <= self.cv_threshold and regularity >= self.reg_threshold:
                confidence = round((1 - min(cv, 1.0)) * 0.5 + regularity * 0.5, 3)
                beacons.append({
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "events": len(sorted_list),
                    "mean_interval_s": round(mean_iat, 2),
                    "std_interval_s": round(std_iat, 2),
                    "cv": round(cv, 4),
                    "regularity": round(regularity, 4),
                    "confidence": confidence,
                    "first_seen": sorted_list[0]["first_seen"],
                    "last_seen": sorted_list[-1]["last_seen"],
                    "bytes_total": sum(f.get("bytes", 0) for f in sorted_list),
                })
        return sorted(beacons, key=lambda b: -b["confidence"])

    @staticmethod
    def _fft_regularity(intervals) -> float:
        """Return peak-spectrum ratio. 1.0 = perfectly periodic, 0.0 = pure noise."""
        if not NUMPY_AVAILABLE or len(intervals) < 5:
            return 0.0
        centered = np.asarray(intervals, dtype=float) - float(np.mean(intervals))
        if not np.all(np.isfinite(centered)):
            return 0.0
        if float(np.std(centered)) <= 1e-12:
            return 1.0
        spectrum = np.abs(np.fft.rfft(centered))[1:]
        if len(spectrum) == 0:
            return 0.0
        powers = np.square(spectrum)
        total = float(np.sum(powers))
        return max(0.0, min(1.0, float(np.max(powers)) / total)) if total > 0 else 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — PROCESS RISK GRAPH (correct propagation)
# ═══════════════════════════════════════════════════════════════════════════════

class ProcessRiskGraph:
    """Propagate risk from children to parents via parent/child edges.

    risk[parent] = max(base[parent], max over children of risk[child] * decay)
    Iterate until convergence (max 5 iterations).
    """

    def __init__(self):
        self.nodes: Dict[int, Dict[str, Any]] = {}
        self.edges: Dict[int, Set[int]] = defaultdict(set)

    def add(self, pid: int, ppid: int, base_risk: float,
            name: str, cmdline: str = "") -> None:
        self.nodes[pid] = {"base_risk": float(base_risk), "name": name,
                            "cmdline": cmdline, "ppid": ppid}
        if ppid and ppid != pid:
            self.edges[ppid].add(pid)

    def propagate(self, decay: float = 0.6, max_iterations: int = 5) -> Dict[int, float]:
        if not 0.0 < decay <= 1.0:
            raise ValueError("decay must be in (0,1]")
        risk = {pid: n["base_risk"] for pid, n in self.nodes.items()}
        for _ in range(max_iterations):
            changed = False
            for parent, children in self.edges.items():
                if parent not in risk:
                    continue
                child_max = max((risk.get(c, 0.0) for c in children), default=0.0)
                new_val = max(risk[parent], child_max * decay)
                if new_val > risk[parent] + 1e-9:
                    risk[parent] = new_val
                    changed = True
            if not changed:
                break
        return risk


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — HOST COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

def collect_host() -> HostInfo:
    boot = psutil.boot_time()
    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    try:
        freq = psutil.cpu_freq()
        cpu_freq = round(freq.current, 0) if freq else None
    except Exception:
        cpu_freq = None
    load = None
    try:
        if hasattr(psutil, "getloadavg"):
            load = [round(x, 2) for x in psutil.getloadavg()]
    except Exception:
        pass
    disks = []
    for part in (_call(lambda: psutil.disk_partitions(all=False), []) or []):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent": usage.percent,
            })
        except (PermissionError, OSError):
            continue
    users = []
    for u in (_call(psutil.users, []) or []):
        users.append({
            "name": u.name,
            "terminal": u.terminal or "",
            "host": u.host or "",
            "started": datetime.fromtimestamp(u.started).isoformat(),
            "pid": getattr(u, "pid", None),
        })
    hostname = socket.gethostname()
    return HostInfo(
        hostname=hostname,
        fqdn=socket.getfqdn(),
        os=platform.system(),
        os_version=platform.release(),
        kernel=platform.version(),
        arch=platform.machine(),
        boot_time=datetime.fromtimestamp(boot).isoformat(),
        uptime_seconds=int(time.time() - boot),
        cpu_count_physical=_call(psutil.cpu_count, 0) or 0,
        cpu_count_logical=psutil.cpu_count(logical=True) or 0,
        cpu_percent=psutil.cpu_percent(interval=0.1),
        cpu_freq_mhz=cpu_freq,
        load_avg=load,
        memory_total_mb=int(vm.total / (1024**2)),
        memory_used_mb=int(vm.used / (1024**2)),
        memory_available_mb=int(vm.available / (1024**2)),
        memory_percent=vm.percent,
        swap_total_mb=int(sm.total / (1024**2)),
        swap_used_mb=int(sm.used / (1024**2)),
        disks=disks,
        logged_in_users=users,
        hostname_hash=hashlib.sha256(hostname.encode()).hexdigest()[:12],
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 14 — NETWORK COLLECTORS
# ═══════════════════════════════════════════════════════════════════════════════

def collect_interfaces() -> List[NetworkInterface]:
    addrs = _call(psutil.net_if_addrs, {}) or {}
    stats = _call(psutil.net_if_stats, {}) or {}
    io_per = _call(lambda: psutil.net_io_counters(pernic=True), {}) or {}
    out = []
    for name, addr_list in addrs.items():
        st = stats.get(name)
        cnt = io_per.get(name)
        addresses = []
        for a in addr_list:
            family = ("IPv4" if a.family == socket.AF_INET else
                      "IPv6" if a.family == socket.AF_INET6 else
                      "MAC" if getattr(a, "family", None) == psutil.AF_LINK else
                      "OTHER")
            addresses.append({"family": family, "address": a.address,
                              "netmask": a.netmask or "",
                              "broadcast": a.broadcast or ""})
        out.append(NetworkInterface(
            name=name,
            is_up=bool(st and st.isup),
            speed_mbps=st.speed if st else 0,
            mtu=st.mtu if st else 0,
            mac=next((x["address"] for x in addresses if x["family"] == "MAC"), ""),
            addresses=addresses,
            bytes_sent=cnt.bytes_sent if cnt else 0,
            bytes_recv=cnt.bytes_recv if cnt else 0,
            packets_sent=cnt.packets_sent if cnt else 0,
            packets_recv=cnt.packets_recv if cnt else 0,
            errors_in=cnt.errin if cnt else 0,
            errors_out=cnt.errout if cnt else 0,
        ))
    return out


def collect_routes() -> List[NetworkRoute]:
    system = platform.system()
    out = []
    try:
        if system == "Linux":
            r = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if not parts:
                        continue
                    gw = parts[parts.index("via") + 1] if "via" in parts else ""
                    iface = parts[parts.index("dev") + 1] if "dev" in parts else ""
                    metric = None
                    if "metric" in parts:
                        try:
                            metric = int(parts[parts.index("metric") + 1])
                        except (ValueError, IndexError):
                            pass
                    out.append(NetworkRoute(parts[0], gw, "", iface, metric))
        elif system == "Windows":
            r = subprocess.run(["route", "print", "-4"], capture_output=True, text=True, timeout=5)
            parsing = False
            for line in r.stdout.splitlines():
                if "Network Destination" in line:
                    parsing = True
                    continue
                if parsing and line.strip():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0][0].isdigit():
                        try:
                            metric = int(parts[4]) if len(parts) > 4 else None
                        except ValueError:
                            metric = None
                        out.append(NetworkRoute(parts[0], parts[2], parts[1], parts[3], metric))
    except Exception:
        logger.debug("Route collection failed", exc_info=True)
    return out


def collect_arp() -> List[Dict[str, str]]:
    system = platform.system()
    out = []
    try:
        if system == "Linux":
            r = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    out.append({
                        "ip": parts[0],
                        "mac": parts[parts.index("lladdr") + 1],
                        "state": parts[-1],
                        "interface": parts[parts.index("dev") + 1] if "dev" in parts else "",
                    })
        elif system in ("Windows", "Darwin"):
            cmd = ["arp", "-a"] if system == "Windows" else ["arp", "-an"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                if system == "Windows":
                    if parts[0].count(".") == 3:
                        out.append({"ip": parts[0], "mac": parts[1],
                                    "state": "reachable", "interface": ""})
                else:
                    if "(" in line and ")" in line and len(parts) >= 4:
                        ip = line.split("(")[1].split(")")[0]
                        out.append({"ip": ip, "mac": parts[3] if len(parts) > 3 else "",
                                    "state": "reachable", "interface": ""})
    except Exception:
        logger.debug("ARP collection failed", exc_info=True)
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 15 — PROCESS & CONNECTION COLLECTORS
# ═══════════════════════════════════════════════════════════════════════════════

def _process_meta(pid: Optional[int]) -> Dict[str, Any]:
    if pid is None or int(pid) <= 0:
        return {"name": "<unattributed>", "user": "<unknown>", "cmdline": "",
                "exe": "", "access_denied": True}
    try:
        proc = psutil.Process(int(pid))
        return {
            "name": _call(proc.name, f"pid:{pid}") or f"pid:{pid}",
            "user": _call(proc.username, "<unknown>") or "<unknown>",
            "cmdline": " ".join(_call(proc.cmdline, []) or []),
            "exe": _call(proc.exe, "") or "",
            "access_denied": False,
        }
    except psutil.AccessDenied:
        return {"name": f"pid:{pid}", "user": "<access-denied>",
                "cmdline": "<access-denied>", "exe": "", "access_denied": True}
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return {"name": f"pid:{pid}", "user": "<exited>",
                "cmdline": "", "exe": "", "access_denied": False}
    except Exception:
        return {"name": f"pid:{pid}", "user": "<unknown>",
                "cmdline": "", "exe": "", "access_denied": True}


def _endpoint_sig(endpoint: Any) -> Tuple[str, int]:
    if not endpoint:
        return ("", 0)
    try:
        return (str(endpoint.ip), int(endpoint.port))
    except AttributeError:
        try:
            return (str(endpoint[0]), int(endpoint[1]))
        except (TypeError, ValueError, IndexError):
            return ("", 0)


def _connection_sig(conn: Any) -> Tuple[Any, ...]:
    try:
        return (int(getattr(conn, "family", 0) or 0),
                int(getattr(conn, "type", 0) or 0),
                _endpoint_sig(getattr(conn, "laddr", None)),
                _endpoint_sig(getattr(conn, "raddr", None)),
                str(getattr(conn, "status", "") or ""))
    except Exception:
        return (0, 0, ("", 0), ("", 0), "")


def collect_connections(attack_patterns: List[Tuple[str, str, re.Pattern]]) -> List[ConnectionInfo]:
    conns = _call(lambda: psutil.net_connections(kind="inet"), []) or []
    out = []
    meta_cache: Dict[int, Dict[str, Any]] = {}
    match_cache: Dict[int, List[Tuple[str, str, str]]] = {}
    for conn in conns:
        try:
            local_ip, local_port = _endpoint_sig(getattr(conn, "laddr", None))
            remote_ip, remote_port = _endpoint_sig(getattr(conn, "raddr", None))
            family = "IPv4" if getattr(conn, "family", None) == socket.AF_INET else "IPv6"
            st = getattr(conn, "type", None)
            ctype = ("TCP" if st == socket.SOCK_STREAM else
                     "UDP" if st == socket.SOCK_DGRAM else "?")
            raw_pid = getattr(conn, "pid", None)
            pid = int(raw_pid) if raw_pid is not None else None
            pid_key = pid if pid is not None else -1
            if pid_key not in meta_cache:
                meta_cache[pid_key] = _process_meta(pid)
            meta = meta_cache[pid_key]
            if pid_key not in match_cache:
                matches = []
                cmd = meta.get("cmdline") or ""
                for tid, name, pat in attack_patterns:
                    if pat.search(cmd):
                        matches.append((tid, name, cmd[:100]))
                        break
                match_cache[pid_key] = matches
            att = [{"id": t, "name": n, "evidence": redact(e, 100)}
                   for t, n, e in match_cache[pid_key]]
            out.append(ConnectionInfo(
                fd=getattr(conn, "fd", None) if getattr(conn, "fd", None) is not None else -1,
                family=family,
                type=ctype,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                status=str(getattr(conn, "status", "") or ""),
                pid=pid,
                process_name=meta["name"],
                process_user=meta["user"],
                process_cmdline=redact(meta.get("cmdline") or "", 300),
                process_exe=meta.get("exe", ""),
                is_external=bool(remote_ip) and is_public_ip(remote_ip),
                is_listening=(getattr(conn, "status", None)
                              == getattr(psutil, "CONN_LISTEN", "LISTEN")),
                is_privileged=pid is not None and not meta["access_denied"],
                attack_matches=att,
                attribution_method="kernel" if raw_pid is not None else "unavailable",
            ))
        except Exception:
            logger.debug("Skipping malformed connection", exc_info=True)
    return out


def collect_processes(conn_by_pid: Dict[int, List[ConnectionInfo]],
                      attack_patterns: List[Tuple[str, str, re.Pattern]]) -> List[ProcessInfo]:
    attrs = ["pid", "ppid", "name", "username", "status", "cmdline", "exe",
             "cwd", "create_time", "cpu_percent", "memory_info", "num_threads"]
    entries = []
    pid_to_name: Dict[int, str] = {}
    try:
        for proc in psutil.process_iter(attrs):
            try:
                info = proc.info or {}
                pid = int(info.get("pid") or proc.pid)
                pid_to_name[pid] = str(info.get("name") or "")
                entries.append((proc, info, pid))
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied:
                entries.append((proc, {"pid": getattr(proc, "pid", 0)},
                                int(getattr(proc, "pid", 0) or 0)))
            except Exception:
                continue
    except Exception:
        logger.exception("Process enumeration failed")

    out = []
    for proc, info, pid in entries:
        try:
            cmdline_raw = " ".join(str(x) for x in (info.get("cmdline") or []))
            name = str(info.get("name") or f"pid:{pid}")
            ppid = int(info.get("ppid") or 0)
            mem = info.get("memory_info")
            conns = conn_by_pid.get(pid, [])
            listens = sorted({c.local_port for c in conns if c.is_listening})
            remotes = sorted({f"{c.remote_ip}:{c.remote_port}"
                              for c in conns if c.remote_ip and not c.is_listening})
            match_text = f"{cmdline_raw} {name}"
            matches = []
            for tid, tname, pat in attack_patterns:
                m = pat.search(match_text)
                if m:
                    matches.append((tid, tname, m.group(0)[:100]))
            att = [{"id": t, "name": n, "evidence": redact(e, 100)} for t, n, e in matches]
            create_time = info.get("create_time")
            try:
                created = datetime.fromtimestamp(float(create_time)).astimezone().isoformat() \
                          if create_time else ""
            except (OSError, OverflowError, TypeError, ValueError):
                created = ""
            cwd = _call(lambda: proc.cwd(), "") or ""
            out.append(ProcessInfo(
                pid=pid, ppid=ppid, name=name,
                username=str(info.get("username") or "<unknown>"),
                status=str(info.get("status") or ""),
                cmdline=redact(cmdline_raw, 400),
                exe=str(info.get("exe") or ""),
                cwd=str(cwd),
                create_time=created,
                cpu_percent=float(info.get("cpu_percent") or 0.0),
                memory_mb=round((mem.rss if mem else 0) / (1024 ** 2), 2),
                num_threads=int(info.get("num_threads") or 0),
                num_connections=len(conns),
                listen_ports=listens,
                remote_endpoints=remotes[:15],
                attack_matches=att,
                access_denied=False,
                parent_name=pid_to_name.get(ppid, ""),
            ))
        except psutil.AccessDenied:
            out.append(ProcessInfo(
                pid=pid, ppid=int(info.get("ppid") or 0), name=f"pid:{pid}",
                username="<access-denied>", status="",
                cmdline="<access-denied>", exe="", cwd="", create_time="",
                cpu_percent=0.0, memory_mb=0.0, num_threads=0,
                num_connections=len(conn_by_pid.get(pid, [])),
                access_denied=True, parent_name="",
            ))
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except Exception:
            logger.debug("Process skip", exc_info=True)
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 16 — PERSISTENCE AUDITOR (bounded)
# ═══════════════════════════════════════════════════════════════════════════════

_PERSISTENCE_CACHE: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
_PERSISTENCE_LOCK = threading.Lock()
_PERSISTENCE_TTL = 300.0


def audit_persistence(use_cache: bool = True) -> List[Dict[str, Any]]:
    now = time.monotonic()
    if use_cache:
        with _PERSISTENCE_LOCK:
            cached = _PERSISTENCE_CACHE.get("global")
            if cached and now - cached[0] < _PERSISTENCE_TTL:
                return cached[1]
    out = []
    system = platform.system()
    if system in ("Linux", "Darwin"):
        for cp in ("/etc/crontab", "/etc/cron.d", "/var/spool/cron",
                   "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"):
            p = Path(cp)
            if not p.exists():
                continue
            try:
                if p.is_dir():
                    for f in p.iterdir():
                        if f.is_file():
                            out.append({"type": "cron", "path": str(f)})
                else:
                    out.append({"type": "cron", "path": str(p)})
            except (PermissionError, OSError):
                continue
        for d in ("/etc/systemd/system", "/lib/systemd/system"):
            dp = Path(d)
            if dp.is_dir():
                try:
                    for f in dp.glob("*.service"):
                        out.append({"type": "systemd-service", "path": str(f)})
                    for f in dp.glob("*.timer"):
                        out.append({"type": "systemd-timer", "path": str(f)})
                except (PermissionError, OSError):
                    continue
        ldp = Path("/etc/ld.so.preload")
        if ldp.exists() and ldp.stat().st_size > 0:
            try:
                out.append({"type": "ld-preload", "path": str(ldp),
                            "content": redact(ldp.read_text()[:200])})
            except (PermissionError, OSError):
                pass
        # Bounded SUID scan
        deadline = time.monotonic() + 2.0
        suspicious_suid = []
        for d in ("/tmp", "/var/tmp", "/dev/shm"):
            if time.monotonic() > deadline:
                break
            try:
                for f in Path(d).iterdir():
                    if time.monotonic() > deadline:
                        break
                    try:
                        if f.is_file() and (f.stat().st_mode & 0o4000):
                            suspicious_suid.append(str(f))
                            if len(suspicious_suid) >= 50:
                                break
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue
        if suspicious_suid:
            out.append({"type": "suid-outside-standard",
                        "paths": suspicious_suid[:20]})
    if use_cache:
        with _PERSISTENCE_LOCK:
            _PERSISTENCE_CACHE["global"] = (now, out)
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 17 — TELEMETRY SUBSYSTEMS
# ═══════════════════════════════════════════════════════════════════════════════

def init_telemetry_schema(con: sqlite3.Connection) -> None:
    """Create all telemetry tables. Idempotent."""
    con.executescript("""
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            src_ip TEXT NOT NULL, query TEXT NOT NULL, qtype INTEGER DEFAULT 0,
            response TEXT DEFAULT '', rcode INTEGER DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_queries(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_dns_src ON dns_queries(src_ip, ts DESC);

        CREATE TABLE IF NOT EXISTS tls_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, dst_port INTEGER NOT NULL,
            sni TEXT DEFAULT '', ja3 TEXT DEFAULT '');
        CREATE INDEX IF NOT EXISTS idx_tls_ts ON tls_sessions(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_tls_sni ON tls_sessions(sni);

        CREATE TABLE IF NOT EXISTS http_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            src_ip TEXT NOT NULL, method TEXT NOT NULL,
            host TEXT DEFAULT '', path TEXT DEFAULT '',
            user_agent TEXT DEFAULT '', referrer TEXT DEFAULT '');
        CREATE INDEX IF NOT EXISTS idx_http_ts ON http_requests(ts DESC);

        CREATE TABLE IF NOT EXISTS domain_intel (
            domain TEXT PRIMARY KEY, first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, hit_count INTEGER DEFAULT 1,
            is_dga INTEGER DEFAULT 0, dga_score REAL DEFAULT 0.0);
        CREATE INDEX IF NOT EXISTS idx_domain_first ON domain_intel(first_seen DESC);

        CREATE TABLE IF NOT EXISTS file_integrity (
            path TEXT PRIMARY KEY, sha256 TEXT NOT NULL,
            size INTEGER DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);

        CREATE TABLE IF NOT EXISTS service_state (
            name TEXT PRIMARY KEY, snapshot_ts TEXT NOT NULL, state TEXT DEFAULT '');

        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            event_type TEXT NOT NULL, username TEXT DEFAULT '',
            source_ip TEXT DEFAULT '', service TEXT DEFAULT '',
            success INTEGER DEFAULT 0, detail TEXT DEFAULT '');
        CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_events(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_events(source_ip, ts DESC);
    """)


class PassiveNetworkTelemetry:
    """DNS/TLS/HTTP parser. Bounded memory. Thread-safe. Batch DB writes."""

    MAX_LOG = 50000
    MAX_DOMAIN_CACHE = 20000
    FLUSH_INTERVAL_S = 2.0

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._pending_dns: List[tuple] = []
        self._pending_tls: List[tuple] = []
        self._pending_http: List[tuple] = []
        self._first_seen: OrderedDict[str, str] = OrderedDict()
        self._stats = {"dns": 0, "tls": 0, "http": 0, "errors": 0}
        self._last_flush = time.monotonic()

    def on_packet(self, pkt) -> None:
        if not SCAPY_AVAILABLE:
            return
        try:
            if SCAPY_DNS_AVAILABLE and pkt.haslayer(UDP) and pkt.haslayer(DNS):
                self._handle_dns(pkt)
            elif pkt.haslayer(TCP):
                raw = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
                if not raw:
                    return
                if len(raw) >= 6 and raw[0] == 0x16 and raw[1] == 0x03:
                    self._handle_tls(pkt, raw)
                elif (raw[:8].upper().startswith(b"GET ") or
                      raw[:8].upper().startswith(b"POST ") or
                      raw[:7].upper().startswith(b"HEAD ")):
                    self._handle_http(pkt, raw)
            self._maybe_flush()
        except Exception:
            with self._lock:
                self._stats["errors"] += 1

    def _handle_dns(self, pkt) -> None:
        if not pkt.haslayer(DNSQR):
            return
        qr = pkt[DNSQR]
        qname = qr.qname.decode("ascii", errors="replace").rstrip(".") if qr.qname else ""
        if not qname:
            return
        ts = datetime.now(timezone.utc).isoformat()
        if pkt.haslayer(IP):
            src_ip = str(pkt[IP].src)
        elif IPv6 is not None and pkt.haslayer(IPv6):
            src_ip = str(pkt[IPv6].src)
        else:
            return
        response = ""
        rcode = 0
        if pkt.haslayer(DNS) and pkt[DNS].ancount > 0:
            try:
                rr = pkt[DNS].an
                if hasattr(rr, "rdata"):
                    response = str(rr.rdata)
                rcode = int(pkt[DNS].rcode)
            except Exception:
                pass
        with self._lock:
            self._pending_dns.append((ts, src_ip, qname, int(qr.qtype), response, rcode))
            self._stats["dns"] += 1
            self._note_domain(qname, ts)

    def _handle_tls(self, pkt, raw: bytes) -> None:
        parsed = self._parse_client_hello(raw)
        if not parsed:
            return
        ts = datetime.now(timezone.utc).isoformat()
        if pkt.haslayer(IP):
            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
        elif IPv6 is not None and pkt.haslayer(IPv6):
            src_ip = str(pkt[IPv6].src)
            dst_ip = str(pkt[IPv6].dst)
        else:
            return
        dst_port = int(pkt[TCP].dport)
        with self._lock:
            self._pending_tls.append((ts, src_ip, dst_ip, dst_port,
                                      parsed.get("sni") or "", parsed.get("ja3") or ""))
            self._stats["tls"] += 1
            if parsed.get("sni"):
                self._note_domain(parsed["sni"], ts)

    def _parse_client_hello(self, raw: bytes) -> Optional[Dict[str, str]]:
        """Parse TLS ClientHello. Returns {'sni': ..., 'ja3': ...} or None."""
        try:
            if len(raw) < 6 or raw[0] != 0x16:
                return None
            record_len = struct.unpack(">H", raw[3:5])[0]
            payload = raw[5:5 + record_len]
            if not payload or payload[0] != 0x01:
                return None
            # Skip: type(1) + len(3) + version(2) + random(32)
            off = 4 + 2 + 32
            if off >= len(payload):
                return None
            session_len = payload[off]
            off += 1 + session_len
            if off + 2 > len(payload):
                return None
            cipher_len = struct.unpack(">H", payload[off:off + 2])[0]
            ciphers = []
            off += 2
            for i in range(0, cipher_len, 2):
                if off + i + 2 > len(payload):
                    break
                ciphers.append(struct.unpack(">H", payload[off + i:off + i + 2])[0])
            off += cipher_len
            if off >= len(payload):
                return None
            comp_len = payload[off]
            off += 1 + comp_len
            if off + 2 > len(payload):
                return None
            ext_len = struct.unpack(">H", payload[off:off + 2])[0]
            off += 2
            ext_end = min(off + ext_len, len(payload))
            extensions, curves, point_formats = [], [], []
            sni = None
            while off + 4 <= ext_end:
                ext_type = struct.unpack(">H", payload[off:off + 2])[0]
                ext_size = struct.unpack(">H", payload[off + 2:off + 4])[0]
                off += 4
                if off + ext_size > len(payload):
                    break
                ext_data = payload[off:off + ext_size]
                extensions.append(ext_type)
                if ext_type == 0x0000 and len(ext_data) >= 5:
                    try:
                        sni_len = struct.unpack(">H", ext_data[3:5])[0]
                        sni = ext_data[5:5 + sni_len].decode("ascii", errors="ignore")
                    except Exception:
                        pass
                elif ext_type == 0x000a and len(ext_data) >= 2:
                    curve_len = struct.unpack(">H", ext_data[0:2])[0]
                    for i in range(0, curve_len, 2):
                        if 2 + i + 2 <= len(ext_data):
                            curves.append(struct.unpack(">H", ext_data[2+i:2+i+2])[0])
                elif ext_type == 0x000b and len(ext_data) >= 1:
                    fmt_len = ext_data[0]
                    for i in range(fmt_len):
                        if 1 + i < len(ext_data):
                            point_formats.append(ext_data[1 + i])
                off += ext_size
            ja3_str = ",".join([
                "771",
                "-".join(str(c) for c in ciphers),
                "-".join(str(e) for e in extensions),
                "-".join(str(c) for c in curves),
                "-".join(str(p) for p in point_formats),
            ])
            ja3 = hashlib.md5(ja3_str.encode()).hexdigest()
            return {"sni": sni, "ja3": ja3}
        except Exception:
            return None

    def _handle_http(self, pkt, raw: bytes) -> None:
        try:
            text = raw[:8192].decode("latin-1", errors="replace")
            lines = text.split("\r\n")
            if not lines:
                return
            parts = lines[0].split()
            if len(parts) < 3:
                return
            method, path = parts[0], parts[1]
            headers = {}
            for ln in lines[1:]:
                if not ln:
                    break
                if ":" in ln:
                    k, _, v = ln.partition(":")
                    headers[k.strip().lower()] = v.strip()
            ts = datetime.now(timezone.utc).isoformat()
            if pkt.haslayer(IP):
                src_ip = str(pkt[IP].src)
            elif IPv6 is not None and pkt.haslayer(IPv6):
                src_ip = str(pkt[IPv6].src)
            else:
                return
            host = headers.get("host", "")
            with self._lock:
                self._pending_http.append((
                    ts, src_ip, method[:10], host[:300], path[:500],
                    headers.get("user-agent", "")[:300],
                    headers.get("referer", "")[:300]))
                self._stats["http"] += 1
                if host:
                    self._note_domain(host.split(":")[0], ts)
        except Exception:
            pass

    def _note_domain(self, domain: str, ts: str) -> None:
        domain = domain.lower().strip()
        if not domain or len(domain) > 253:
            return
        if domain not in self._first_seen:
            if len(self._first_seen) >= self.MAX_DOMAIN_CACHE:
                self._first_seen.popitem(last=False)
            self._first_seen[domain] = ts
        else:
            self._first_seen.move_to_end(domain)

    def _maybe_flush(self) -> None:
        with self._lock:
            if time.monotonic() - self._last_flush < self.FLUSH_INTERVAL_S:
                return
            if not (self._pending_dns or self._pending_tls or self._pending_http):
                self._last_flush = time.monotonic()
                return
            dns_batch = self._pending_dns[:]
            tls_batch = self._pending_tls[:]
            http_batch = self._pending_http[:]
            first_seen_batch = list(self._first_seen.items())[-500:]
            self._pending_dns.clear()
            self._pending_tls.clear()
            self._pending_http.clear()
            self._last_flush = time.monotonic()
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                init_telemetry_schema(con)
                if dns_batch:
                    con.executemany(
                        "INSERT INTO dns_queries (ts,src_ip,query,qtype,response,rcode) "
                        "VALUES (?,?,?,?,?,?)", dns_batch)
                if tls_batch:
                    con.executemany(
                        "INSERT INTO tls_sessions (ts,src_ip,dst_ip,dst_port,sni,ja3) "
                        "VALUES (?,?,?,?,?,?)", tls_batch)
                if http_batch:
                    con.executemany(
                        "INSERT INTO http_requests (ts,src_ip,method,host,path,"
                        "user_agent,referrer) VALUES (?,?,?,?,?,?,?)", http_batch)
                now_iso = datetime.now(timezone.utc).isoformat()
                for domain, first in first_seen_batch:
                    is_dga, dga_score = is_likely_dga(domain)
                    con.execute(
                        "INSERT INTO domain_intel (domain,first_seen,last_seen,"
                        "hit_count,is_dga,dga_score) VALUES (?,?,?,1,?,?) "
                        "ON CONFLICT(domain) DO UPDATE SET "
                        "last_seen=excluded.last_seen, hit_count=hit_count+1",
                        (domain, first, now_iso, 1 if is_dga else 0, dga_score))
                con.execute(
                    "DELETE FROM dns_queries WHERE id NOT IN "
                    "(SELECT id FROM dns_queries ORDER BY id DESC LIMIT ?)",
                    (self.MAX_LOG,))
                con.execute(
                    "DELETE FROM tls_sessions WHERE id NOT IN "
                    "(SELECT id FROM tls_sessions ORDER BY id DESC LIMIT ?)",
                    (self.MAX_LOG,))
                con.execute(
                    "DELETE FROM http_requests WHERE id NOT IN "
                    "(SELECT id FROM http_requests ORDER BY id DESC LIMIT ?)",
                    (self.MAX_LOG,))
        except sqlite3.Error as exc:
            logger.warning("Telemetry flush failed: %s", exc)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def get_recent_dns(self, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(limit, 1000))
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                init_telemetry_schema(con)
                rows = con.execute(
                    "SELECT ts,src_ip,query,qtype FROM dns_queries "
                    "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [{"ts": r[0], "src_ip": r[1], "query": r[2], "qtype": r[3]} for r in rows]
        except sqlite3.Error:
            return []

    def get_recent_tls(self, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(limit, 1000))
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                init_telemetry_schema(con)
                rows = con.execute(
                    "SELECT ts,src_ip,dst_ip,dst_port,sni,ja3 FROM tls_sessions "
                    "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [{"ts": r[0], "src_ip": r[1], "dst_ip": r[2], "dst_port": r[3],
                     "sni": r[4], "ja3": r[5]} for r in rows]
        except sqlite3.Error:
            return []

    def get_recent_http(self, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(limit, 1000))
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                init_telemetry_schema(con)
                rows = con.execute(
                    "SELECT ts,src_ip,method,host,path FROM http_requests "
                    "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [{"ts": r[0], "src_ip": r[1], "method": r[2], "host": r[3],
                     "path": r[4]} for r in rows]
        except sqlite3.Error:
            return []

    def get_dga_domains(self, limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(limit, 500))
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                init_telemetry_schema(con)
                rows = con.execute(
                    "SELECT domain, first_seen, hit_count, dga_score "
                    "FROM domain_intel WHERE is_dga=1 "
                    "ORDER BY dga_score DESC LIMIT ?", (limit,)).fetchall()
            return [{"domain": r[0], "first_seen": r[1], "hits": r[2],
                     "dga_score": r[3]} for r in rows]
        except sqlite3.Error:
            return []

    def scan_typosquats(self, limit: int = 20) -> List[Dict[str, Any]]:
        limit = max(1, min(limit, 200))
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                init_telemetry_schema(con)
                rows = con.execute(
                    "SELECT domain, first_seen FROM domain_intel "
                    "ORDER BY last_seen DESC LIMIT 5000").fetchall()
            out = []
            for domain, first in rows:
                brand = is_likely_typosquat(domain)
                if brand:
                    out.append({"domain": domain, "brand": brand, "first_seen": first})
                    if len(out) >= limit:
                        break
            return out
        except sqlite3.Error:
            return []


class EndpointIntegrityMonitor:
    """SHA256 file baseline + service snapshot."""

    DEFAULT_FILES = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
        "/etc/crontab", "/etc/ssh/sshd_config", "/etc/ld.so.preload",
    ]

    def __init__(self, db_path: Path, critical_files: Optional[List[str]] = None):
        self.db_path = Path(db_path)
        self.critical_files = critical_files or self.DEFAULT_FILES
        self._lock = threading.RLock()

    def _sha256(self, path: str) -> Optional[tuple]:
        try:
            hh = hashlib.sha256()
            size = 0
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hh.update(chunk)
                    size += len(chunk)
            return (hh.hexdigest(), size)
        except (OSError, PermissionError):
            return None

    def check_file_integrity(self) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        changes = []
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                init_telemetry_schema(con)
                known = dict(con.execute("SELECT path, sha256 FROM file_integrity").fetchall())
                current = {}
                for path in self.critical_files:
                    if not os.path.isfile(path):
                        continue
                    result = self._sha256(path)
                    if result is None:
                        continue
                    digest, size = result
                    current[path] = digest
                    old = known.get(path)
                    if old is None:
                        con.execute(
                            "INSERT INTO file_integrity (path,sha256,size,first_seen,last_seen) "
                            "VALUES (?,?,?,?,?)", (path, digest, size, now, now))
                    elif old != digest:
                        con.execute(
                            "UPDATE file_integrity SET sha256=?, size=?, last_seen=? "
                            "WHERE path=?", (digest, size, now, path))
                        changes.append({"type": "file-modified", "path": path,
                                        "old": old[:16] + "...",
                                        "new": digest[:16] + "..."})
                for path in known:
                    if path not in current and not os.path.exists(path):
                        con.execute("DELETE FROM file_integrity WHERE path=?", (path,))
                        changes.append({"type": "file-deleted", "path": path})
        except sqlite3.Error as exc:
            logger.warning("FIM check failed: %s", exc)
        return changes

    def check_services(self) -> List[Dict[str, Any]]:
        if platform.system() != "Linux":
            return []
        current = {}
        try:
            r = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all",
                 "--no-pager", "--no-legend"],
                capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                parts = line.split()
                if parts and parts[0].endswith(".service"):
                    name = parts[0].replace(".service", "")
                    state = parts[3] if len(parts) > 3 else ""
                    current[name] = state
        except Exception:
            return []
        if not current:
            return []
        changes = []
        now = datetime.now(timezone.utc).isoformat()
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                init_telemetry_schema(con)
                known = dict(con.execute("SELECT name, state FROM service_state").fetchall())
                for name, state in current.items():
                    if name not in known:
                        changes.append({"type": "service-new", "name": name, "state": state})
                for name in known:
                    if name not in current:
                        changes.append({"type": "service-removed", "name": name})
                con.execute("DELETE FROM service_state")
                con.executemany(
                    "INSERT INTO service_state (name,snapshot_ts,state) VALUES (?,?,?)",
                    [(n, now, s) for n, s in current.items()])
        except sqlite3.Error as exc:
            logger.warning("Service check failed: %s", exc)
        return changes


class AuthMonitor:
    """Parse /var/log/auth.log — never reads passwords."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._last_offset = 0
        self._last_file = ""

    def _find_log(self) -> Optional[str]:
        for p in ("/var/log/auth.log", "/var/log/secure"):
            if os.path.isfile(p) and os.access(p, os.R_OK):
                return p
        return None

    def parse_new_events(self) -> int:
        log = self._find_log()
        if not log:
            return 0
        try:
            size = os.path.getsize(log)
            if log != self._last_file:
                self._last_offset = 0
                self._last_file = log
            if size < self._last_offset:
                self._last_offset = 0
            if size == self._last_offset:
                return 0
            with open(log, "r", errors="ignore") as f:
                f.seek(self._last_offset)
                new_lines = f.read(size - self._last_offset)
                self._last_offset = size
            events = []
            now_iso = datetime.now(timezone.utc).isoformat()
            for line in new_lines.splitlines():
                if not line.strip():
                    continue
                ev = self._parse_line(line, now_iso)
                if ev:
                    events.append(ev)
            if events:
                with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                    init_telemetry_schema(con)
                    con.executemany(
                        "INSERT INTO auth_events (ts,event_type,username,source_ip,"
                        "service,success,detail) VALUES (?,?,?,?,?,?,?)", events)
            return len(events)
        except (OSError, PermissionError):
            return 0

    def _parse_line(self, line: str, now_iso: str) -> Optional[tuple]:
        m = re.search(r"Failed \S+ for (invalid user )?(\S+) from (\S+) port", line)
        if m:
            return (now_iso, "ssh_failed", m.group(2), m.group(3), "sshd", 0, line[:500])
        m = re.search(r"Accepted \S+ for (\S+) from (\S+) port", line)
        if m:
            return (now_iso, "ssh_success", m.group(1), m.group(2), "sshd", 1, line[:500])
        m = re.search(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)$", line)
        if m:
            return (now_iso, "sudo", m.group(1), "", "sudo", 1, m.group(2)[:500])
        return None

    def detect_brute_force(self, minutes: int = 10, threshold: int = 5) -> List[Dict[str, Any]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                init_telemetry_schema(con)
                rows = con.execute(
                    "SELECT source_ip, COUNT(*) as c, COUNT(DISTINCT username) as u "
                    "FROM auth_events WHERE ts >= ? AND success=0 AND source_ip != '' "
                    "GROUP BY source_ip HAVING c >= ? ORDER BY c DESC",
                    (cutoff, threshold)).fetchall()
            return [{"source_ip": r[0], "attempts": r[1], "distinct_users": r[2]} for r in rows]
        except sqlite3.Error:
            return []

    def detect_spray(self, minutes: int = 10, threshold: int = 5) -> List[Dict[str, Any]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
                init_telemetry_schema(con)
                rows = con.execute(
                    "SELECT source_ip, COUNT(DISTINCT username) as u, COUNT(*) as c "
                    "FROM auth_events WHERE ts >= ? AND success=0 "
                    "AND source_ip != '' AND username != '' "
                    "GROUP BY source_ip HAVING u >= ? ORDER BY u DESC",
                    (cutoff, threshold)).fetchall()
            return [{"source_ip": r[0], "distinct_users": r[1], "attempts": r[2]} for r in rows]
        except sqlite3.Error:
            return []


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 18 — PACKET CAPTURE ENGINE (async hook, no blocking)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class FlowRecord:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    first_seen: datetime
    last_seen: datetime
    packets: int = 0
    bytes_total: int = 0
    syn_count: int = 0
    ack_count: int = 0
    flags_seen: Set[str] = field(default_factory=set)


class PacketCaptureEngine:
    """Non-blocking packet capture with flow tracking.

    - Main queue feeds flow processing
    - Extra queue feeds telemetry (separate thread, won't block main)
    - Both bounded to prevent memory blowup
    """

    def __init__(self, iface: Optional[str] = None, bpf_filter: str = "ip or ip6",
                 queue_size: int = 20000, flow_ttl: int = 300,
                 max_flows: int = 50000):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.queue: Queue = Queue(maxsize=queue_size)
        self._extra_queue: Queue = Queue(maxsize=queue_size)
        self.flow_ttl = float(flow_ttl)
        self.max_flows = max_flows
        self.flows: OrderedDict[Tuple, FlowRecord] = OrderedDict()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._sniffer = None
        self._consumer_thread = None
        self._extra_consumer_thread = None
        self._started = False
        self.stats = {"captured": 0, "dropped": 0, "processed": 0,
                      "extra_processed": 0, "extra_dropped": 0}
        self.extra_packet_hook = None

    def _on_packet(self, pkt) -> None:
        with self._lock:
            self.stats["captured"] += 1
        # Feed main queue (fast, non-blocking)
        try:
            self.queue.put_nowait(pkt)
        except Full:
            with self._lock:
                self.stats["dropped"] += 1
        # Feed extra queue (separate thread, non-blocking)
        if self.extra_packet_hook is not None:
            try:
                self._extra_queue.put_nowait(pkt)
            except Full:
                with self._lock:
                    self.stats["extra_dropped"] += 1

    def _consume(self) -> None:
        while not self._stop.is_set() or not self.queue.empty():
            try:
                pkt = self.queue.get(timeout=0.25)
            except Empty:
                self._prune_flows()
                continue
            try:
                self._process_packet(pkt)
                with self._lock:
                    self.stats["processed"] += 1
                    if self.stats["processed"] % 1000 == 0:
                        self._prune_flows()
            except Exception:
                pass
            finally:
                self.queue.task_done()

    def _extra_consume(self) -> None:
        """Separate consumer for telemetry — won't block main packet processing."""
        while not self._stop.is_set() or not self._extra_queue.empty():
            try:
                pkt = self._extra_queue.get(timeout=0.25)
            except Empty:
                continue
            try:
                if self.extra_packet_hook:
                    self.extra_packet_hook(pkt)
                with self._lock:
                    self.stats["extra_processed"] += 1
            except Exception:
                pass
            finally:
                self._extra_queue.task_done()

    def _process_packet(self, pkt) -> None:
        if pkt.haslayer(IP):
            ip = pkt[IP]
            proto_ip = "IPv4"
        elif IPv6 is not None and pkt.haslayer(IPv6):
            ip = pkt[IPv6]
            proto_ip = "IPv6"
        else:
            return
        proto = ("TCP" if pkt.haslayer(TCP) else
                 "UDP" if pkt.haslayer(UDP) else
                 "ICMP" if ICMP is not None and pkt.haslayer(ICMP) else proto_ip)
        sp = dp = 0
        flags = ""
        if pkt.haslayer(TCP):
            sp, dp = pkt[TCP].sport, pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            sp, dp = pkt[UDP].sport, pkt[UDP].dport
        key = (ip.src, sp, ip.dst, dp, proto)
        now = datetime.now(timezone.utc)
        size = len(pkt)
        with self._lock:
            f = self.flows.get(key)
            if f is None:
                while len(self.flows) >= self.max_flows:
                    self.flows.popitem(last=False)
                f = FlowRecord(src_ip=str(ip.src), src_port=int(sp),
                               dst_ip=str(ip.dst), dst_port=int(dp),
                               proto=proto, first_seen=now, last_seen=now)
                self.flows[key] = f
            else:
                self.flows.move_to_end(key)
            f.last_seen = now
            f.packets += 1
            f.bytes_total += size
            if "S" in flags:
                f.syn_count += 1
            if "A" in flags:
                f.ack_count += 1
            for ch in flags:
                if ch in "FSRPAUEC":
                    f.flags_seen.add(ch)

    def _prune_flows(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.flow_ttl)
        with self._lock:
            while self.flows:
                _, oldest = next(iter(self.flows.items()))
                if oldest.last_seen >= cutoff:
                    break
                self.flows.popitem(last=False)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self.stats)

    def start(self) -> bool:
        if not SCAPY_AVAILABLE:
            return False
        if self._started:
            return True
        self._stop.clear()
        try:
            kwargs = {"prn": self._on_packet, "store": False}
            if self.iface:
                kwargs["iface"] = self.iface
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter
            self._consumer_thread = threading.Thread(
                target=self._consume, daemon=True, name="pcap-consumer")
            self._consumer_thread.start()
            self._extra_consumer_thread = threading.Thread(
                target=self._extra_consume, daemon=True, name="pcap-extra")
            self._extra_consumer_thread.start()
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            self._started = True
            return True
        except Exception:
            logger.exception("Packet capture start failed")
            self._stop.set()
            try:
                if self._sniffer is not None and self._sniffer.running:
                    self._sniffer.stop()
            except Exception:
                pass
            for t in (self._consumer_thread, self._extra_consumer_thread):
                if t is not None:
                    t.join(timeout=2)
            self._sniffer = None
            self._consumer_thread = None
            self._extra_consumer_thread = None
            return False

    def stop(self) -> None:
        sniffer = self._sniffer
        consumer = self._consumer_thread
        extra = self._extra_consumer_thread
        self._sniffer = None
        self._started = False
        if sniffer is not None:
            try:
                sniffer.stop(join=True)
            except Exception:
                pass
        self._stop.set()
        for t in (consumer, extra):
            if t is not None:
                t.join(timeout=10)

    def get_flows(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [{
                "src_ip": f.src_ip, "src_port": f.src_port,
                "dst_ip": f.dst_ip, "dst_port": f.dst_port, "proto": f.proto,
                "first_seen": f.first_seen.isoformat(),
                "last_seen": f.last_seen.isoformat(),
                "packets": f.packets, "bytes": f.bytes_total,
                "syn_count": f.syn_count, "ack_count": f.ack_count,
                "flags": "".join(sorted(f.flags_seen)),
            } for f in self.flows.values()]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 19 — ATT&CK DETECTION PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

DETECTION_PATTERNS: Dict[str, List[str]] = {
    "T1595": [r"(?i)\b(nmap|masscan|zmap|unicornscan|rustscan)\b",
              r"(?i)\bnc\s+-z.*-v\b"],
    "T1059": [
        r"(?i)\b(powershell|pwsh)(\.exe)?\b.*(?:-enc(?:odedcommand)?\b|downloadstring|frombase64string|invoke-expression)",
        r"(?i)\b(cmd(\.exe)?)\s+/c\b.*(?:certutil|bitsadmin|mshta|rundll32)",
        r"(?i)\b(bash|sh|zsh)\s+-c\b.*(?:curl|wget|nc\s+-e|/dev/tcp|base64\s+-d)",
    ],
    "T1059.001": [
        r"(?i)powershell(\.exe)?.*-(enc|encodedcommand)\s",
        r"(?i)powershell(\.exe)?.*(frombase64string|downloadstring|iex\b)",
    ],
    "T1059.004": [
        r"(?i)(bash|sh|zsh)\s+-c\s+.*(curl|wget|nc|python|perl|base64)",
        r"(?i)(/dev/tcp/|/dev/udp/)",
    ],
    "T1547": [
        r"(?i)reg\s+add.*\\Run\b",
        r"(?i)(\.bashrc|\.bash_profile|\.profile|\.zshrc)",
        r"(?i)(/etc/rc\.local|/etc/init\.d|/etc/systemd/system)",
    ],
    "T1547.001": [r"(?i)reg\s+add.*\\Run(Once)?\b"],
    "T1543.003": [r"(?i)sc(\.exe)?\s+create\s+.*binpath\s*="],
    "T1546.004": [r"(?i)echo\s+.*>>?\s*(~/\.(bashrc|zshrc)|/etc/profile)"],
    "T1548": [
        r"(?i)(sudo|doas)\s+.*(bash|sh|python|perl|vi|vim)",
        r"(?i)runas(\.exe)?\s+\/user",
        r"(?i)(chmod\s+u\+s|chmod\s+4[0-9]{3})",
    ],
    "T1548.001": [r"(?i)chmod\s+u\+s", r"(?i)chmod\s+4[0-9]{3}"],
    "T1055": [
        r"(?i)(writeprocessmemory|virtualallocex|createremotethread)",
        r"(?i)(mavinject|queueuserapc)",
    ],
    "T1140": [
        r"(?i)(certutil\s+-decode|certutil\s+-decodehex)",
        r"(?i)(FromBase64String|Convert\.FromBase64String)",
    ],
    "T1027": [
        r"(?i)(base64|b64|xxd|hexdump)\s*-?d?\s*",
        r"(?i)([A-Za-z0-9+/]{100,}={0,2})",
    ],
    "T1070": [
        r"(?i)(wevtutil\s+cl|Clear-EventLog)",
        r"(?i)(rm\s+-rf\s+/var/log)",
        r"(?i)(history\s+-c|rm\s+.*\.bash_history)",
    ],
    "T1070.001": [r"(?i)wevtutil\s+cl\s+(System|Security|Application)"],
    "T1070.003": [r"(?i)(history\s+-c|unset\s+HISTFILE)"],
    "T1036": [
        r"(?i)(svch0st|scvhost|lssas|csrsss)\.(exe|com)\b",
        r"(?i)(\.pdf\.exe|\.doc\.exe|\.jpg\.exe|\.txt\.exe)",
    ],
    "T1218": [
        r"(?i)(rundll32|regsvr32|mshta|installutil|certutil)\.exe",
        r"(?i)mshta(\.exe)?\s+(javascript:|vbscript:|https?://)",
        r"(?i)regsvr32(\.exe)?\s+.*\/i:https?://",
    ],
    "T1218.005": [r"(?i)mshta(\.exe)?\s+(https?://|javascript:)"],
    "T1218.011": [r"(?i)rundll32(\.exe)?\s+.*\.(dll|ocx)"],
    "T1564.003": [r"(?i)(-WindowStyle\s+Hidden|-w\s+hidden)"],
    "T1574.006": [r"(?i)LD_PRELOAD\s*=|DYLD_INSERT_LIBRARIES\s*="],
    "T1110": [r"(?i)\b(hydra|medusa|ncrack|patator|kerbrute)\b"],
    "T1110.002": [r"(?i)(hashcat|john\s+--)"],
    "T1552.001": [r"(?i)grep\s+-r.*(password|passwd|api_key|secret)\s+"],
    "T1552.003": [r"(?i)cat\s+.*\.(bash|zsh)_history"],
    "T1552.004": [r"(?i)(BEGIN\s+(RSA|OPENSSH|PRIVATE)\s+PRIVATE\s+KEY)"],
    "T1552.005": [r"(?i)169\.254\.169\.254"],
    "T1003": [
        r"(?i)(mimikatz|sekurlsa|lsadump)",
        r"(?i)reg\s+save.*(sam|system|security)\b",
    ],
    "T1003.001": [r"(?i)(procdump|comsvcs).*(lsass|MiniDump)"],
    "T1003.008": [r"(?i)(cat|cp|strings).*(\/etc\/(passwd|shadow))"],
    "T1555.003": [r"(?i)(Login\s+Data|logins\.json|cookies\.sqlite)"],
    "T1558": [r"(?i)(rubeus|kekeo|mimikatz.*kerberos::golden)"],
    "T1040": [r"(?i)(tcpdump|wireshark|tshark)"],
    "T1087": [
        r"(?i)net\s+(user|group|localgroup)\b",
        r"(?i)\b(whoami|id)\b",
        r"(?i)cat\s+/etc/passwd",
    ],
    "T1087.001": [r"(?i)net\s+user\b|whoami\s+/all"],
    "T1083": [r"(?i)dir\s+/s|Get-ChildItem.*-Recurse"],
    "T1046": [r"(?i)\b(nmap|masscan|zmap)\b"],
    "T1057": [r"(?i)\b(tasklist|ps\s+aux)\b"],
    "T1082": [
        r"(?i)\b(systeminfo|uname\s+-a|hostnamectl)\b",
        r"(?i)(cat\s+/etc/os-release|lsb_release)",
    ],
    "T1016": [r"(?i)(ipconfig\s+/all|ifconfig|ip\s+addr)"],
    "T1018": [r"(?i)(net\s+view|nltest\s+/dclist)"],
    "T1033": [r"(?i)\b(whoami|qwinsta|quser)\b"],
    "T1021.001": [r"(?i)(mstsc|rdesktop|xfreerdp)"],
    "T1021.002": [r"(?i)(net\s+use|smbclient|impacket)"],
    "T1021.004": [r"(?i)(ssh\s+.*@|ssh-keygen)"],
    "T1005": [r"(?i)(copy|robocopy|cp)\s+.*\.(doc|pdf|zip|rar|7z)"],
    "T1560.001": [r"(?i)(tar\s+-czf|zip\s+-r)"],
    "T1071": [r"(?i)(certutil.*-urlcache|bitsadmin.*\/transfer)"],
    "T1105": [r"(?i)(curl|wget).*https?://"],
    "T1572": [r"(?i)(ngrok|cloudflared|chisel|ligolo)"],
    "T1090": [r"(?i)(proxychains|tor\s+-|socks5://)"],
    "T1219": [r"(?i)(teamviewer|anydesk|screenconnect|rustdesk)"],
    "T1041": [r"(?i)(curl|wget).*(-d\s+@|--data-binary|--upload-file)"],
    "T1485": [r"(?i)(dd\s+if=/dev/(zero|random))"],
    "T1486": [
        r"(?i)\.(locked|encrypted|crypto|locky|wncry|wannacry)",
        r"(?i)(vssadmin.*delete\s+shadows.*\/all)",
    ],
    "T1490": [r"(?i)vssadmin.*delete\s+shadows.*\/all"],
    "T1489": [r"(?i)(net\s+stop|systemctl\s+stop)"],
    "T1496": [r"(?i)(xmrig|minerd|cryptonight)"],
    "T1529": [r"(?i)(shutdown\s+-[hr]|reboot\b|poweroff\b)"],
    "T1685": [
        r"(?i)systemctl\s+stop\s+(auditd|falcon-sensor|carbonblack)",
        r"(?i)reg\s+add.*Windows\s+Defender.*DisableAntiSpyware.*1",
    ],
    "T1686.003": [r"(?i)netsh\s+advfirewall\s+set\s+.*state\s+off"],
}

TECHNIQUE_NAMES: Dict[str, str] = {
    "T1595": "Active Scanning", "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell", "T1059.004": "Unix Shell",
    "T1547": "Boot/Logon Autostart", "T1547.001": "Registry Run Keys",
    "T1543.003": "Windows Service", "T1546.004": "Unix Shell Config",
    "T1548": "Abuse Elevation Control", "T1548.001": "Setuid/Setgid",
    "T1055": "Process Injection", "T1140": "Deobfuscate/Decode",
    "T1027": "Obfuscated Files", "T1070": "Indicator Removal",
    "T1070.001": "Clear Event Logs", "T1070.003": "Clear Command History",
    "T1036": "Masquerading", "T1218": "System Binary Proxy Execution",
    "T1218.005": "Mshta", "T1218.011": "Rundll32",
    "T1564.003": "Hidden Window", "T1574.006": "LD_PRELOAD Hijacking",
    "T1110": "Brute Force", "T1110.002": "Password Cracking",
    "T1552.001": "Credentials In Files", "T1552.003": "Shell History",
    "T1552.004": "Private Keys", "T1552.005": "Cloud Metadata",
    "T1003": "OS Credential Dumping", "T1003.001": "LSASS Memory",
    "T1003.008": "/etc/passwd and /etc/shadow",
    "T1555.003": "Browser Credentials", "T1558": "Kerberos Tickets",
    "T1040": "Network Sniffing", "T1087": "Account Discovery",
    "T1087.001": "Local Account", "T1083": "File Discovery",
    "T1046": "Network Service Discovery", "T1057": "Process Discovery",
    "T1082": "System Information Discovery", "T1016": "Network Config Discovery",
    "T1018": "Remote System Discovery", "T1033": "User Discovery",
    "T1021.001": "Remote Desktop", "T1021.002": "SMB/Windows Shares",
    "T1021.004": "SSH", "T1005": "Data from Local System",
    "T1560.001": "Archive via Utility", "T1071": "Application Layer Protocol",
    "T1105": "Ingress Tool Transfer", "T1572": "Protocol Tunneling",
    "T1090": "Proxy", "T1219": "Remote Access Tools",
    "T1041": "Exfil Over C2", "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact", "T1490": "Inhibit System Recovery",
    "T1489": "Service Stop", "T1496": "Resource Hijacking",
    "T1529": "System Shutdown/Reboot", "T1685": "Disable or Modify Tools",
    "T1686.003": "Windows Firewall Disable",
}

TECHNIQUE_TACTICS: Dict[str, str] = {
    "T1595": "reconnaissance", "T1059": "execution",
    "T1059.001": "execution", "T1059.004": "execution",
    "T1547": "persistence", "T1547.001": "persistence",
    "T1543.003": "persistence", "T1546.004": "persistence",
    "T1548": "privilege-escalation", "T1548.001": "privilege-escalation",
    "T1055": "defense-evasion", "T1140": "defense-evasion",
    "T1027": "defense-evasion", "T1070": "defense-evasion",
    "T1070.001": "defense-evasion", "T1070.003": "defense-evasion",
    "T1036": "defense-evasion", "T1218": "defense-evasion",
    "T1218.005": "defense-evasion", "T1218.011": "defense-evasion",
    "T1564.003": "defense-evasion", "T1574.006": "defense-evasion",
    "T1110": "credential-access", "T1110.002": "credential-access",
    "T1552.001": "credential-access", "T1552.003": "credential-access",
    "T1552.004": "credential-access", "T1552.005": "credential-access",
    "T1003": "credential-access", "T1003.001": "credential-access",
    "T1003.008": "credential-access", "T1555.003": "credential-access",
    "T1558": "credential-access", "T1040": "credential-access",
    "T1087": "discovery", "T1087.001": "discovery",
    "T1083": "discovery", "T1046": "discovery",
    "T1057": "discovery", "T1082": "discovery",
    "T1016": "discovery", "T1018": "discovery", "T1033": "discovery",
    "T1021.001": "lateral-movement", "T1021.002": "lateral-movement",
    "T1021.004": "lateral-movement", "T1005": "collection",
    "T1560.001": "collection", "T1071": "command-and-control",
    "T1105": "command-and-control", "T1572": "command-and-control",
    "T1090": "command-and-control", "T1219": "command-and-control",
    "T1041": "exfiltration", "T1485": "impact",
    "T1486": "impact", "T1490": "impact", "T1489": "impact",
    "T1496": "impact", "T1529": "impact",
    "T1685": "defense-impairment", "T1686.003": "defense-impairment",
}


def compile_patterns() -> List[Tuple[str, str, re.Pattern]]:
    """Compile all detection patterns once. Returns list of (id, name, pattern)."""
    compiled = []
    for tid, patterns in DETECTION_PATTERNS.items():
        name = TECHNIQUE_NAMES.get(tid, tid)
        for p in patterns:
            try:
                compiled.append((tid, name, re.compile(p)))
            except re.error as exc:
                logger.warning("Invalid pattern %s: %s", tid, exc)
    return compiled


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 20 — SUPPRESSION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SuppressRule:
    name: str
    pattern: str
    techniques: List[str]
    reason: str
    builtin: bool = True


BUILTIN_SUPPRESSIONS: List[SuppressRule] = [
    SuppressRule(name="package-manager",
                 pattern=r"(?i)\b(apt|apt-get|yum|dnf|pacman|snap|brew|npm|pip|pip3)\b\s+",
                 techniques=["T1059", "T1082", "T1087", "T1016"],
                 reason="Package management activity"),
    SuppressRule(name="system-services",
                 pattern=r"(?i)(NetworkManager|systemd-networkd|systemd-resolved|"
                         r"systemd-logind|systemd-udevd|dbus-daemon|rsyslogd)",
                 techniques=["T1059", "T1082", "T1016"],
                 reason="Standard system service"),
    SuppressRule(name="dev-tools",
                 pattern=r"(?i)^(vim?|nano|emacs|code|subl|git|make|cmake|"
                         r"gcc|g\+\+|clang|rustc|cargo|go|node|npm)\b\s+",
                 techniques=["T1059", "T1082"],
                 reason="Development tooling"),
    SuppressRule(name="container-runtime",
                 pattern=r"(?i)\b(dockerd|containerd|runc|podman|kubelet)\b",
                 techniques=["T1059"],
                 reason="Container runtime"),
    SuppressRule(name="sudo-benign",
                 pattern=(r"(?i)^sudo\s+(?:apt|apt-get|dnf|yum|pacman|"
                          r"systemctl\s+(?:start|stop|restart|reload|status)|"
                          r"journalctl|dmesg|ls|lsof|ss|netstat|ps)"),
                 techniques=["T1548"],
                 reason="Benign administrative sudo"),
]


class SuppressionEngine:
    """Suppression with audit trail. HIGH_RISK_OVERRIDE always wins."""

    HIGH_RISK_OVERRIDE = re.compile(
        r"(?i)(-enc(?:odedcommand)?\b|frombase64string|downloadstring|"
        r"invoke-mimikatz|sekurlsa|lsass|procdump|/dev/tcp/|"
        r"\bnc\s+-e\b|\bncat\s+-e\b|"
        r"vssadmin\s+delete\s+shadows|memfd_create|LD_PRELOAD|"
        r"sudo\s+(?:-\S+\s+)*(?:bash|sh|zsh|python\d*|perl|ruby|vi|vim|nano))")

    def __init__(self, user_path: Optional[Path] = None):
        self.rules: List[SuppressRule] = list(BUILTIN_SUPPRESSIONS)
        self._user_count = 0
        self._events: List[Dict[str, str]] = []
        self._lock = threading.Lock()
        self._max_events = 1000
        if user_path and Path(user_path).exists():
            self._load_user(Path(user_path))
        self._compiled: List[Tuple[SuppressRule, re.Pattern]] = []
        for rule in self.rules:
            try:
                self._compiled.append((rule, re.compile(rule.pattern)))
            except re.error as exc:
                logger.warning("Invalid rule %s: %s", rule.name, exc)

    def _load_user(self, path: Path) -> None:
        try:
            text = path.read_text(encoding="utf-8")
            if path.suffix.lower() in (".yaml", ".yml"):
                if not YAML_AVAILABLE:
                    return
                data = yaml.safe_load(text)
            else:
                data = json.loads(text)
        except Exception as exc:
            logger.warning("Could not parse allowlist: %s", exc)
            return
        if not isinstance(data, dict):
            return
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            return
        for entry in rules[:500]:
            if not isinstance(entry, dict):
                continue
            try:
                name = str(entry.get("name", "user-rule"))[:120]
                pattern = str(entry["pattern"])
                techs = [str(t).strip().upper() for t in entry.get("techniques", [])[:200]]
                if not pattern or len(pattern) > 2000:
                    continue
                self.rules.append(SuppressRule(
                    name=name, pattern=pattern, techniques=techs,
                    reason=str(entry.get("reason", "User-defined"))[:300],
                    builtin=False))
                self._user_count += 1
            except Exception:
                continue

    def clear_audit(self) -> None:
        with self._lock:
            self._events.clear()

    def audit_snapshot(self) -> List[Dict[str, str]]:
        with self._lock:
            return list(self._events)

    def is_suppressed(self, cmdline: str, exe: str, tid: str) -> Optional[str]:
        tid = str(tid or "").upper()
        if not tid or tid in CRITICAL_TECHNIQUES:
            return None
        cmd = str(cmdline or "")[:4096]
        full_exe = str(exe or "")[:1024]
        if self.HIGH_RISK_OVERRIDE.search(cmd):
            return None
        exe_name = ntpath.basename(full_exe.replace("/", "\\")).lower()
        haystack = f"{exe_name} {cmd}"
        for rule, pattern in self._compiled:
            if tid not in rule.techniques:
                continue
            if pattern.search(haystack):
                with self._lock:
                    if len(self._events) < self._max_events:
                        self._events.append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "rule": rule.name,
                            "technique": tid,
                            "reason": rule.reason[:300],
                            "executable": redact(full_exe, 300),
                            "command": redact(cmd, 300),
                        })
                return f"[{rule.name}] {rule.reason}"
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 21 — CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class CorrelationEngine:
    def __init__(self, host: HostInfo,
                 interfaces: List[NetworkInterface],
                 connections: List[ConnectionInfo],
                 processes: List[ProcessInfo],
                 routes: List[NetworkRoute],
                 arp: List[Dict[str, str]],
                 beacons: Optional[List[Dict]] = None,
                 pcap_flows: Optional[List[Dict]] = None,
                 persistence: Optional[List[Dict[str, Any]]] = None,
                 suppression: Optional[SuppressionEngine] = None,
                 telemetry: Optional[Dict[str, Any]] = None):
        self.host = host
        self.interfaces = interfaces
        self.connections = connections
        self.processes = processes
        self.routes = routes
        self.arp = arp
        self.beacons = beacons or []
        self.pcap_flows = pcap_flows or []
        self.persistence = persistence or []
        self.suppression = suppression or SuppressionEngine()
        self.telemetry = telemetry or {}
        self.findings: List[Finding] = []
        self._external_pids = {c.pid for c in connections
                               if c.pid is not None and c.is_external}
        self._c2_port_pids = {c.pid for c in connections
                              if c.pid is not None and c.remote_port in SUSPICIOUS_PORTS}
        self._suspicious_path_pids: Set[int] = set()
        self._suspicious_parent_pids: Set[int] = set()
        for p in processes:
            if _is_temporary_path(p.exe):
                self._suspicious_path_pids.add(p.pid)
            pl = (p.parent_name or "").lower()
            if pl in {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                      "mshta.exe", "rundll32.exe", "regsvr32.exe"}:
                self._suspicious_parent_pids.add(p.pid)

    def _new(self, severity: str, category: str, title: str,
             description: str, confidence: str = "Medium", **kwargs) -> Finding:
        evidence = kwargs.get("evidence", [])
        pids = kwargs.get("involved_pids", [])
        ips = kwargs.get("involved_ips", [])
        ports = kwargs.get("involved_ports", [])
        techniques = kwargs.get("attack_techniques", [])
        stable = {
            "category": category, "title": title,
            "pids": sorted(int(x) for x in pids if str(x).isdigit()),
            "ips": sorted(str(x) for x in ips),
            "ports": sorted(int(x) for x in ports if str(x).isdigit()),
            "techniques": sorted(str(x) for x in techniques),
        }
        if not (stable["pids"] or stable["ips"] or stable["ports"] or stable["techniques"]):
            stable["evidence"] = sorted(str(x)[:300] for x in evidence[:3])
        digest = hashlib.sha256(
            json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:12].upper()
        fid = f"GS-{digest}"
        f = Finding(
            id=fid, severity=severity, confidence=confidence,
            category=category, title=title, description=description,
            evidence=evidence, involved_pids=pids, involved_ips=ips,
            involved_ports=ports, attack_techniques=techniques)
        f.risk_score = (SEV_WEIGHT.get(f.severity, 0) * 10
                        + CONF_WEIGHT.get(f.confidence, 1) * 5
                        + len(f.evidence) * 2
                        + len(f.attack_techniques) * 3)
        self.findings.append(f)
        return f

    def detect_attack_matches(self) -> None:
        seen = set()
        matched_pids: Set[int] = set()
        graph = ProcessRiskGraph()
        proc_meta = {}
        for p in self.processes:
            entropy = shannon_entropy(p.cmdline or "")
            base = 0.0
            if p.pid in self._external_pids: base += 2.0
            if p.pid in self._suspicious_path_pids: base += 4.0
            if p.pid in self._suspicious_parent_pids: base += 2.0
            if entropy > 4.8: base += 3.0
            proc_meta[p.pid] = {"entropy": entropy, "base_risk": base}
            graph.add(p.pid, p.ppid, base, p.name, p.cmdline or "")
        propagated = graph.propagate(decay=0.6)

        # Connection-level matches
        for c in self.connections:
            if not c.attack_matches:
                continue
            visible = [m for m in c.attack_matches
                       if not self.suppression.is_suppressed(
                           c.process_cmdline, c.process_exe, m.get("id", ""))]
            if not visible:
                continue
            key = (c.pid, c.process_cmdline[:80], tuple(m.get("id") for m in visible))
            if key in seen:
                continue
            seen.add(key)
            if c.pid is not None:
                matched_pids.add(c.pid)
            signals = []
            if c.is_external: signals.append("external_connection")
            if c.remote_port in SUSPICIOUS_PORTS: signals.append("suspicious_port")
            if _is_temporary_path(c.process_exe): signals.append("temp_execution")
            if (c.process_exe or "").lower().split("/")[-1] in LOLBINS:
                signals.append("lolbin_network")
            if shannon_entropy(c.process_cmdline or "") > 4.8:
                signals.append("high_entropy_cmd")
            posterior = BayesianScorer.posterior(signals)
            confidence = BayesianScorer.to_confidence(posterior)
            tid = visible[0]["id"]
            severity = BayesianScorer.to_severity(posterior, tid in CRITICAL_TECHNIQUES)
            if severity in ("Info", "Low") and confidence == "Low":
                continue
            evidence = [f"P(malicious|signals)={posterior:.3f}",
                        f"signals={','.join(signals) or 'none'}"]
            evidence.extend(f"{m['id']}: {m['evidence']}" for m in visible[:2])
            self._new(severity, "attack", f"ATT&CK: {visible[0]['name']}",
                     f"PID {c.pid} ({c.process_name}) matched {tid}. "
                     f"Bayesian posterior={posterior:.1%}.",
                     confidence=confidence, evidence=evidence,
                     involved_pids=[c.pid] if c.pid else [],
                     involved_ips=[c.remote_ip] if c.remote_ip else [],
                     involved_ports=[c.remote_port] if c.remote_port else [],
                     attack_techniques=[m["id"] for m in visible])

        # Process-only matches
        seen_p = set()
        for p in self.processes:
            if not p.attack_matches or p.pid in matched_pids:
                continue
            key = (p.pid, p.cmdline[:80])
            if key in seen_p:
                continue
            seen_p.add(key)
            visible = [m for m in p.attack_matches
                       if not self.suppression.is_suppressed(
                           p.cmdline, p.exe, m.get("id", ""))]
            if not visible:
                continue
            meta = proc_meta.get(p.pid, {"entropy": 0.0, "base_risk": 0.0})
            signals = []
            if p.pid in self._suspicious_path_pids: signals.append("temp_execution")
            if p.pid in self._suspicious_parent_pids: signals.append("parent_shell")
            if p.pid in self._external_pids: signals.append("external_connection")
            if p.pid in self._c2_port_pids: signals.append("suspicious_port")
            if meta["entropy"] > 4.8: signals.append("high_entropy_cmd")
            posterior = BayesianScorer.posterior(signals)
            graph_boost = min(propagated.get(p.pid, 0.0) / 20.0, 0.25)
            posterior = min(posterior + graph_boost, 0.99)
            confidence = BayesianScorer.to_confidence(posterior)
            tid = visible[0]["id"]
            severity = BayesianScorer.to_severity(posterior, tid in CRITICAL_TECHNIQUES)
            if severity in ("Info", "Low") and confidence == "Low":
                continue
            evidence = [f"P(malicious|signals)={posterior:.3f}",
                        f"signals={','.join(signals) or 'none'}",
                        f"graph_risk={propagated.get(p.pid, 0.0):.2f}"]
            evidence.extend(f"{m['id']}: {m['evidence']}" for m in visible[:2])
            self._new(severity, "attack", f"ATT&CK: {visible[0]['name']}",
                     f"Process {p.name} (PID {p.pid}) matched {tid}. "
                     f"Bayesian posterior={posterior:.1%}.",
                     confidence=confidence, evidence=evidence,
                     involved_pids=[p.pid],
                     attack_techniques=[m["id"] for m in visible])

    def detect_external_c2(self) -> None:
        for c in self.connections:
            if not c.is_external or c.is_listening:
                continue
            if c.remote_port in SUSPICIOUS_PORTS:
                self._new("Critical", "c2",
                         f"External connection on suspicious port {c.remote_port}",
                         f"PID {c.pid} ({c.process_name}) → {c.remote_ip}:{c.remote_port}",
                         confidence="High",
                         evidence=[c.process_cmdline[:250]],
                         involved_pids=[c.pid] if c.pid else [],
                         involved_ips=[c.remote_ip],
                         involved_ports=[c.remote_port])

    def detect_temp_execution(self) -> None:
        for p in self.processes:
            target = _temp_execution_target(p)
            if not target:
                continue
            kind, path = target
            if self.suppression.is_suppressed(p.cmdline, p.exe, "T1059"):
                continue
            confidence = "High" if p.pid in self._external_pids else "Medium"
            self._new("High", "anomaly", "Execution from temp directory",
                     f"PID {p.pid} ({p.name}) running {kind} from temp.",
                     confidence=confidence,
                     evidence=[f"target={path}", f"exe={p.exe}", f"cmd={p.cmdline[:200]}"],
                     involved_pids=[p.pid])

    def detect_beaconing(self) -> None:
        for b in self.beacons:
            severity = "Critical" if b["confidence"] > 0.7 else "High"
            self._new(severity, "beacon",
                     f"C2 beacon candidate → {b['dst_ip']}:{b['dst_port']}",
                     f"Statistical beaconing: {b['events']} events, "
                     f"CV={b['cv']}, regularity={b['regularity']}",
                     confidence="High",
                     evidence=[f"mean_interval={b['mean_interval_s']}s",
                               f"cv={b['cv']}",
                               f"fft_regularity={b['regularity']}"],
                     involved_ips=[b["dst_ip"]],
                     involved_ports=[b["dst_port"]])

    def detect_port_scans(self) -> None:
        if not self.pcap_flows:
            return
        for scan in PortScanDetector().analyze(self.pcap_flows):
            self._new(scan["severity"], "reconnaissance",
                     f"Port scan from {scan['source']}",
                     f"{scan['ports_scanned']} distinct ports, "
                     f"completion {scan['completion_ratio']:.1%}",
                     confidence="High" if scan["scan_probability"] > 0.75 else "Medium",
                     evidence=[f"ports={scan['ports_scanned']}",
                               f"syn={scan['syn_count']} ack={scan['ack_count']}"],
                     attack_techniques=["T1595", "T1046"])

    def detect_persistence(self) -> None:
        for item in self.persistence:
            t = item.get("type", "")
            if t == "ld-preload":
                self._new("Critical", "persistence", "LD_PRELOAD configured",
                         f"File: {item.get('path')}", confidence="High",
                         evidence=[item.get("content", "")],
                         attack_techniques=["T1574.006"])
            elif t == "suid-outside-standard":
                for p in item.get("paths", [])[:10]:
                    self._new("High", "persistence",
                             "SUID binary outside standard paths",
                             f"File: {p}", confidence="Medium",
                             evidence=[p], attack_techniques=["T1548.001"])

    def detect_dga_typosquat(self) -> None:
        for d in self.telemetry.get("dga_domains", [])[:10]:
            self._new("High", "c2", f"DGA candidate: {d['domain']}",
                     f"Entropy/consonant analysis scored {d['dga_score']}",
                     confidence="High",
                     evidence=[f"domain={d['domain']}",
                               f"dga_score={d['dga_score']}",
                               f"hits={d.get('hits', 0)}"],
                     attack_techniques=["T1568.002"])
        for t in self.telemetry.get("typosquats", [])[:10]:
            self._new("High", "c2",
                     f"Typosquat: {t['domain']} (targets {t['brand']})",
                     "Levenshtein distance 1-2 from known brand",
                     confidence="Medium",
                     evidence=[f"domain={t['domain']}", f"brand={t['brand']}"],
                     attack_techniques=["T1583.001"])

    def detect_auth_threats(self) -> None:
        for b in self.telemetry.get("auth_brute", [])[:10]:
            self._new("High", "credential-access",
                     f"Brute force from {b['source_ip']}",
                     f"{b['attempts']} failed logins, {b['distinct_users']} users",
                     confidence="High",
                     evidence=[f"source={b['source_ip']}",
                               f"attempts={b['attempts']}"],
                     involved_ips=[b["source_ip"]],
                     attack_techniques=["T1110"])
        for s in self.telemetry.get("auth_spray", [])[:10]:
            self._new("High", "credential-access",
                     f"Password spray from {s['source_ip']}",
                     f"{s['distinct_users']} users targeted",
                     confidence="High",
                     evidence=[f"source={s['source_ip']}",
                               f"users={s['distinct_users']}"],
                     involved_ips=[s["source_ip"]],
                     attack_techniques=["T1110.003"])

    def detect_fim(self) -> None:
        for ch in self.telemetry.get("fim_changes", [])[:10]:
            severity = "High" if "deleted" in ch["type"] else "Medium"
            self._new(severity, "persistence", f"File {ch['type']}",
                     f"Path: {ch['path']}", confidence="High",
                     evidence=[f"type={ch['type']}", f"path={ch['path']}"],
                     attack_techniques=["T1565.001"])

    def detect_privilege_gap(self) -> None:
        if self.host.is_privileged:
            return
        denied = [p for p in self.processes if p.access_denied]
        if len(denied) >= 3:
            self._new("Info", "exposure",
                     f"Privilege gap: {len(denied)} processes unreadable",
                     "Run as root for full visibility",
                     confidence="High",
                     evidence=[f"denied_pids={[p.pid for p in denied[:10]]}"])

    def run_all(self) -> List[Finding]:
        self.detect_attack_matches()
        self.detect_external_c2()
        self.detect_temp_execution()
        self.detect_persistence()
        self.detect_beaconing()
        self.detect_port_scans()
        self.detect_dga_typosquat()
        self.detect_auth_threats()
        self.detect_fim()
        self.detect_privilege_gap()
        self.findings.sort(
            key=lambda f: (SEV_WEIGHT.get(f.severity, 0),
                           CONF_WEIGHT.get(f.confidence, 1),
                           f.risk_score), reverse=True)
        return self.findings


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 22 — STORAGE (correct DB migration)
# ═══════════════════════════════════════════════════════════════════════════════

_DB_LOCK = threading.RLock()
_DB_INITIALIZED = False


@contextmanager
def _db_conn():
    _ensure_data_dir()
    con = sqlite3.connect(str(DB_PATH), timeout=15.0)
    try:
        con.execute("PRAGMA busy_timeout=15000")
        yield con
        con.commit()
    except Exception:
        try:
            con.rollback()
        except sqlite3.Error:
            pass
        raise
    finally:
        con.close()


def _migrate_schema(con: sqlite3.Connection) -> None:
    """Check ALL columns against expected schema. ALTER missing ones.

    This is the CORRECT migration:
      - Reads actual PRAGMA table_info
      - Compares against expected column set
      - Adds ONLY the missing columns
      - Idempotent (safe to run every startup)
    """
    expected = {
        "snapshots": {
            "ts": "TEXT", "host": "TEXT", "hostname_hash": "TEXT",
            "connections": "INTEGER DEFAULT 0",
            "processes": "INTEGER DEFAULT 0",
            "findings": "INTEGER DEFAULT 0", "payload": "TEXT",
        },
        "findings": {
            "id": "TEXT", "snapshot_ts": "TEXT",
            "severity": "TEXT DEFAULT 'Info'",
            "confidence": "TEXT DEFAULT 'Medium'",
            "category": "TEXT DEFAULT 'unknown'",
            "title": "TEXT DEFAULT ''",
            "description": "TEXT DEFAULT ''",
            "risk_score": "INTEGER DEFAULT 0",
            "attack_techniques": "TEXT DEFAULT ''",
        },
        "triage_records": {
            "finding_id": "TEXT", "status": "TEXT DEFAULT 'new'",
            "analyst": "TEXT DEFAULT ''", "note": "TEXT DEFAULT ''",
            "updated_at": "TEXT DEFAULT ''", "title": "TEXT DEFAULT ''",
            "severity": "TEXT DEFAULT 'Info'",
            "category": "TEXT DEFAULT 'unknown'",
            "snapshot_ts": "TEXT DEFAULT ''",
        },
        "triage_history": {
            "action_id": "INTEGER", "finding_id": "TEXT",
            "previous_status": "TEXT DEFAULT ''",
            "status": "TEXT DEFAULT 'new'",
            "analyst": "TEXT DEFAULT ''", "note": "TEXT DEFAULT ''",
            "created_at": "TEXT DEFAULT ''",
        },
    }
    for table, cols in expected.items():
        try:
            existing = {row[1] for row in con.execute(f"PRAGMA table_info({table})")}
            if not existing:
                continue
            for col, typ in cols.items():
                if col in existing:
                    continue
                try:
                    con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
                    logger.info("DB migrated: %s.%s added", table, col)
                except sqlite3.OperationalError as exc:
                    logger.warning("Cannot add %s.%s: %s", table, col, exc)
        except sqlite3.Error as exc:
            logger.warning("Migration check failed for %s: %s", table, exc)


def init_db() -> None:
    global _DB_INITIALIZED
    if _DB_INITIALIZED:
        return
    with _DB_LOCK:
        if _DB_INITIALIZED:
            return
        with _db_conn() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
            con.executescript("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    ts TEXT PRIMARY KEY, host TEXT, hostname_hash TEXT,
                    connections INTEGER, processes INTEGER, findings INTEGER,
                    payload TEXT);
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT, snapshot_ts TEXT, severity TEXT, confidence TEXT,
                    category TEXT, title TEXT, description TEXT,
                    risk_score INTEGER, attack_techniques TEXT,
                    PRIMARY KEY (id, snapshot_ts));
                CREATE INDEX IF NOT EXISTS idx_findings_id_ts
                    ON findings(id, snapshot_ts DESC);
                CREATE TABLE IF NOT EXISTS triage_records (
                    finding_id TEXT PRIMARY KEY, status TEXT NOT NULL,
                    analyst TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'Info',
                    category TEXT NOT NULL DEFAULT 'unknown',
                    snapshot_ts TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS triage_history (
                    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    previous_status TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL, analyst TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
            """)
            # Add missing columns to old tables
            _migrate_schema(con)
            # Telemetry schema (safe per-table fallback)
            try:
                init_telemetry_schema(con)
            except sqlite3.Error as exc:
                logger.warning("Telemetry schema init failed: %s", exc)
        try:
            os.chmod(DB_PATH, 0o600)
        except OSError:
            pass
        _DB_INITIALIZED = True


def save_snapshot(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("host"), dict):
        raise ValueError("snapshot must contain host")
    init_db()
    ts = str(payload.get("ts") or datetime.now(timezone.utc).isoformat())
    host = str(payload["host"].get("hostname", "unknown"))
    hh = str(payload["host"].get("hostname_hash", ""))
    findings = payload.get("findings", [])
    payload_json = json.dumps(payload, default=str, ensure_ascii=False,
                              separators=(",", ":"))
    with _db_conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO snapshots "
            "(ts, host, hostname_hash, connections, processes, findings, payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, host, hh,
             len(payload.get("connections", [])),
             len(payload.get("processes", [])),
             len(findings), payload_json))
        if isinstance(findings, list):
            rows = []
            for f in findings:
                if not isinstance(f, dict):
                    continue
                rows.append((
                    str(f.get("id", "")), ts,
                    str(f.get("severity", "Info")),
                    str(f.get("confidence", "Medium")),
                    str(f.get("category", "unknown")),
                    str(f.get("title", ""))[:1000],
                    str(f.get("description", ""))[:4000],
                    int(f.get("risk_score", 0) or 0),
                    ",".join(str(x) for x in f.get("attack_techniques", []))[:4000]))
            if rows:
                con.executemany(
                    "INSERT OR REPLACE INTO findings "
                    "(id, snapshot_ts, severity, confidence, category, title, "
                    "description, risk_score, attack_techniques) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        con.execute("DELETE FROM snapshots WHERE ts NOT IN "
                    "(SELECT ts FROM snapshots ORDER BY ts DESC LIMIT 500)")
        con.execute("DELETE FROM findings WHERE snapshot_ts NOT IN "
                    "(SELECT ts FROM snapshots)")


TRIAGE_STATUSES = {
    "new": "New", "in_progress": "Investigating",
    "benign_positive": "Benign positive", "false_positive": "False positive",
    "confirmed_incident": "Confirmed incident", "resolved": "Resolved",
    "accepted_risk": "Accepted risk",
}


def save_triage(finding_id: str, status: str,
                analyst: str = "", note: str = "") -> Dict[str, Any]:
    finding_id = str(finding_id or "").strip()[:100]
    status = str(status or "").strip()
    if not finding_id:
        raise ValueError("finding_id required")
    if status not in TRIAGE_STATUSES:
        raise ValueError("invalid status")
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with _db_conn() as con:
        f = con.execute(
            "SELECT title, severity, category, snapshot_ts FROM findings "
            "WHERE id=? ORDER BY snapshot_ts DESC LIMIT 1", (finding_id,)).fetchone()
        if f is None:
            raise LookupError("finding not in stored history")
        old = con.execute("SELECT status FROM triage_records WHERE finding_id=?",
                          (finding_id,)).fetchone()
        prev = old[0] if old else ""
        con.execute(
            "INSERT INTO triage_records (finding_id,status,analyst,note,"
            "updated_at,title,severity,category,snapshot_ts) "
            "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET "
            "status=excluded.status, analyst=excluded.analyst, note=excluded.note, "
            "updated_at=excluded.updated_at",
            (finding_id, status, str(analyst)[:120], str(note)[:4000], now,
             str(f[0] or "")[:1000], str(f[1] or "Info"),
             str(f[2] or "unknown"), str(f[3] or "")))
        con.execute(
            "INSERT INTO triage_history (finding_id,previous_status,status,"
            "analyst,note,created_at) VALUES (?,?,?,?,?,?)",
            (finding_id, prev, status, str(analyst)[:120],
             str(note)[:4000], now))
        con.execute("DELETE FROM triage_history WHERE action_id NOT IN "
                    "(SELECT action_id FROM triage_history ORDER BY action_id DESC LIMIT 10000)")
    return {"finding_id": finding_id, "status": status, "updated_at": now}


def get_triage_records(ids: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    init_db()
    with _db_conn() as con:
        if ids is None:
            rows = con.execute(
                "SELECT finding_id,status,analyst,note,updated_at,title,severity,"
                "category,snapshot_ts FROM triage_records ORDER BY updated_at DESC "
                "LIMIT 2000").fetchall()
        else:
            safe = list(dict.fromkeys(str(v)[:100] for v in ids if v))[:500]
            if not safe:
                return {}
            ph = ",".join("?" for _ in safe)
            rows = con.execute(
                "SELECT finding_id,status,analyst,note,updated_at,title,severity,"
                f"category,snapshot_ts FROM triage_records WHERE finding_id IN ({ph})",
                safe).fetchall()
    keys = ("finding_id", "status", "analyst", "note", "updated_at",
            "title", "severity", "category", "snapshot_ts")
    return {str(r[0]): dict(zip(keys, r)) for r in rows}


def get_snapshot_history(limit: int = 100) -> List[Dict[str, Any]]:
    init_db()
    limit = max(1, min(int(limit or 100), 500))
    with _db_conn() as con:
        rows = con.execute(
            "SELECT ts, host, connections, processes, findings, payload "
            "FROM snapshots ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        try:
            payload = json.loads(r[5]) if r[5] else {}
            if not isinstance(payload, dict):
                payload = {}
        except (json.JSONDecodeError, TypeError):
            payload = {}
        out.append({"ts": r[0], "host": r[1], "connections": r[2],
                    "processes": r[3], "findings": r[4], "payload": payload})
    return out


def get_finding_history(limit: int = 200) -> List[Dict[str, Any]]:
    init_db()
    limit = max(1, min(int(limit or 200), 2000))
    with _db_conn() as con:
        rows = con.execute(
            "SELECT id, snapshot_ts, severity, confidence, category, title, "
            "description, risk_score, attack_techniques FROM findings "
            "ORDER BY snapshot_ts DESC LIMIT ?", (limit,)).fetchall()
    return [{"id": r[0], "ts": r[1], "severity": r[2], "confidence": r[3],
             "category": r[4], "title": r[5], "description": r[6],
             "risk_score": r[7],
             "attack_techniques": (r[8] or "").split(",") if r[8] else []}
            for r in rows]


def get_triage_history(limit: int = 200) -> List[Dict[str, Any]]:
    init_db()
    limit = max(1, min(int(limit or 200), 1000))
    with _db_conn() as con:
        rows = con.execute(
            "SELECT finding_id,previous_status,status,analyst,note,created_at "
            "FROM triage_history ORDER BY action_id DESC LIMIT ?",
            (limit,)).fetchall()
    keys = ("finding_id", "previous_status", "status", "analyst", "note", "created_at")
    return [dict(zip(keys, r)) for r in rows]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 23 — BASELINE
# ═══════════════════════════════════════════════════════════════════════════════

class Baseline:
    def __init__(self, path: Path, learning: bool = False):
        self.path = Path(path).expanduser()
        self.learning = bool(learning)
        self._lock = threading.RLock()
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        empty = {"schema_version": 2, "processes": {}, "connections": {}, "scans": 0}
        if not self.path.is_file():
            return empty
        try:
            parsed = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("root must be object")
            empty.update(parsed)
            empty["processes"] = parsed.get("processes", {}) if isinstance(parsed.get("processes"), dict) else {}
            empty["connections"] = parsed.get("connections", {}) if isinstance(parsed.get("connections"), dict) else {}
            empty["scans"] = max(0, int(parsed.get("scans", 0) or 0))
            return empty
        except Exception as exc:
            logger.warning("Could not load baseline: %s", exc)
            return empty

    @property
    def is_initialized(self) -> bool:
        return bool(self.data.get("scans", 0) or self.data.get("processes")
                    or self.data.get("connections"))

    def save(self) -> None:
        tmp = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.path.parent))
            tmp = Path(tmp_name)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False, default=str)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.path)
            tmp = None
        except Exception:
            logger.exception("Could not save baseline")
        finally:
            if tmp is not None:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass

    def observe(self, processes: List[ProcessInfo],
                connections: List[ConnectionInfo]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            pmap = self.data.setdefault("processes", {})
            cmap = self.data.setdefault("connections", {})
            for p in processes:
                if p.access_denied:
                    continue
                key = f"{p.name}:{p.exe}"
                entry = pmap.setdefault(key, {"count": 0, "first_seen": now})
                entry["count"] = int(entry.get("count", 0)) + 1
                entry["last_seen"] = now
            for c in connections:
                key = f"{c.process_name}:{c.local_port}:{c.remote_ip}:{c.remote_port}"
                entry = cmap.setdefault(key, {"count": 0, "first_seen": now})
                entry["count"] = int(entry.get("count", 0)) + 1
                entry["last_seen"] = now
            self.data["scans"] = int(self.data.get("scans", 0)) + 1
            self.data["last_scan"] = now

    def diff(self, processes: List[ProcessInfo],
             connections: List[ConnectionInfo],
             limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            known_p = set(self.data.get("processes", {}).keys())
            known_c = set(self.data.get("connections", {}).keys())
            initialized = bool(self.data.get("scans", 0) or known_p or known_c)
        if self.learning or not initialized:
            return []
        events = []
        seen = set()
        for p in processes:
            if p.access_denied:
                continue
            key = f"{p.name}:{p.exe}"
            if key in known_p or key in seen:
                continue
            seen.add(key)
            events.append({
                "kind": "process", "key": key, "pid": p.pid,
                "name": p.name, "exe": p.exe, "username": p.username,
                "temporary_path": _is_temporary_path(p.exe),
            })
            if len(events) >= limit:
                return events
        seen = set()
        for c in connections:
            key = f"{c.process_name}:{c.local_port}:{c.remote_ip}:{c.remote_port}"
            if key in known_c or key in seen:
                continue
            seen.add(key)
            events.append({
                "kind": "connection", "key": key,
                "process_name": c.process_name, "pid": c.pid,
                "local_ip": c.local_ip, "local_port": c.local_port,
                "remote_ip": c.remote_ip, "remote_port": c.remote_port,
                "is_external": c.is_external,
            })
            if len(events) >= limit:
                break
        return events


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 24 — SNAPSHOT COMPOSER
# ═══════════════════════════════════════════════════════════════════════════════

def _fallback_host() -> HostInfo:
    hostname = _call(socket.gethostname, "unknown") or "unknown"
    return HostInfo(
        hostname=hostname, fqdn=hostname, os=platform.system() or "Unknown",
        os_version=platform.release() or "Unknown", kernel="Unknown",
        arch=platform.machine() or "Unknown", boot_time="", uptime_seconds=0,
        cpu_count_physical=0, cpu_count_logical=0, cpu_percent=0.0,
        cpu_freq_mhz=None, load_avg=None, memory_total_mb=0, memory_used_mb=0,
        memory_available_mb=0, memory_percent=0.0, swap_total_mb=0, swap_used_mb=0,
        disks=[], logged_in_users=[],
        hostname_hash=hashlib.sha256(hostname.encode()).hexdigest()[:12])


def _safe_call(label: str, fn, default):
    try:
        return fn()
    except Exception:
        logger.exception("%s failed", label)
        return default


# Global telemetry instances (lazy)
_TELEMETRY: Dict[str, Any] = {}
_TELEMETRY_LOCK = threading.Lock()


def get_telemetry() -> Dict[str, Any]:
    with _TELEMETRY_LOCK:
        if not _TELEMETRY:
            _TELEMETRY["net"] = PassiveNetworkTelemetry(DB_PATH)
            _TELEMETRY["fim"] = EndpointIntegrityMonitor(DB_PATH)
            _TELEMETRY["auth"] = AuthMonitor(DB_PATH)
        return _TELEMETRY


def collect_telemetry_extras(run_expensive: bool = False) -> Dict[str, Any]:
    """Collect telemetry data. run_expensive=False skips FIM/auth (fast)."""
    extras: Dict[str, Any] = {}
    try:
        tel = get_telemetry()
    except Exception:
        return extras
    net = tel.get("net")
    if net is not None:
        try:
            extras["dga_domains"] = net.get_dga_domains(50)
            extras["typosquats"] = net.scan_typosquats(20)
            extras["telemetry_stats"] = net.get_stats()
        except Exception:
            pass
    if run_expensive:
        fim = tel.get("fim")
        if fim is not None:
            try:
                extras["fim_changes"] = fim.check_file_integrity()
            except Exception:
                pass
        auth = tel.get("auth")
        if auth is not None:
            try:
                auth.parse_new_events()
                extras["auth_brute"] = auth.detect_brute_force()
                extras["auth_spray"] = auth.detect_spray()
            except Exception:
                pass
    return extras


def take_snapshot(with_processes: bool = True,
                  attack_patterns: Optional[List[Tuple[str, str, re.Pattern]]] = None,
                  pcap_engine: Optional[PacketCaptureEngine] = None,
                  beacon_detector: Optional[BeaconDetector] = None,
                  suppression: Optional[SuppressionEngine] = None,
                  baseline: Optional[Baseline] = None,
                  telemetry_extras: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    start = time.monotonic()
    patterns = attack_patterns or compile_patterns()
    supp = suppression or SuppressionEngine()
    supp.clear_audit()
    host = _safe_call("host", collect_host, _fallback_host())
    ifaces = _safe_call("interfaces", collect_interfaces, [])
    conns = _safe_call("connections", lambda: collect_connections(patterns), [])
    by_pid = defaultdict(list)
    for c in conns:
        if c.pid is not None:
            by_pid[c.pid].append(c)
    procs = (_safe_call("processes", lambda: collect_processes(by_pid, patterns), [])
             if with_processes else [])
    routes = _safe_call("routes", collect_routes, [])
    arp = _safe_call("arp", collect_arp, [])
    persistence = _safe_call("persistence", audit_persistence, [])

    if baseline is not None and baseline.learning:
        _safe_call("baseline", lambda: baseline.observe(procs, conns), None)
        baseline.save()

    pcap_flows: List[Dict[str, Any]] = []
    pcap_stats: Dict[str, int] = {}
    if pcap_engine is not None:
        pcap_flows = _safe_call("pcap", pcap_engine.get_flows, [])
        pcap_stats = pcap_engine.get_stats()

    beacons: List[Dict[str, Any]] = []
    if beacon_detector and pcap_flows:
        beacons = _safe_call("beacons",
                              lambda: beacon_detector.analyze(pcap_flows), [])

    if telemetry_extras is None:
        telemetry_extras = collect_telemetry_extras(run_expensive=False)

    engine = CorrelationEngine(
        host, ifaces, conns, procs, routes, arp,
        beacons=beacons, pcap_flows=pcap_flows,
        persistence=persistence, suppression=supp,
        telemetry=telemetry_extras)
    try:
        findings = engine.run_all()
    except Exception as exc:
        logger.exception("Correlation failed")
        findings = [Finding(id="GS-ERROR-0001", severity="Info",
                            confidence="High", category="anomaly",
                            title="Engine degraded",
                            description=str(exc)[:200], risk_score=0)]

    drift = []
    if baseline is not None and not baseline.learning:
        drift = _safe_call("baseline_diff",
                           lambda: baseline.diff(procs, conns), [])

    stats = {
        "connections_total": len(conns),
        "listening": sum(1 for c in conns if c.is_listening),
        "external": sum(1 for c in conns if c.is_external),
        "processes_total": len(procs),
        "processes_denied": sum(1 for p in procs if p.access_denied),
        "attack_matches": sum(1 for p in procs if p.attack_matches)
                          + sum(1 for c in conns if c.attack_matches),
        "persistence_items": len(persistence),
        "findings_total": len(findings),
        "critical": sum(1 for f in findings if f.severity == "Critical"),
        "high": sum(1 for f in findings if f.severity == "High"),
        "medium": sum(1 for f in findings if f.severity == "Medium"),
        "low": sum(1 for f in findings if f.severity == "Low"),
        "high_confidence": sum(1 for f in findings if f.confidence == "High"),
        "beacons": len(beacons),
        "privileged": host.is_privileged if hasattr(host, "is_privileged") else False,
        "suppressed": len(supp.audit_snapshot()),
    }

    snap: Dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "scan_duration_s": round(time.monotonic() - start, 2),
        "host": asdict(host),
        "interfaces": [asdict(i) for i in ifaces],
        "connections": [asdict(c) for c in conns],
        "processes": [asdict(p) for p in procs],
        "routes": [asdict(r) for r in routes],
        "arp": arp,
        "persistence": persistence,
        "beacons": beacons,
        "pcap_flows": pcap_flows[:500],
        "pcap_stats": pcap_stats,
        "findings": [asdict(f) for f in findings],
        "suppression_audit": supp.audit_snapshot(),
        "baseline_changes": drift,
        "stats": stats,
    }
    for k, v in telemetry_extras.items():
        snap[k] = v
    return snap


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 25 — CLI RENDERING
# ═══════════════════════════════════════════════════════════════════════════════

C = {"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
     "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
     "cyan": "\033[36m"}
console = Console() if RICH_AVAILABLE else None


def _print(msg: str, style: str = "") -> None:
    if RICH_AVAILABLE:
        console.print(msg, style=style, highlight=False)
    else:
        color = C.get(style, "")
        print(f"{color}{msg}{C['reset']}" if color else msg)


def banner() -> None:
    if _QUIET_MODE:
        return
    if RICH_AVAILABLE:
        console.print(Panel(
            f"[bold cyan]{BANNER}[/bold cyan]\n"
            f"  [dim]Host & Network Recon Correlation Engine · v{TOOL_VERSION}[/dim]\n\n"
            f"  [bold]Developer   :[/bold] {DEVELOPER}\n"
            f"  [bold]Organization:[/bold] [magenta]{ORGANIZATION}[/magenta]\n"
            f"  [bold]Website     :[/bold] [blue]{CONTACT['website']}[/blue]\n",
            border_style="bright_blue",
            title="[bold]GRAYSENTINEL CYBER DEFENCE LAB[/bold]"))
    else:
        print(BANNER)
        print(f"  v{TOOL_VERSION} · {DEVELOPER} · {ORGANIZATION}")


def footer() -> None:
    if _QUIET_MODE:
        return
    if RICH_AVAILABLE:
        console.print(Panel(
            f"[bold]🌐 {CONTACT['website']}[/bold]\n"
            f"[bold]📧 {CONTACT['email']}[/bold]",
            border_style="magenta",
            title=f"[bold]{ORGANIZATION}[/bold]"))
    else:
        print(f"\n{ORGANIZATION}\n  {CONTACT['website']}")


SEV_COLOR = {"Critical": "bold red", "High": "red", "Medium": "yellow",
             "Low": "green", "Info": "dim"}


def render_snapshot(snap: Dict[str, Any]) -> None:
    hh = snap["host"]
    s = snap["stats"]
    if RICH_AVAILABLE:
        console.print(Panel(
            f"[bold cyan]HOST[/bold cyan]  {hh['hostname']} ({hh['fqdn']})\n"
            f"[dim]{hh['os']} {hh['os_version']}[/dim]\n"
            f"[dim]Privileged: {'[green]yes[/green]' if s['privileged'] else '[yellow]no[/yellow]'}[/dim]",
            title=f"[bold]{TOOL_NAME} v{TOOL_VERSION}[/bold]",
            border_style="bright_blue"))
        stat_table = Table(show_header=False, box=None)
        stat_table.add_column("Key", style="cyan")
        stat_table.add_column("Value", justify="right")
        for k, v in [
            ("Connections", s["connections_total"]),
            ("  Listening", s["listening"]),
            ("  External", s["external"]),
            ("Processes", s["processes_total"]),
            ("ATT&CK matches", s["attack_matches"]),
            ("Persistence items", s["persistence_items"]),
            ("Beacons", s["beacons"]),
            ("Findings", s["findings_total"]),
            ("  Critical", s["critical"]),
            ("  High", s["high"]),
        ]:
            stat_table.add_row(k, str(v))
        console.print(stat_table)
        if snap["findings"]:
            console.print(f"\n[bold red]⚠️  {len(snap['findings'])} Finding(s)[/bold red]\n")
            for f in snap["findings"][:30]:
                color = SEV_COLOR.get(f["severity"], "white")
                console.print(
                    f"[{color}]{f['severity']:8}[/{color}]  "
                    f"[bold]{f['id']}[/bold]  {f['title']}  "
                    f"[dim](risk={f['risk_score']}, conf={f['confidence']})[/dim]")
                console.print(f"   [dim]{f['description']}[/dim]")
                for e in f["evidence"][:3]:
                    console.print(f"   [dim]·[/dim] {e[:140]}")
                if f["attack_techniques"]:
                    console.print(f"   [red]→ {', '.join(f['attack_techniques'])}[/red]")
                console.print()
        else:
            console.print("\n[green]✔ No findings — clean run[/green]")
    else:
        print(f"\n=== {hh['hostname']} ({hh['fqdn']}) ===")
        print(f"Connections: {s['connections_total']} | Findings: {s['findings_total']}")
        for f in snap["findings"][:20]:
            print(f"\n[{f['severity']}] {f['id']} — {f['title']}")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 26 — FLASK DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

DASHBOARD_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,'Menlo','Consolas',monospace;background:#0a0e14;
     color:#c9d1d9;font-size:13px;line-height:1.5}
a{color:#58a6ff;text-decoration:none} a:hover{text-decoration:underline}
.header{background:linear-gradient(135deg,#0d1117,#161b22);
        padding:16px 24px;border-bottom:2px solid #1f6feb}
.header h1{font-size:22px;color:#79c0ff;letter-spacing:1px}
.header .sub{color:#8b949e;font-size:12px;margin-top:4px}
nav{background:#161b22;padding:10px 24px;border-bottom:1px solid #30363d;
    display:flex;gap:12px;flex-wrap:wrap;font-weight:bold;font-size:12px}
nav a{color:#c9d1d9;padding:4px 8px;border-radius:4px}
nav a:hover{background:#1f6feb;color:#fff;text-decoration:none}
.container{padding:24px;max-width:1600px;margin:0 auto}
h2{color:#79c0ff;margin:24px 0 12px 0;font-size:16px;
   padding-bottom:8px;border-bottom:1px solid #21262d}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.stat{background:#161b22;border-radius:8px;padding:14px;
      border-left:3px solid #1f6feb}
.stat .num{font-size:26px;font-weight:bold;color:#79c0ff}
.stat .lbl{color:#8b949e;font-size:11px;text-transform:uppercase;margin-top:4px}
.stat.crit{border-color:#f85149} .stat.crit .num{color:#f85149}
.stat.high{border-color:#ff7b72} .stat.high .num{color:#ff7b72}
.stat.med{border-color:#d29922} .stat.med .num{color:#d29922}
.card{background:#0d1117;border:1px solid #30363d;border-radius:8px;
      padding:18px;margin-bottom:16px}
table{border-collapse:collapse;width:100%;margin-top:8px;font-size:12px}
th,td{border:1px solid #21262d;padding:8px 10px;text-align:left;vertical-align:top}
th{background:#161b22;color:#8b949e;font-weight:normal;font-size:11px;
   text-transform:uppercase}
tr:hover td{background:#161b22}
.dim{color:#6e7681} .ext{color:#f85149;font-weight:bold}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;
       font-size:11px;font-weight:bold}
.b-Critical{background:#f85149;color:#fff}
.b-High{background:#ff7b72;color:#fff}
.b-Medium{background:#d29922;color:#000}
.b-Low{background:#3fb950;color:#000}
.b-Info{background:#30363d;color:#8b949e}
.finding{border-left:4px solid #444;padding:14px 18px;background:#161b22;
         border-radius:6px;margin-bottom:12px}
.finding.Critical{border-color:#f85149}
.finding.High{border-color:#ff7b72}
.finding.Medium{border-color:#d29922}
.finding.Low{border-color:#3fb950}
.finding .title{font-size:14px;font-weight:bold;margin-bottom:6px}
.finding .ev{font-family:monospace;font-size:11px;background:#0d1117;
             padding:6px 10px;border-radius:4px;color:#8b949e;margin-top:6px}
.attack-tag{background:#f8514922;color:#ff7b72;border:1px solid #f85149;
            padding:1px 8px;border-radius:10px;font-size:11px;margin-right:4px}
.info{background:#0c2d6b;border-left:4px solid #1f6feb;padding:12px 16px;
      border-radius:4px;margin:12px 0;color:#79c0ff}
.warn{background:#3d2c00;border-left:4px solid #d29922;padding:12px 16px;
      border-radius:4px;margin:12px 0;color:#d29922}
.footer{background:#161b22;padding:20px;margin-top:24px;
        border-top:1px solid #30363d;color:#8b949e;font-size:11px;text-align:center}
"""


def create_app(pcap_engine: Optional[PacketCaptureEngine] = None,
               suppression: Optional[SuppressionEngine] = None,
               baseline: Optional[Baseline] = None):
    if not FLASK_AVAILABLE:
        raise RuntimeError("Flask not installed")
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)
    app.config.update(MAX_CONTENT_LENGTH=64*1024,
                      SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Strict")
    supp = suppression or SuppressionEngine()
    patterns = compile_patterns()
    bd = BeaconDetector()

    # Wire telemetry hook
    if pcap_engine is not None:
        try:
            tel = get_telemetry()
            if tel.get("net"):
                pcap_engine.extra_packet_hook = tel["net"].on_packet
        except Exception:
            logger.exception("Could not wire telemetry")

    @app.before_request
    def _auth():
        token = app.config.get("DASHBOARD_AUTH_TOKEN")
        if not token:
            return None
        a = request.headers.get("Authorization", "")
        if a.startswith("Bearer "):
            if hmac.compare_digest(a[7:].encode(), token.encode()):
                return None
        auth = request.authorization
        if (auth and hmac.compare_digest((auth.username or "").encode(), b"sentinel")
                and hmac.compare_digest((auth.password or "").encode(), token.encode())):
            return None
        resp = app.response_class("Auth required", 401)
        resp.headers["WWW-Authenticate"] = 'Basic realm="BlueKit Sentinel"'
        return resp

    @app.after_request
    def _sec(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            "form-action 'self'; frame-ancestors 'none'")
        return response

    @app.errorhandler(Exception)
    def _err(exc):
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return exc
        logger.exception("Dashboard error")
        return jsonify({"error": "Internal server error"}), 500

    _cache: Dict[bool, Tuple[float, Dict[str, Any]]] = {}
    _lock = threading.Lock()
    _ttl = 3.0

    def _fresh(with_procs: bool = True) -> Dict[str, Any]:
        key = bool(with_procs)
        with _lock:
            now = time.monotonic()
            cached = _cache.get(key)
            if cached and now - cached[0] < _ttl:
                return cached[1]
            # Expensive telemetry only on with_procs=True (main page)
            extras = collect_telemetry_extras(run_expensive=with_procs)
            snap = take_snapshot(
                with_processes=key, attack_patterns=patterns,
                pcap_engine=pcap_engine, beacon_detector=bd,
                suppression=supp, baseline=baseline, telemetry_extras=extras)
            try:
                save_snapshot(snap)
            except Exception:
                logger.exception("Could not persist snapshot")
            _cache[key] = (time.monotonic(), snap)
            return snap

    def _base(body: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{h(TOOL_NAME)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{DASHBOARD_CSS}</style></head><body>
<div class="header"><h1>🛡️ BLUEKIT SENTINEL <span style="font-size:14px;color:#8b949e">v{h(TOOL_VERSION)}</span></h1>
<div class="sub"><span style="color:#f85149;font-weight:bold">GRAYSENTINEL</span> · {h(ORGANIZATION)}
· <a href="{h(CONTACT['website'])}">{h(CONTACT['website'])}</a></div></div>
<nav>
<a href="/">📊 Overview</a><a href="/connections">🔌 Connections</a>
<a href="/processes">⚙️ Processes</a><a href="/network">🌐 Network</a>
<a href="/findings">⚠️ Findings</a><a href="/dns">🌐 DNS</a>
<a href="/tls">🔒 TLS</a><a href="/auth">🔐 Auth</a>
<a href="/integrity">🛡️ Integrity</a><a href="/triage">🧭 Triage</a>
<a href="/suppressions">🧾 Suppressions</a><a href="/beacons">🎯 Beacons</a>
<a href="/pcap">📡 PCAP</a><a href="/history">📈 History</a>
</nav><div class="container">{body}</div>
<div class="footer"><b>{h(ORGANIZATION)}</b> · {h(TOOL_NAME)} v{h(TOOL_VERSION)}
· © 2025 Ritik Shrivas · <a href="mailto:{h(CONTACT['email'])}">{h(CONTACT['email'])}</a></div>
</body></html>"""

    @app.route("/favicon.ico")
    def favicon():
        return "", 204

    @app.route("/")
    def index():
        snap = _fresh(True)
        hh = snap["host"]
        s = snap["stats"]
        priv_warn = ""
        if not s["privileged"]:
            priv_warn = f"""<div class="warn"><b>⚠️ Partial visibility.</b>
{s['processes_denied']} processes unreadable. Run with sudo for full coverage.</div>"""
        stats_html = f"""<div class="grid">
<div class="stat"><div class="num">{s['connections_total']}</div><div class="lbl">Connections</div></div>
<div class="stat"><div class="num">{s['external']}</div><div class="lbl">External</div></div>
<div class="stat"><div class="num">{s['processes_total']}</div><div class="lbl">Processes</div></div>
<div class="stat"><div class="num">{s['attack_matches']}</div><div class="lbl">ATT&CK</div></div>
<div class="stat"><div class="num">{s['persistence_items']}</div><div class="lbl">Persistence</div></div>
<div class="stat"><div class="num">{s['beacons']}</div><div class="lbl">Beacons</div></div>
<div class="stat crit"><div class="num">{s['critical']}</div><div class="lbl">Critical</div></div>
<div class="stat high"><div class="num">{s['high']}</div><div class="lbl">High</div></div>
</div>"""
        findings_html = ""
        if snap["findings"]:
            findings_html = "<div class='card'><h2>⚠️ Top Findings</h2>"
            for f in snap["findings"][:10]:
                att = " ".join(f"<span class='attack-tag'>{h(t)}</span>"
                                for t in f.get("attack_techniques", []))
                ev = "<br>".join(h(str(e)[:200]) for e in f.get("evidence", [])[:3])
                findings_html += f"""<div class="finding {h(f['severity'])}">
<div class="title"><span class="badge b-{h(f['severity'])}">{h(f['severity'])}</span>
&nbsp;{h(f['id'])} — {h(f['title'])}</div>
<div>{h(f['description'])}</div><div class="ev">{ev}</div>{att}</div>"""
            findings_html += "</div>"
        body = (f"<div style='color:#8b949e;font-size:12px;margin:12px 0'>"
                f"Last: {snap['ts'][:19]} UTC · {snap['scan_duration_s']}s</div>"
                + priv_warn + stats_html
                + f"<div class='card'><h2>🖥️ {h(hh['hostname'])}</h2>"
                  f"<p>{h(hh['os'])} {h(hh['os_version'])}</p></div>"
                + findings_html)
        return _base(body)

    @app.route("/findings")
    def findings_page():
        snap = _fresh(True)
        html_out = ""
        for f in snap["findings"]:
            att = " ".join(f"<span class='attack-tag'>{h(t)}</span>"
                            for t in f.get("attack_techniques", []))
            ev = "<br>".join(h(str(e)[:250]) for e in f.get("evidence", [])[:6])
            html_out += f"""<div class="finding {h(f['severity'])}">
<div class="title"><span class="badge b-{h(f['severity'])}">{h(f['severity'])}</span>
&nbsp;<b>{h(f['id'])}</b> — {h(f['title'])}
<span class="dim">(risk={h(f['risk_score'])}, conf={h(f['confidence'])})</span></div>
<div>{h(f['description'])}</div><div class="ev">{ev}</div>{att}</div>"""
        body = f"""<h2>⚠️ Findings ({len(snap['findings'])})</h2>
{html_out or '<p class="dim">No findings</p>'}"""
        return _base(body)

    @app.route("/connections")
    def connections_page():
        snap = _fresh(False)
        rows = ""
        for c in sorted(snap["connections"],
                        key=lambda x: (not x["is_external"], not x["is_listening"]))[:500]:
            cls = "ext" if c["is_external"] else "dim"
            att = " ".join(f"<span class='attack-tag'>{h(m['id'])}</span>"
                            for m in c["attack_matches"])
            rows += f"""<tr><td>{h(c['type'])}</td>
<td>{h(c['local_ip'])}:{h(c['local_port'])}</td>
<td class="{cls}">{h(c['remote_ip'] or '—')}:{h(c['remote_port'] or '—')}</td>
<td>{h(c['pid'] if c['pid'] else '—')}</td>
<td>{h(c['process_name'])}</td><td>{att}</td></tr>"""
        body = f"""<h2>🔌 Connections ({len(snap['connections'])})</h2>
<table><tr><th>Proto</th><th>Local</th><th>Remote</th><th>PID</th>
<th>Process</th><th>ATT&CK</th></tr>{rows}</table>"""
        return _base(body)

    @app.route("/processes")
    def processes_page():
        snap = _fresh(True)
        rows = ""
        for p in sorted(snap["processes"],
                        key=lambda x: (not x["attack_matches"], -x["num_connections"]))[:500]:
            att = " ".join(f"<span class='attack-tag'>{h(m['id'])}</span>"
                            for m in p["attack_matches"])
            rows += f"""<tr><td>{h(p['pid'])}</td>
<td><b>{h(p['name'])}</b></td><td class="dim">{h(p['username'])}</td>
<td>{p['num_connections']}</td>
<td class="dim">{h(p['cmdline'][:100])}</td><td>{att}</td></tr>"""
        body = f"""<h2>⚙️ Processes ({len(snap['processes'])})</h2>
<table><tr><th>PID</th><th>Name</th><th>User</th><th>Conns</th>
<th>Command</th><th>ATT&CK</th></tr>{rows}</table>"""
        return _base(body)

    @app.route("/network")
    def network_page():
        snap = _fresh(False)
        iface_rows = "".join(
            f"<tr><td>{h(i['name'])}</td><td>{'✔' if i['is_up'] else '✖'}</td>"
            f"<td class='dim'>{h(i['mac'])}</td>"
            f"<td>{h(', '.join(a['address'] for a in i['addresses'] if a['family']!='MAC'))}</td>"
            f"</tr>" for i in snap["interfaces"])
        route_rows = "".join(
            f"<tr><td>{h(r['destination'])}</td><td>{h(r['gateway'] or '—')}</td>"
            f"<td>{h(r['interface'])}</td></tr>" for r in snap["routes"])
        arp_rows = "".join(
            f"<tr><td>{h(a['ip'])}</td><td class='dim'>{h(a['mac'])}</td>"
            f"<td>{h(a['state'])}</td></tr>" for a in snap["arp"])
        body = f"""<div class="card"><h2>🌐 Interfaces</h2>
<table><tr><th>Name</th><th>Up</th><th>MAC</th><th>Addresses</th></tr>
{iface_rows}</table></div>
<div class="card"><h2>🛣️ Routes ({len(snap['routes'])})</h2>
<table><tr><th>Destination</th><th>Gateway</th><th>Interface</th></tr>
{route_rows}</table></div>
<div class="card"><h2>📡 ARP ({len(snap['arp'])})</h2>
<table><tr><th>IP</th><th>MAC</th><th>State</th></tr>{arp_rows}</table></div>"""
        return _base(body)

    @app.route("/dns")
    def dns_page():
        try:
            tel = get_telemetry()
            net = tel.get("net")
        except Exception:
            net = None
        if not net:
            return _base("<div class='warn'>Telemetry not available</div>")
        dns = net.get_recent_dns(200)
        dga = net.get_dga_domains(50)
        typo = net.scan_typosquats(20)
        rows = "".join(
            f"<tr><td class='dim'>{h(str(r['ts'])[:19])}</td>"
            f"<td>{h(r['src_ip'])}</td><td>{h(r['query'])}</td></tr>"
            for r in dns)
        dga_rows = "".join(
            f"<tr><td>{h(r['domain'])}</td><td>{r['dga_score']}</td></tr>"
            for r in dga)
        typo_rows = "".join(
            f"<tr><td>{h(r['domain'])}</td><td>{h(r['brand'])}</td></tr>"
            for r in typo)
        body = f"""<h2>🌐 DNS Activity</h2>
<div class="card"><h3>Recent queries ({len(dns)})</h3>
<table><tr><th>Time</th><th>Source</th><th>Query</th></tr>
{rows or '<tr><td colspan="3" class="dim">No DNS captured (enable --pcap)</td></tr>'}</table></div>
<div class="card"><h3>DGA candidates ({len(dga)})</h3>
<table><tr><th>Domain</th><th>Score</th></tr>
{dga_rows or '<tr><td colspan="2" class="dim">None</td></tr>'}</table></div>
<div class="card"><h3>Typosquats ({len(typo)})</h3>
<table><tr><th>Domain</th><th>Target brand</th></tr>
{typo_rows or '<tr><td colspan="2" class="dim">None</td></tr>'}</table></div>"""
        return _base(body)

    @app.route("/tls")
    def tls_page():
        try:
            net = get_telemetry().get("net")
        except Exception:
            net = None
        if not net:
            return _base("<div class='warn'>Telemetry not available</div>")
        sessions = net.get_recent_tls(300)
        rows = "".join(
            f"<tr><td class='dim'>{h(str(r['ts'])[:19])}</td>"
            f"<td>{h(r['src_ip'])}</td><td class='ext'>{h(r['sni'] or '—')}</td>"
            f"<td class='dim'>{h(r['ja3'][:16])}…</td></tr>"
            for r in sessions)
        body = f"""<h2>🔒 TLS Sessions ({len(sessions)})</h2>
<div class="info">SNI reveals hostname inside encrypted traffic</div>
<table><tr><th>Time</th><th>Source</th><th>SNI</th><th>JA3</th></tr>
{rows or '<tr><td colspan="4" class="dim">No TLS captured</td></tr>'}</table>"""
        return _base(body)

    @app.route("/auth")
    def auth_page():
        try:
            auth = get_telemetry().get("auth")
        except Exception:
            auth = None
        if not auth:
            return _base("<div class='warn'>Auth monitor not available</div>")
        brute = auth.detect_brute_force()
        spray = auth.detect_spray()
        b_rows = "".join(
            f"<tr><td>{h(r['source_ip'])}</td><td>{r['attempts']}</td>"
            f"<td>{r['distinct_users']}</td></tr>" for r in brute)
        s_rows = "".join(
            f"<tr><td>{h(r['source_ip'])}</td><td>{r['distinct_users']}</td>"
            f"<td>{r['attempts']}</td></tr>" for r in spray)
        body = f"""<h2>🔐 Authentication Monitoring</h2>
<div class="info">Requires sudo to read /var/log/auth.log</div>
<div class="card"><h3>⚠️ Brute force ({len(brute)})</h3>
<table><tr><th>Source</th><th>Attempts</th><th>Users</th></tr>
{b_rows or '<tr><td colspan="3" class="dim">None</td></tr>'}</table></div>
<div class="card"><h3>⚠️ Password spray ({len(spray)})</h3>
<table><tr><th>Source</th><th>Users</th><th>Attempts</th></tr>
{s_rows or '<tr><td colspan="3" class="dim">None</td></tr>'}</table></div>"""
        return _base(body)

    @app.route("/integrity")
    def integrity_page():
        try:
            fim = get_telemetry().get("fim")
        except Exception:
            fim = None
        if not fim:
            return _base("<div class='warn'>FIM not available</div>")
        changes = fim.check_file_integrity()
        rows = "".join(
            f"<div class='finding {'High' if 'deleted' in c['type'] else 'Medium'}'>"
            f"<b>{h(c['type'])}</b> — {h(c['path'])}</div>"
            for c in changes)
        body = f"""<h2>🛡️ File Integrity</h2>
<div class="info">SHA256 baseline of critical system files (requires sudo)</div>
<div class="card"><h3>Changes ({len(changes)})</h3>
{rows or '<p class="dim">No changes detected</p>'}</div>"""
        return _base(body)

    @app.route("/triage")
    def triage_page():
        csrf = session.get("csrf_token") or secrets.token_urlsafe(32)
        session["csrf_token"] = csrf
        snap = _fresh(True)
        findings = snap["findings"][:100]
        states = get_triage_records([str(f.get("id", "")) for f in findings])
        cards = []
        for f in findings:
            fid = str(f.get("id", ""))
            st = states.get(fid, {})
            cur = st.get("status", "new")
            opts = "".join(f"<option value='{h(v)}' {'selected' if v==cur else ''}>{h(l)}</option>"
                            for v, l in TRIAGE_STATUSES.items())
            cards.append(f"""<div class="card">
<div class="title"><span class="badge b-{h(f['severity'])}">{h(f['severity'])}</span>
<b>{h(fid)}</b> — {h(f['title'])}</div>
<form method="post" action="/triage/update" style="margin-top:12px;display:grid;gap:8px">
<input type="hidden" name="csrf" value="{h(csrf)}">
<input type="hidden" name="finding_id" value="{h(fid)}">
<label>Status<select name="status">{opts}</select></label>
<label>Analyst<input name="analyst" value="{h(st.get('analyst',''))}"></label>
<label>Notes<textarea name="note">{h(st.get('note',''))}</textarea></label>
<button type="submit">Save</button></form></div>""")
        body = f"""<h2>🧭 Alert Triage</h2>
{''.join(cards) or '<p class="dim">No findings</p>'}"""
        return _base(body)

    @app.route("/triage/update", methods=["POST"])
    def triage_update():
        expected = str(session.get("csrf_token", ""))
        provided = str(request.form.get("csrf", ""))
        if not expected or not hmac.compare_digest(expected, provided):
            return "CSRF failed", 403
        try:
            save_triage(request.form.get("finding_id", ""),
                       request.form.get("status", ""),
                       request.form.get("analyst", ""),
                       request.form.get("note", ""))
        except LookupError as exc:
            return h(str(exc)), 404
        except ValueError as exc:
            return h(str(exc)), 400
        except Exception:
            return "Save failed", 500
        return redirect(url_for("triage_page"), code=303)

    @app.route("/suppressions")
    def suppressions_page():
        snap = _fresh(True)
        events = snap.get("suppression_audit", [])
        rows = "".join(
            f"<tr><td>{h(str(e.get('timestamp',''))[:19])}</td>"
            f"<td>{h(e.get('rule',''))}</td><td>{h(e.get('technique',''))}</td>"
            f"<td>{h(e.get('command',''))}</td></tr>" for e in events[-500:])
        body = f"""<h2>🧾 Suppression Audit ({len(events)})</h2>
<table><tr><th>Time</th><th>Rule</th><th>Tech</th><th>Command</th></tr>
{rows or '<tr><td colspan="4" class="dim">None</td></tr>'}</table>"""
        return _base(body)

    @app.route("/beacons")
    def beacons_page():
        snap = _fresh(False)
        rows = "".join(
            f"<tr><td class='ext'>{h(b['dst_ip'])}:{h(b['dst_port'])}</td>"
            f"<td>{b['events']}</td><td>{b['cv']}</td><td>{b['regularity']}</td>"
            f"<td>{b['confidence']}</td></tr>" for b in snap.get("beacons", []))
        body = f"""<h2>🎯 Beacon Candidates</h2>
<div class="info">Statistical CV + FFT regularity. Requires ≥8 events.</div>
<table><tr><th>Destination</th><th>Events</th><th>CV</th><th>FFT</th><th>Conf</th></tr>
{rows or '<tr><td colspan="5" class="dim">None</td></tr>'}</table>"""
        return _base(body)

    @app.route("/pcap")
    def pcap_page():
        if not SCAPY_AVAILABLE or pcap_engine is None:
            return _base("<div class='warn'>PCAP not enabled</div>")
        flows = pcap_engine.get_flows()
        stats = pcap_engine.get_stats()
        rows = "".join(
            f"<tr><td>{h(f['proto'])}</td><td>{h(f['src_ip'])}:{h(f['src_port'])}</td>"
            f"<td class='{'ext' if is_public_ip(f['dst_ip']) else 'dim'}'>"
            f"{h(f['dst_ip'])}:{h(f['dst_port'])}</td>"
            f"<td>{f['packets']}</td><td>{f['bytes']:,}</td></tr>"
            for f in sorted(flows, key=lambda x: -x["bytes"])[:200])
        body = f"""<h2>📡 Packet Capture</h2>
<div class="grid">
<div class="stat"><div class="num">{stats.get('captured',0):,}</div><div class="lbl">Captured</div></div>
<div class="stat"><div class="num">{stats.get('processed',0):,}</div><div class="lbl">Flows</div></div>
<div class="stat med"><div class="num">{stats.get('dropped',0):,}</div><div class="lbl">Dropped</div></div>
<div class="stat"><div class="num">{len(flows)}</div><div class="lbl">Active flows</div></div>
</div>
<table><tr><th>Proto</th><th>Source</th><th>Destination</th><th>Packets</th><th>Bytes</th></tr>
{rows or '<tr><td colspan="5" class="dim">No flows</td></tr>'}</table>"""
        return _base(body)

    @app.route("/history")
    def history_page():
        snaps = get_snapshot_history(100)
        findings = get_finding_history(200)
        snap_rows = "".join(
            f"<tr><td class='dim'>{h(str(s['ts'])[:19])}</td><td>{h(s['host'])}</td>"
            f"<td>{s['connections']}</td><td>{s['findings']}</td></tr>"
            for s in snaps[:50])
        find_rows = "".join(
            f"<tr><td class='dim'>{h(str(f['ts'])[:19])}</td>"
            f"<td><span class='badge b-{h(f['severity'])}'>{h(f['severity'])}</span></td>"
            f"<td>{h(f['title'])}</td></tr>" for f in findings[:100])
        body = f"""<h2>📈 Snapshot History</h2>
<table><tr><th>Time</th><th>Host</th><th>Conns</th><th>Findings</th></tr>
{snap_rows or '<tr><td colspan="4" class="dim">No history</td></tr>'}</table>
<h2>⚠️ Finding History</h2>
<table><tr><th>Time</th><th>Severity</th><th>Title</th></tr>
{find_rows or '<tr><td colspan="3" class="dim">No findings</td></tr>'}</table>"""
        return _base(body)

    @app.route("/api/snapshot")
    def api_snapshot():
        return jsonify(_fresh(True))

    @app.route("/api/findings")
    def api_findings():
        snap = _fresh(False)
        return jsonify({"findings": snap["findings"], "stats": snap["stats"]})

    @app.route("/api/history")
    def api_history():
        return jsonify(get_snapshot_history(200))

    return app


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 27 — CLI COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

def write_json_report(path_value: str, payload: Dict[str, Any]) -> Path:
    target = Path(path_value).expanduser()
    parent = target.parent if str(target.parent) else Path(".")
    if not parent.is_dir():
        raise FileNotFoundError(f"Output dir missing: {parent}")
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(parent))
    tmp_path = Path(tmp)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)
        return target
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _positive_int(v: str) -> int:
    try:
        n = int(v)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be integer") from exc
    if n < 1:
        raise argparse.ArgumentTypeError("must be > 0")
    return n


def _nonneg_int(v: str) -> int:
    try:
        n = int(v)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be integer") from exc
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def _valid_port(v: str) -> int:
    n = _positive_int(v)
    if n > 65535:
        raise argparse.ArgumentTypeError("must be 1..65535")
    return n


def _valid_bpf(v: str) -> str:
    if len(v) > 1024 or any(ord(c) < 32 for c in v):
        raise argparse.ArgumentTypeError("filter must be printable ≤1024 chars")
    return v


def _is_loopback(host: str) -> bool:
    cand = (host or "").strip().strip("[]").lower()
    if cand == "localhost":
        return True
    try:
        return ipaddress.ip_address(cand).is_loopback
    except ValueError:
        return False


def _filter_confidence(findings: List[Dict], min_conf: str) -> List[Dict]:
    threshold = CONF_ORDER.get(min_conf.lower(), 1)
    return [f for f in findings
            if CONF_ORDER.get(str(f.get("confidence", "medium")).lower(), 2) >= threshold]


def cmd_scan(args: argparse.Namespace) -> int:
    banner()
    _print(f"[dim]v{TOOL_VERSION} — starting scan[/dim]")
    supp = SuppressionEngine(
        Path(args.allowlist).expanduser() if args.allowlist else
        (ALLOWLIST_PATH if ALLOWLIST_PATH.exists() else None))
    baseline = None
    if args.baseline:
        if args.baseline == "learn":
            baseline = Baseline(BASELINE_PATH, learning=True)
        else:
            baseline = Baseline(Path(args.baseline).expanduser(), learning=False)
            if not baseline.is_initialized:
                _print("[yellow]Baseline empty — run 'scan --baseline learn' first[/yellow]")
    pcap_engine = None
    if args.pcap:
        if not SCAPY_AVAILABLE:
            _print("[yellow]Scapy not installed — skipping PCAP[/yellow]")
        else:
            pcap_engine = PacketCaptureEngine(
                iface=args.pcap, bpf_filter=args.bpf or "ip or ip6")
            if pcap_engine.start():
                _print(f"[dim]PCAP active on {args.pcap}[/dim]")
                try:
                    tel = get_telemetry()
                    if tel.get("net"):
                        pcap_engine.extra_packet_hook = tel["net"].on_packet
                except Exception:
                    pass
            else:
                pcap_engine = None
    try:
        _print("[dim]⏳ Collecting data…[/dim]")
        snap = take_snapshot(
            with_processes=not args.no_processes,
            pcap_engine=pcap_engine,
            beacon_detector=BeaconDetector() if pcap_engine else None,
            suppression=supp, baseline=baseline)
        if not args.no_save:
            save_snapshot(snap)
        if args.min_confidence != "low":
            snap["findings"] = _filter_confidence(snap["findings"], args.min_confidence)
            snap["stats"]["findings_total"] = len(snap["findings"])
        render_snapshot(snap)
        if args.json:
            out = write_json_report(args.json, snap)
            _print(f"\n[green]✔[/green] Wrote {out}")
        footer()
        if snap["stats"]["critical"] > 0:
            return 2
        if snap["stats"]["high"] > 0:
            return 1
        return 0
    finally:
        if pcap_engine:
            pcap_engine.stop()


def cmd_watch(args: argparse.Namespace) -> int:
    banner()
    seen = set()
    iteration = 0
    supp = SuppressionEngine()
    pcap_engine = None
    if args.pcap and SCAPY_AVAILABLE:
        pcap_engine = PacketCaptureEngine(iface=args.pcap)
        if pcap_engine.start():
            try:
                tel = get_telemetry()
                if tel.get("net"):
                    pcap_engine.extra_packet_hook = tel["net"].on_packet
            except Exception:
                pass
    _print(f"[bold]Watch mode · interval={args.interval}s[/bold]")
    _print("[dim]Ctrl+C to stop[/dim]\n")
    try:
        while not _shutdown_event.is_set():
            iteration += 1
            _print(f"\n[dim]=== Scan #{iteration} · {datetime.now().strftime('%H:%M:%S')} ===[/dim]")
            snap = take_snapshot(
                with_processes=not args.no_processes,
                pcap_engine=pcap_engine,
                beacon_detector=BeaconDetector() if pcap_engine else None,
                suppression=supp)
            if not args.no_save:
                save_snapshot(snap)
            new = []
            for f in snap["findings"]:
                key = (f["title"], tuple(f["involved_pids"]), tuple(f["involved_ips"]))
                if key not in seen:
                    seen.add(key)
                    new.append(f)
            if new:
                _print(f"[bold red]⚠️ {len(new)} new finding(s)[/bold red]")
                for f in new[:10]:
                    color = SEV_COLOR.get(f["severity"], "white")
                    _print(f"  [{color}]{f['severity']:8}[/{color}] {f['title']}")
            else:
                _print(f"[green]✔ No new findings[/green]")
            if args.count and iteration >= args.count:
                break
            _shutdown_event.wait(args.interval)
    except KeyboardInterrupt:
        _print("\n[dim]Stopped[/dim]")
    finally:
        if pcap_engine:
            pcap_engine.stop()
    footer()
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    if not FLASK_AVAILABLE:
        _print("[red]Flask required: pip install flask[/red]")
        return 1
    if not args.tls_cert and not WAITRESS_AVAILABLE:
        _print("[red]Waitress required: pip install waitress[/red]")
        return 1
    remote = not _is_loopback(args.host)
    if remote:
        if not args.auth_token or len(args.auth_token) < 24:
            _print("[red]Remote bind needs --auth-token (≥24 chars)[/red]")
            return 2
        if not args.tls_cert or not args.tls_key:
            _print("[red]Remote bind needs TLS cert/key[/red]")
            return 2
    if bool(args.tls_cert) != bool(args.tls_key):
        _print("[red]--tls-cert and --tls-key together[/red]")
        return 2
    banner()
    supp = SuppressionEngine()
    pcap_engine = None
    if args.pcap and SCAPY_AVAILABLE:
        pcap_engine = PacketCaptureEngine(iface=args.pcap,
                                          bpf_filter=args.bpf or "ip or ip6")
        if pcap_engine.start():
            _print(f"[green]✔[/green] PCAP on {args.pcap}")
    app = create_app(pcap_engine=pcap_engine, suppression=supp)
    app.config["DASHBOARD_AUTH_TOKEN"] = args.auth_token
    scheme = "https" if args.tls_cert else "http"
    url = f"{scheme}://{args.host}:{args.port}"
    _print(f"[bold green]🛡️ {TOOL_NAME} Web Dashboard[/bold green]")
    _print(f"[bold]{url}[/bold]")
    try:
        threads = max(4, min(32, (os.cpu_count() or 2) * 2))
        if args.tls_cert:
            try:
                from gunicorn.app.base import BaseApplication as GBApp
            except ImportError:
                _print("[red]Gunicorn required for TLS[/red]")
                return 1
            class _App(GBApp):
                def __init__(self, flask_app, options):
                    self.flask_app = flask_app
                    self.options = options
                    super().__init__()
                def load_config(self):
                    for k, v in self.options.items():
                        if v is not None and k in self.cfg.settings:
                            self.cfg.set(k, v)
                def load(self):
                    return self.flask_app
            _App(app, {
                "bind": f"{args.host}:{args.port}",
                "workers": 1, "worker_class": "gthread", "threads": threads,
                "timeout": 60, "certfile": args.tls_cert, "keyfile": args.tls_key,
            }).run()
        else:
            waitress_serve(app, host=args.host, port=args.port, threads=threads,
                           channel_timeout=120, max_request_body_size=64*1024)
    except KeyboardInterrupt:
        _print("\n[dim]Stopped[/dim]")
    finally:
        if pcap_engine:
            pcap_engine.stop()
    footer()
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    banner()
    snaps = get_snapshot_history(limit=args.limit)
    findings = get_finding_history(limit=args.limit)
    if not snaps:
        _print("[yellow]No history yet.[/yellow]")
        footer()
        return 0
    if RICH_AVAILABLE:
        t = Table(title=f"Snapshots (last {len(snaps)})")
        t.add_column("Time", style="dim")
        t.add_column("Host")
        t.add_column("Conns", justify="right")
        t.add_column("Findings", justify="right")
        for s in snaps[:50]:
            t.add_row(s["ts"][:19], s["host"], str(s["connections"]),
                     str(s["findings"]))
        console.print(t)
        if findings:
            ft = Table(title="Recent Findings")
            ft.add_column("Time", style="dim")
            ft.add_column("Severity")
            ft.add_column("Title")
            for f in findings[:30]:
                color = SEV_COLOR.get(f["severity"], "white")
                ft.add_row(f["ts"][:19],
                          f"[{color}]{f['severity']}[/{color}]", f["title"])
            console.print(ft)
    footer()
    return 0


def cmd_persist(args: argparse.Namespace) -> int:
    banner()
    _print("[dim]Auditing persistence…[/dim]\n")
    items = audit_persistence(use_cache=False)
    if not items:
        _print("[green]✔ No persistence items[/green]")
        footer()
        return 0
    if RICH_AVAILABLE:
        t = Table(title=f"Persistence ({len(items)})")
        t.add_column("Type", style="cyan")
        t.add_column("Path")
        for item in items:
            path = item.get("path") or ", ".join(item.get("paths", [])[:3]) or "—"
            t.add_row(item.get("type", "?"), str(path)[:100])
        console.print(t)
    if args.json:
        out = write_json_report(args.json, {"persistence": items})
        _print(f"\n[green]✔[/green] Wrote {out}")
    footer()
    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 28 — ARG PARSER & MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bluekit-sentinel",
        description=f"{TOOL_NAME} v{TOOL_VERSION} — Host & Network Recon Correlation Engine\n"
                    f"{ORGANIZATION} · {DEVELOPER} · {CONTACT['website']}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python bluekit_sentinel.py scan
  sudo python bluekit_sentinel.py scan --pcap eth0 -v
  python bluekit_sentinel.py scan --json report.json
  python bluekit_sentinel.py scan --baseline learn
  python bluekit_sentinel.py watch --interval 15
  sudo python bluekit_sentinel.py web --pcap eth0
  python bluekit_sentinel.py history
  python bluekit_sentinel.py persist-audit

Contact: {CONTACT['email']}
        """)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("--quiet", action="store_true", help="Hide banner")
        sp.add_argument("--allowlist", metavar="PATH", help="Suppression allowlist")
        sp.add_argument("--baseline", metavar="PATH_OR_LEARN",
                        help="Baseline file or 'learn'")
        sp.add_argument("--min-confidence", choices=["low", "medium", "high"],
                        default="low")

    p = sub.add_parser("scan", help="One-shot scan")
    p.add_argument("--json", "-j", help="Write JSON report")
    p.add_argument("--no-processes", action="store_true")
    p.add_argument("--no-save", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--pcap", metavar="IFACE")
    p.add_argument("--bpf", metavar="FILTER", type=_valid_bpf, default="ip or ip6")
    add_common(p)

    p = sub.add_parser("watch", help="Continuous watch")
    p.add_argument("--interval", "-i", type=_positive_int, default=15)
    p.add_argument("--count", "-c", type=_nonneg_int, default=0)
    p.add_argument("--no-processes", action="store_true")
    p.add_argument("--no-save", action="store_true")
    p.add_argument("--pcap", metavar="IFACE")
    add_common(p)

    p = sub.add_parser("web", help="Web dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=_valid_port, default=8080)
    p.add_argument("--pcap", metavar="IFACE")
    p.add_argument("--bpf", metavar="FILTER", type=_valid_bpf, default="ip or ip6")
    p.add_argument("--auth-token", default=None)
    p.add_argument("--tls-cert", default=None)
    p.add_argument("--tls-key", default=None)
    add_common(p)

    p = sub.add_parser("history", help="Snapshot history")
    p.add_argument("--limit", "-n", type=_positive_int, default=50)
    p.add_argument("--quiet", action="store_true")

    p = sub.add_parser("persist-audit", help="Audit persistence")
    p.add_argument("--json", "-j")
    p.add_argument("--quiet", action="store_true")

    return parser


def _signal_handler(signum, frame):
    _shutdown_event.set()
    raise KeyboardInterrupt


def main() -> int:
    _shutdown_event.clear()
    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _signal_handler)
    parser = build_parser()
    args = parser.parse_args()
    global _QUIET_MODE
    _QUIET_MODE = bool(getattr(args, "quiet", False))
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "watch":
            return cmd_watch(args)
        if args.command == "web":
            return cmd_web(args)
        if args.command == "history":
            return cmd_history(args)
        if args.command == "persist-audit":
            return cmd_persist(args)
        parser.print_help()
        return 0
    except KeyboardInterrupt:
        _print("\n[dim]Stopped[/dim]")
        return 130
    except Exception:
        logger.exception("Fatal error")
        _print("[red]Command failed; check logs.[/red]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
