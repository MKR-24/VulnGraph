import subprocess
import json
import os
from typing import List, Dict
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.resolve()
TOOLS_DIR = BASE_DIR / "tools"
GITLEAKS_EXE = TOOLS_DIR / "gitleaks.exe"
TRIVY_EXE = TOOLS_DIR / "trivy.exe"

def run_gitleaks(repo_path: str = ".") -> list:
    if not GITLEAKS_EXE.exists():
        print("gitleaks.exe not found at:", GITLEAKS_EXE)
        return []
    try:
        result = subprocess.run([
            str(GITLEAKS_EXE), "detect",
            "--source", str(BASE_DIR / repo_path),
            "--report-format", "json",
            "--no-git",
            "--redact"  # hides real secrets in output
        ], capture_output=True, text=True, cwd=BASE_DIR)
        return json.loads(result.stdout) if result.stdout.strip() else []
    except Exception as e:
        print("Gitleaks error:", e)
        return []
    
def run_trivy_fs(path: str = ".") -> list:
    if not TRIVY_EXE.exists():
        print("trivy.exe not found at:", TRIVY_EXE)
        return []
    try:
        result = subprocess.run([
            str(TRIVY_EXE), "fs",
            "--format", "json",
            "--scanners", "vuln,secret,misconfig",
            str(BASE_DIR / path)
        ], capture_output=True, text=True, cwd=BASE_DIR)
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        return data.get("Results", [])
    except Exception as e:
        print("Trivy error:", e)
        return []

def run_bandit(path: str = ".") -> list:
    try:
        result = subprocess.run([
            "bandit", "-r", str(BASE_DIR / path), "-f", "json", "--quiet"
        ], capture_output=True, text=True, cwd=BASE_DIR)
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        return data.get("results", [])
    except Exception as e:
        print("Bandit error:", e)
        return []

def scan_all() -> Dict[str, List[Dict]]:
    """Run all scanners."""
    return {
        "gitleaks": run_gitleaks(),
        "trivy": run_trivy_fs(),
        "bandit": run_bandit()
    }
