import subprocess
import json
import os
from typing import List, Dict
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.resolve()
TOOLS_DIR = BASE_DIR / "tools"
GITLEAKS_EXE = TOOLS_DIR / "gitleaks.exe"
TRIVY_EXE = TOOLS_DIR / "trivy.exe"

def normalize_path(path: str) -> str:
    """Convert any path (abs/rel, win/unix) to project-relative forward-slash path."""
    path_str =path_str.replace("\\", "/").strip()
    base_str= str(BASE_DIR).replace("\\", "/") + "/"
    if path_str.startswith(base_str):
        path_str = path_str[len(base_str):]
    path_str = path_str.lstrip("./")
    return path_str

def run_gitleaks(repo_path: str = ".") -> list:
    if not GITLEAKS_EXE.exists():
        print("gitleaks.exe not found at:", GITLEAKS_EXE)
        return []
    try:
        cmd = [
            str(GITLEAKS_EXE), "detect",
            "--source", str(BASE_DIR),
            "--config", str(BASE_DIR / "gitleaks.toml"),
            "--report-format", "json",
            "--no-git",
            "--redact"
        ]
        print("Running Gitleaks:", " ".join(cmd))  # Debug cmd
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=BASE_DIR, timeout=120)

        print(f"Gitleaks exit code: {result.returncode}")
        if result.returncode not in [0, 1]:
            print("Gitleaks stderr:", result.stderr.strip())
            return []

        findings = json.loads(result.stdout) if result.stdout.strip() else []
        print(f"🔍 Gitleaks found {len(findings)} leaks")
        return findings
    except Exception as e:
        print("Gitleaks exception:", str(e))
        return []
    
def run_trivy_fs(path: str = ".") -> list:
    if not TRIVY_EXE.exists():
        print("trivy.exe not found at:", TRIVY_EXE)
        return []
    try:
        cmd = [
            str(TRIVY_EXE), "fs",
            "--format", "json",
            "--scanners", "vuln,secret,misconfig",
            "--quiet",  # less noise
            str(BASE_DIR / path)
        ]
        print("Running Trivy:", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=BASE_DIR, timeout=180)

        print(f"Trivy exit code: {result.returncode}")
        if result.returncode != 0:
            print("Trivy stderr:", result.stderr.strip())

        data = json.loads(result.stdout) if result.stdout.strip() else {}
        results = data.get("Results", [])
        total_items = sum(
            len(r.get("Vulnerabilities", [])) + len(r.get("Secrets", []))
            for r in results
        )
        print(f"🔍 Trivy processed {len(results)} targets, found ~{total_items} issues")
        return results
    except Exception as e:
        print("Trivy exception:", str(e))
        return []

def run_bandit(path: str = ".") -> list:
    try:
        cmd = [
            "bandit", "-r",
            str(BASE_DIR / path),
            "-f", "json",
            "--quiet",
            "--recursive",  # explicit, though -r already does it
            "--exclude", ".venv,__pycache__,tools,tmp,node_modules"
        ]
        print("Running Bandit:", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=BASE_DIR)

        print(f"Bandit exit code: {result.returncode}")
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        findings = data.get("results", [])
        print(f"🔍 Bandit found {len(findings)} issues")
        return findings
    except Exception as e:
        print("Bandit exception:", str(e))
        return []

def scan_all() -> Dict[str, List[Dict]]:
    """Run all scanners."""
    print(f"🚀 Starting scan from base directory: {BASE_DIR}")
    findings = {
        "gitleaks": run_gitleaks(),
        "trivy": run_trivy_fs(),
        "bandit": run_bandit()
    }
    print("✅ Scan finished")
    return findings
