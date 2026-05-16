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
    "Normalize file paths to use forward slashes for consistency across platforms."
    path_str = str(path).replace("\\", "/").strip()
    base_str = str(BASE_DIR).replace("\\", "/") + "/"
    if path_str.startswith(base_str):
        path_str = path_str[len(base_str):]
    path_str = path_str.lstrip("./")
    return path_str if path_str else ""

def run_gitleaks(repo_path: str= ".") -> list:
    if not GITLEAKS_EXE.exists():
        print("gitleaks.exe not found at", GITLEAKS_EXE)
        return []
    report_path= BASE_DIR/ "tmp" / "gitleaks-report.json"
    os.makedirs(BASE_DIR / "tmp",exist_ok=True)
    try:
        cmd = [
            str(GITLEAKS_EXE), "detect",
            "--source", str(BASE_DIR),
            "--config", str(BASE_DIR / "gitleaks.toml"),
            "--report-format", "json",
            "--report-path", str(report_path),
            "--no-git",
            "--redact"
        ]
        print("Running gitleaks with command:", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, cwd= BASE_DIR,timeout = 300)

        print(f"Gitleaks exited with code : {result.returncode}")
        if result.returncode not in [0,1]:
            print("Gitleaks error output:", result.stderr.strip())
            return []
        if report_path.exists():
            with open(report_path,"r",encoding="utf-8") as f:
                findings = json.loads(f.read())
                print(f"Gitleaks found {len(findings)} secrets.")
                return findings if isinstance(findings, list ) else []
        else:
            print("Gitleaks found 0 secrets")
            return []
    except Exception as e:
        print("Gitleaks execution error:", str(e))
        return []

def run_trivy_fs(path: str = ".") -> list:
    if not TRIVY_EXE.exists():
        print("trivy.exe not found at", TRIVY_EXE)
        return []
    try:
        cmd = [
            str(TRIVY_EXE), "fs",
            "--format", "json",
            "--scanners", "vuln,secret,misconfig",
            "--quiet",
            "--skip-dirs",".venv,data,tmp,tools,node_modules",
            str(BASE_DIR)
        ]
        print("Running Trivy with command:", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, cwd= BASE_DIR,timeout = 300)

        print(f"Trivy exited with code : {result.returncode}")
        if result.returncode != 0:
            print("Trivy error output:", result.stderr.strip())
            return []
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        results = data.get("Results", [])
        total_items = sum(
            len(r.get("Vulnerabilities", [])) +
            len(r.get("Secrets", [])) +
            len(r.get("Misconfigurations", []))
            for r in results
        )
        print(f"Trivy processed {len(results)} results with a total of {total_items} findings.")
        return results
    except Exception as e:
        print("Trivy execution error:", str(e))
        return []
    
def run_bandit(path: str = ".") -> list:
    try:
        exclude_dirs = ",".join([
            str(BASE_DIR / ".venv"),
            str(BASE_DIR / "__pycache__"),
            str(BASE_DIR / "node_modules"),
            str(BASE_DIR / "tools"),
            str(BASE_DIR / "tmp"),
            str(BASE_DIR / "data"),
        ])
        cmd = [
            "bandit", "-r", str(BASE_DIR),
            "-f", "json",
            "--quiet",
            "--exclude", exclude_dirs
        ]
        print("Running Bandit with command:", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, cwd= BASE_DIR,timeout = 300)

        print(f"Bandit exited with code : {result.returncode}")
        data= json.loads(result.stdout) if result.stdout.strip() else {}
        findings = data.get("results", [])
        print(f"Bandit found {len(findings)} issues.")
        return findings
    except Exception as e:
        print("Bandit execution error:", str(e))
        return []
    
def scan_all() -> Dict[str, List[Dict]]:
    """Run all scanners. Returns dict with keys: gitleaks, trivy, bandit.
    Empty list per key means either clean scan OR scanner failure — check logs to distinguish."""
    print(f"Starting comprehensive scan from base directory: {BASE_DIR}")
    findings={
        "gitleaks": run_gitleaks(),
        "trivy": run_trivy_fs(),
        "bandit": run_bandit()
    }
    total_findings ={k : len(v) for k,v in findings.items()} 
    print(f"Scan completed with findings: {total_findings}")
    return findings