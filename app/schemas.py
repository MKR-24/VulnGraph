"""
Pydantic models for output validation.
Finding first goes through here before reaching neo4j
In that way only validated findings are there in graph

GitleaksFinding - validates Gitleaks JSON output
TrivyVuln- validates Trivy CVE findings
Bandit Finding- validates Bandit SAST findings
Normalized Finding-common schema for all
"""
from pydantic import BaseModel,Field,field_validator,model_validator
from typing import Optional
from enum import Enum

#Enums
class Severity(str,Enum):
    """Normalized severity levels"""
    CRITICAL = "CRITICAL"
    HIGH="HIGH"
    MEDIUM= "MEDIUM"
    LOW= "LOW"
    UNDEFINED= "UNDEFINED"
    UNKNOWN = "UNKNOWN"

class ScannerSource(str,Enum):
    BANDIT="bandit"
    TRIVY= "trivy"
    GITLEAKS="gitleaks"

#severity normalization
SEVERITY_MAP ={
    #bandit
    "high": Severity.HIGH,
    "medium":Severity.MEDIUM,
    "low":Severity.LOW,
    #Trivy
    "critical": Severity.CRITICAL,
    "unknown": Severity.UNKNOWN,
    #Fallback
    "undefined": Severity.UNDEFINED,
    "": Severity.UNDEFINED,
}

def normalize_severity(raw:Optional[str])->Severity:
    if not raw:
        return Severity.UNDEFINED
    return SEVERITY_MAP.get(raw.lower().strip(), Severity.UNDEFINED)

#Gitleaks Schema
class GitleaksFinding(BaseModel):
    """
    Validate single finding from Gitleaks
    Gitleaks JSON fields: RuleID, File, StartLine, Match,Secret,Commit
    """
    RuleID: str
    File: str
    StartLine: int = 0
    Match: Optional[str]=None
    Secret: Optional[str] =None


    model_config={"populate_by_name":True} 

    @field_validator("RuleID")
    @classmethod
    def rule_id_not_empty(cls,v:str)->str:
        if not v.strip():
            raise ValueError("RuleID cannot be empty")
        return v.strip()


    @field_validator("File")
    @classmethod
    def file_not_empty(cls,v:str)->str:
        if not v.strip():
            raise ValueError("File path cannot be empty")
        return v.strip().replace("\\","/")

    @field_validator("StartLine",mode="before")
    @classmethod
    def line_non_neg(cls,v)->int:
        try:
            val=int(v)
            return max(val,0)
        except(TypeError,ValueError):
            return 0

#Trivy Schema
class TrivyVuln(BaseModel):
    """
    Validates a single Trivy vulnerability finding
    Fields: VulnerabilityId, Severity, Title, Description,PkgName
    """
    VulnerabilityID: str
    Severity:str="UNKNOWN"
    Title: Optional[str] = None
    Description: Optional[str]= None
    PkgName: Optional[str]=None
    InstalledVersion: Optional[str]=None
    FixedVersion:Optional[str]=None

    @field_validator("VulnerabilityID")
    @classmethod
    def vuln_id_not_empty(cls,v:str)->str:
        if not v.strip():
            raise ValueError("Vuln Id cannot be empty")
        return v.strip()
    
    @field_validator("Severity")
    @classmethod
    def normalize_sev(cls,v:str)->str:
        return v.upper().strip() if v else "UNKNOWN"
    
    @field_validator("Title", "Description",mode="before")
    @classmethod
    def truncate_long(cls,v)->Optional[str]:
        if v is None:
            return None
        return str(v)[:500]
    
class TrivySecret(BaseModel):
    RuleID: str="UNKNOWN"
    Match:Optional[str]=None
    Severity:str="UNKNOWN"

    @field_validator("Severity")
    @classmethod
    def normalize_sev(cls,v:str)->str:
        return v.upper().strip() if v else "UNKNOWN"

    @field_validator("Match",mode="before")
    @classmethod
    def truncate_match(cls,v)->Optional[str]:
        if v is None:
            return None
        return str(v)[:500]

class TrivyResult(BaseModel):
    Target: str=""
    Vulnerabilities:list[TrivyVuln]=[]
    Secrets: list[TrivySecret]=[]

    @field_validator("Target")
    @classmethod
    def normalize_target(cls,v:str)->str:
        return v.replace("\\","/").strip() if v else ""
    
    @model_validator(mode="before")
    @classmethod
    def handle_none_lists(cls,values):
        #Trivy can return null instead of empty list
        if isinstance(values,dict):
            if values.get("Vulnerabilities") is None:
                values["Vulnerabilities"]=[]
            if values.get("Secrets") is None:
                values["Secrets"]=[]
        return values
    
#Bandit
class BanditFinding(BaseModel):
    """
    Bandit uses test_id not issue_code
    """
    test_id: str=Field(...,description="Bandit rule Id")
    test_name: str=""
    filename: str
    issue_severity: str="UNDEFINED"
    issue_confidence: str="UNDEFINED"
    issue_text: str=""
    line_number: int =0
    issue_cwe: Optional[dict]= None

    @field_validator("test_id")
    @classmethod
    def test_id_not_empty(cls,v:str) -> str:
        if not v.strip():
            raise ValueError("Test_id cannot be empty")
        return v.strip().upper()
    
    @field_validator("filename")
    @classmethod
    def filename_not_empty(cls,v:str)->str:
        if not v.strip():
            raise ValueError("filename cannot be empty")
        return v.strip().replace("\\","/")
    
    @field_validator("issue_severity", "issue_confidence")
    @classmethod
    def uppercase_fields(cls,v:str)->str:
        return v.upper().strip() if v else "UNDEFINED"
    
    @field_validator("issue_text",mode="before")
    @classmethod
    def truncate_text(cls,v)->str:
        if not v:
            return ""
        return str(v)[:500]
    
    @field_validator("line_number",mode="before")
    @classmethod
    def line_non_negative(cls,v)->int:
        try:
            return max(int(v),0)
        except (TypeError,ValueError):
            return 0
        
    def get_cwe_id(self)->Optional[str]:
        if self.issue_cwe and isinstance(self.issue_cwe,dict):
            cwe_id=self.issue_cwe.get("id")
            if cwe_id:
                return f"CWE-{cwe_id}"
        return None
    
#Normalized Finding
class NormalizedFinding(BaseModel):
    """
    Unified finding schema — all three scanners convert to this before Neo4j.
    This is the single source of truth for what a finding looks like in the graph.
    """
    finding_id:  str                         # CVE-2025-1234, B404, generic-api-key
    severity:    Severity                    # always our normalized enum
    source:      ScannerSource               # bandit / trivy / gitleaks
    file_path:   str                         # normalized forward-slash path
    text:        str          = ""           # description / issue text
    title:       str          = ""           # CVE title (Trivy only)
    line_number: Optional[int] = None        # line number if available
    cwe:         Optional[str] = None        # CWE-XXX string
    confidence:  Optional[str] = None        # Bandit confidence level
    pkg_name:    Optional[str] = None        # Trivy package name
    fixed_version: Optional[str] = None     # Trivy fix version

    @field_validator("file_path")
    @classmethod
    def normalize_path(cls, v: str) -> str:
        return v.replace("\\", "/").strip().lstrip("./")
 
    @field_validator("finding_id")
    @classmethod
    def finding_id_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("finding_id cannot be empty")
        return v.strip()

#Parser functions 
#These take raw scanner JSON and return validated NormalizedFinding lists.
# Invalid findings are logged and skipped — never silently corrupted.

def parse_bandit_findings(raw_findings: list[dict]) -> tuple[list[NormalizedFinding], list[dict]]:
    """
    Parse and validate raw Bandit JSON findings.

    Returns:
        (valid_findings, failed_findings)
        valid_findings:  list of NormalizedFinding ready for Neo4j
        failed_findings: list of raw dicts that failed validation (for logging)
    """
    valid = []
    failed = []

    for raw in raw_findings:
        try:
            bandit = BanditFinding(**raw)
            normalized = NormalizedFinding(
                finding_id=bandit.test_id,
                severity=normalize_severity(bandit.issue_severity),
                source=ScannerSource.BANDIT,
                file_path=bandit.filename,
                text=f"{bandit.test_name} — {bandit.issue_text}".strip(" —"),
                line_number=bandit.line_number,
                cwe=bandit.get_cwe_id(),
                confidence=bandit.issue_confidence,
            )
            valid.append(normalized)
        except Exception as e:
            print(f"[schemas] Bandit validation failed for {raw.get('test_id', 'UNKNOWN')}: {e}")
            failed.append(raw)

    print(f"[schemas] Bandit: {len(valid)} valid, {len(failed)} failed")
    return valid, failed

def parse_trivy_results(raw_results: list[dict]) -> tuple[list[NormalizedFinding], list[dict]]:
    """
    Parse and validate raw Trivy JSON results.
    Each result contains multiple vulnerabilities and secrets.
    """
    valid = []
    failed = []

    for raw_result in raw_results:
        try:
            result = TrivyResult(**raw_result)

            for vuln in result.Vulnerabilities:
                try:
                    normalized = NormalizedFinding(
                        finding_id=vuln.VulnerabilityID,
                        severity=normalize_severity(vuln.Severity),
                        source=ScannerSource.TRIVY,
                        file_path=result.Target,
                        text=vuln.Description or "",
                        title=vuln.Title or "",
                        pkg_name=vuln.PkgName,
                        fixed_version=vuln.FixedVersion,
                    )
                    valid.append(normalized)
                except Exception as e:
                    print(f"[schemas] Trivy vuln validation failed: {e}")
                    failed.append(raw_result)

            for secret in result.Secrets:
                try:
                    normalized = NormalizedFinding(
                        finding_id=secret.RuleID,
                        severity=normalize_severity(secret.Severity),
                        source=ScannerSource.TRIVY,
                        file_path=result.Target,
                        text=secret.Match or "",
                    )
                    valid.append(normalized)
                except Exception as e:
                    print(f"[schemas] Trivy secret validation failed: {e}")
                    failed.append(raw_result)

        except Exception as e:
            print(f"[schemas] Trivy result validation failed: {e}")
            failed.append(raw_result)

    print(f"[schemas] Trivy: {len(valid)} valid, {len(failed)} failed")
    return valid, failed


def parse_gitleaks_findings(raw_findings: list[dict]) -> tuple[list[NormalizedFinding], list[dict]]:
    """
    Parse and validate raw Gitleaks JSON findings.
    """
    valid = []
    failed = []

    for raw in raw_findings:
        try:
            # Handle both "Startline" and "StartLine" field names across Gitleaks versions
            if "StartLine" not in raw and "Startline" in raw:
                raw["StartLine"] = raw["Startline"]

            finding = GitleaksFinding(**raw)
            normalized = NormalizedFinding(
                finding_id=finding.RuleID,
                severity=Severity.HIGH,  # Gitleaks doesn't provide severity — default HIGH for secrets
                source=ScannerSource.GITLEAKS,
                file_path=finding.File,
                line_number=finding.StartLine,
                text=f"Secret matched rule: {finding.RuleID}",
            )
            valid.append(normalized)
        except Exception as e:
            print(f"[schemas] Gitleaks validation failed for {raw.get('RuleID', 'UNKNOWN')}: {e}")
            failed.append(raw)

    print(f"[schemas] Gitleaks: {len(valid)} valid, {len(failed)} failed")
    return valid, failed

#CLI test 
if __name__ == "__main__":
    # Test with a real Bandit finding structure
    test_bandit = {
        "test_id": "B404",
        "test_name": "blacklist",
        "filename": "C:\\Users\\test\\project\\scanner.py",
        "issue_severity": "low",
        "issue_confidence": "HIGH",
        "issue_text": "Consider possible security implications associated with subprocess module.",
        "line_number": 5,
        "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"}
    }

    valid, failed = parse_bandit_findings([test_bandit])
    print(f"\nParsed finding: {valid[0].model_dump()}")
    print(f"CWE: {valid[0].cwe}")
    print(f"Severity: {valid[0].severity}")

    # Test invalid finding — missing required field
    bad_bandit = {"test_name": "blacklist", "filename": "test.py"}
    valid2, failed2 = parse_bandit_findings([bad_bandit])
    print(f"\nInvalid finding handled: {len(failed2)} failed as expected")
