"""
llm.py - LLM powered explanations for VulnGraph Findings

Flow:
1. Query Neo4j for Vulnerability / Secret nodes without explanations
2. Build a structured prompt for each finding
3. Call Ollama (phi3 or any model) and parse JSON response
4. Store explanation back as node properties in Neo4j

Usage:
from llm import explain_all_findings, explain_single_node
"""

import json
import time
import os
import requests
from dotenv import load_dotenv
from neo4j import GraphDatabase
from rag import retrieve_for_finding,seed_kb,is_seeded


load_dotenv()

#Configurations
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi3:latest")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "vulngraph123")

BATCH_DELAY = 3.0  # seconds between Ollama calls to avoid overload
MAX_RETRIES = 2  # max retries for Ollama calls

#Prompt Template
PROMPTS = {
    "v2_vulnerability": """You are a senior application security engineer. Analyze this vulnerability finding using the provided reference context and respond ONLY with a valid JSON object — no preamble, no markdown, no explanation outside the JSON.

Reference context from security knowledge base:
{context}

Finding details:
- ID: {id}
- Severity: {severity}
- Source scanner: {source}
- Description: {text}

Use the reference context to give accurate, grounded explanations. Respond with exactly this JSON structure:
{{
    "explanation": "1-2 sentence plain English description of what this vulnerability is",
    "why_dangerous": "1-2 sentence explanation of the real-world risk if exploited",
    "fix": "Concrete, specific fix — code snippet or step-by-step instruction",
    "cwe": "CWE-XXX if applicable, else null"
}}""",

    "v2_secret": """You are a senior application security engineer. Analyze this leaked secret finding using the provided reference context and respond ONLY with a valid JSON object — no preamble, no markdown, no explanation outside the JSON.

Reference context from security knowledge base:
{context}

Finding details:
- Rule matched: {rule}
- Line number: {line}
- Source scanner: {source}

Use the reference context to give accurate, grounded explanations. Respond with exactly this JSON structure:
{{
    "explanation": "1-2 sentence plain English description of what this secret leak means",
    "why_dangerous": "1-2 sentence explanation of what an attacker could do with this",
    "fix": "Concrete steps to remediate — rotate key, remove from code, use env vars etc.",
    "cwe": "CWE-798 or similar if applicable, else null"
}}""",

    # Keep v1 as fallback if RAG is unavailable
    "v1_vulnerability": """You are a senior application security engineer. Analyze this vulnerability finding and respond ONLY with a valid JSON object — no preamble, no markdown, no explanation outside the JSON.

Finding details:
- ID: {id}
- Severity: {severity}
- Source scanner: {source}
- Description: {text}

Respond with exactly this JSON structure:
{{
    "explanation": "1-2 sentence plain English description of what this vulnerability is",
    "why_dangerous": "1-2 sentence explanation of the real-world risk if exploited",
    "fix": "Concrete, specific fix — code snippet or step-by-step instruction",
    "cwe": "CWE-XXX if applicable, else null"
}}""",

    "v1_secret": """You are a senior application security engineer. Analyze this leaked secret finding and respond ONLY with a valid JSON object — no preamble, no markdown, no explanation outside the JSON.

Finding details:
- Rule matched: {rule}
- Line number: {line}
- Source scanner: {source}

Respond with exactly this JSON structure:
{{
    "explanation": "1-2 sentence plain English description of what this secret leak means",
    "why_dangerous": "1-2 sentence explanation of what an attacker could do with this",
    "fix": "Concrete steps to remediate — rotate key, remove from code, use env vars etc.",
    "cwe": "CWE-798 or similar if applicable, else null"
}}"""
}

ACTIVE_PROMPT_VULN = "v2_vulnerability"
ACTIVE_PROMPT_SECRET = "v2_secret"  # nosec B105

#Ollama client
def  call_ollama(prompt:str, retries:int=MAX_RETRIES)-> dict | None:
    """
    Send a prompt to Ollama and return the parsed JSON response.
    Returns None on failure - caller decides on how to handle
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "num_predict": 400,
            "temperature": 0.2 # Low temp for consistent, factual responses
        }
    }
    for attempt in range(1,retries+1):
        try:
            response = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            raw= response.json().get("response","").strip()

            #Strip markdown fences if model ignores format = json instrcution
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            parsed = json.loads(raw)

            #Validating expected keys
            required= {"explanation", "why_dangerous", "fix"}
            if not required.issubset(parsed.keys()):
                print(f"[llm] Missing keys in response.  {parsed.keys()}")
                return None
            return parsed
        except requests.exceptions.ConnectionError:
            print(f"[llm] Ollama not reachable at {OLLAMA_URL}. ")
            return None
        except json.JSONDecodeError as e:
            print(f"[llm] JSON parse failed on (attempt {attempt}):{e}")
            if attempt == retries:
                return None
        except Exception as e:
            print(f"[llm] Unexpected error on (attempt {attempt}):{e}")
            if attempt == retries:
                return None
        time.sleep(1)
    return None


def check_ollama_health() -> bool:
    """Return True if Ollama is healthy, False otherwise."""
    try:
        r=requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        models= [m["name"] for m in r.json().get("models",[])]
        available = any(OLLAMA_MODEL in m for m in models)
        if not available:
            print(f"[llm] Ollama is up but model {OLLAMA_MODEL} not found. Available models: {models}")
        return available
    except Exception:
        print(f"[llm] Ollama not reachable or error occurred at {OLLAMA_URL}.")
        return False
    
#Neo4j helper functions
def get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def get_unexplained_vulnerabilities() -> list[dict]:
    """Fetch Vulnerability nodes that don't yet have an explanation."""
    with get_driver().session() as session:
        result = session.run("""
            MATCH (v:Vulnerability)
            WHERE v.explanation IS NULL
            RETURN elementId(v) AS eid,
                v.id AS id,
                v.severity AS severity,
                v.source AS source,
                coalesce(v.text, v.title, '') AS text
        """)
        return [dict(r) for r in result]

def get_unexplained_secrets() -> list[dict]:
    """Fetch Secret nodes that don't yet have an explanation."""
    with get_driver().session() as session:
        result = session.run("""
            MATCH (s:Secret)
            WHERE s.explanation IS NULL
            RETURN elementId(s) AS eid,
                s.rule AS rule,
                coalesce(s.line, 0) AS line,
                s.source AS source
        """)
        return [dict(r) for r in result]

def _to_str(val) -> str:
    """Convert any LLM output value to a plain string safe for Neo4j."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        return " | ".join(f"{k}: {v}" for k, v in val.items())
    if isinstance(val, list):
        return " ".join(str(i) for i in val)
    return str(val)

def save_explanation(eid: str, parsed: dict, node_type: str):
    """Write explanation fields back to the node in Neo4j."""
    with get_driver().session() as session:
        if node_type == "Vulnerability":
            session.run("""
                MATCH (v:Vulnerability) WHERE elementId(v) = $eid
                SET v.explanation    = $explanation,
                    v.why_dangerous  = $why_dangerous,
                    v.fix            = $fix,
                    v.cwe            = $cwe,
                    v.llm_model      = $model,
                    v.llm_version    = $version
            """,
                eid=eid,
                explanation=_to_str(parsed.get("explanation", "")),
                why_dangerous=_to_str(parsed.get("why_dangerous", "")),
                fix=_to_str(parsed.get("fix", "")),
                cwe=_to_str(parsed.get("cwe", "")),
                model=OLLAMA_MODEL,
                version=ACTIVE_PROMPT_VULN
            )
        else:  # Secret
            session.run("""
                MATCH (s:Secret) WHERE elementId(s) = $eid
                SET s.explanation    = $explanation,
                    s.why_dangerous  = $why_dangerous,
                    s.fix            = $fix,
                    s.cwe            = $cwe,
                    s.llm_model      = $model,
                    s.llm_version    = $version
            """,
                eid=eid,
                explanation=_to_str(parsed.get("explanation", "")),
                why_dangerous=_to_str(parsed.get("why_dangerous", "")),
                fix=_to_str(parsed.get("fix", "")),
                cwe=_to_str(parsed.get("cwe", "")),
                model=OLLAMA_MODEL,
                version=ACTIVE_PROMPT_SECRET
            )

#Main functions
def explain_single_node(node:dict,node_type:str)-> dict | None:
    """
    Generate explanation for a single node (Vulnerability or Secret).
    Returns parsed dict on success, None on failure.
    """
    #Retrieve RAG context first
    context= retrieve_for_finding(node)
    if not context:
        context= "No additional context available"
    if node_type == "Vulnerability":
        prompt = PROMPTS[ACTIVE_PROMPT_VULN].format(
            context=context,
            id=node.get("id", "UNKNOWN_ID"),
            severity=node.get("severity", "UNDEFINED"),
            source=node.get("source", "UNKNOWN_SOURCE"),
            text=node.get("text", "No description provided.")[:1000]  # Truncate long descriptions to fit prompt limits
        )
    else:  # Secret
        prompt = PROMPTS[ACTIVE_PROMPT_SECRET].format(
            context=context,
            rule=node.get("rule", "UNDEFINED_RULE"),
            line=node.get("line", "?"),
            source=node.get("source", "UNKNOWN_SOURCE")
        )
    print(f" [llm] Explaining {node_type} :{node.get('id') or node.get('rule')}...")
    parsed = call_ollama(prompt)
    if parsed:
        save_explanation(node["eid"], parsed, node_type)
        print(f"  [llm]  Saved explanation for {node.get('id') or node.get('rule')}")
    else:
        print(f"  [llm]  Failed for {node.get('id') or node.get('rule')}")
    return parsed

def explain_all_findings(
        progress_callback =None,
        skip_secrets: bool = False,
) -> dict:
    """
    Batch explain all unexplained findings.

    Args:
        progress_callback: optional callable(current, total, message) for Streamlit progress bars
        skip_secrets: set True to only process vulnerabilities

    Returns:
        {"success": int, "failed": int, "skipped": int}

    """
    if not check_ollama_health():
        return {"success": 0, "failed": 0, "skipped": 0, "error": f"Ollama not healthy at {OLLAMA_URL}"}
    
    vulns = get_unexplained_vulnerabilities()
    secrets = [] if skip_secrets else get_unexplained_secrets()

    all_nodes = [(n,"Vulnerability") for n in vulns] + [(s,"Secret") for s in secrets]
    total = len(all_nodes)
    success = 0
    failed = 0

    if total == 0:
        print("[llm] No unexplained findings found. All clear!")
        return {"success": 0, "failed": 0, "skipped": 0}
    
    print(f"[llm] Starting explanation of {total} findings ({len(vulns)} vulnerabilities and {len(secrets)} secrets)...")
    for i , (node, node_type) in enumerate(all_nodes, 1):
        if progress_callback:
            label = node.get("id") or node.get("rule") or "..."
            progress_callback(i, total, f"Explaining {node_type}: {label}")

        result = explain_single_node(node, node_type)
        if result:
            success += 1
        else:
            failed += 1
        
        if i < total:
            time.sleep(BATCH_DELAY)  # Avoid overwhelming Ollama

    print(f"[llm] Done! Success: {success}, Failed: {failed}, Skipped: {total - success - failed}")
    return {"success": success, "failed": failed, "skipped": total - success - failed}

#CLI entry point
if __name__ == "__main__":
    print(f"[llm] Using model: {OLLAMA_MODEL} at {OLLAMA_URL}")
    results = explain_all_findings()
    print(f"[llm] Final results: {results}")