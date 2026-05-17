"""
eval.py-LLM Evaluation Harness for VulnGraph
Measures quality of LLM-generated vulnerability explanations against
ground truth references using three metrics:

    1. Answer Relevancy  — does the explanation address the actual vulnerability?
    (PRIMARY metric — most important for a security tool)
    2. Faithfulness      — does the explanation match retrieved RAG context?
    3. CWE Accuracy      — did the LLM identify the correct CWE reference?

Scores are logged to SQLite for trend tracking over time.

"""
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from neo4j import GraphDatabase
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer

load_dotenv()

#Config
NEO4J_URI = os.getenv("NEO4J_URI","bolt://localhost:7687")
NEO4J_USER= os.getenv("NEO4J_USER","neo4j")
NEO4J_PASSWORD=os.getenv("NEO4J_PASSWORD","vulngraph123")
EVAL_DB_PATH=str(Path(__file__).parent.parent/"data"/"eval_results.db")
EMBED_MODEL = "all-MiniLM-L6-v2"

#Ground Truth Dataset
GROUND_TRUTH = [
    {
        "finding_id": "B404",
        "cwe": "CWE-78",
        "reference_explanation": "The subprocess module is imported, which allows Python code to execute system commands. If user-controlled input reaches subprocess calls, attackers can execute arbitrary OS commands on the server.",
        "reference_why_dangerous": "An attacker who can influence subprocess arguments can run any command with the application's privileges, potentially reading sensitive files, creating backdoors, or destroying data.",
        "reference_fix": "Use subprocess.run() with a list of arguments instead of shell=True. Never pass user input directly to subprocess. Validate and sanitize all inputs before use.",
        "tags": ["command-injection", "subprocess"]
    },
    {
        "finding_id": "B603",
        "cwe": "CWE-78",
        "reference_explanation": "subprocess.Popen is called without shell=True, which is safer than shell=True but still requires careful input validation to prevent argument injection.",
        "reference_why_dangerous": "Even without shell=True, if user-controlled data reaches the command arguments, attackers may be able to inject additional arguments or manipulate program behavior.",
        "reference_fix": "Always pass commands as a list of strings, never as a single string. Validate all inputs that could reach subprocess arguments. Use shlex.quote() if string commands are unavoidable.",
        "tags": ["subprocess", "argument-injection"]
    },
    {
        "finding_id": "B110",
        "cwe": "CWE-703",
        "reference_explanation": "A try-except block catches an exception and passes silently without logging or handling it. This hides errors and security-relevant failures from developers and monitoring systems.",
        "reference_why_dangerous": "Silent exception handling can mask security failures, unexpected states, and active attacks. An attacker may be able to trigger error conditions that would normally be detected but are now hidden.",
        "reference_fix": "Replace bare 'except: pass' with specific exception handling. At minimum, log the exception with its full traceback. Use 'except SpecificException as e: logger.error(e)' instead.",
        "tags": ["error-handling", "logging"]
    },
    {
        "finding_id": "B105",
        "cwe": "CWE-259",
        "reference_explanation": "A string that appears to be a password or secret is hardcoded directly in the source code. Hardcoded credentials are visible to anyone with code access and cannot be rotated without a code change.",
        "reference_why_dangerous": "Hardcoded secrets exposed in version control give any repository reader permanent access to the protected resource. Even after rotation, the secret remains in git history.",
        "reference_fix": "Move all secrets to environment variables or a secrets manager. Use os.getenv('SECRET_NAME') in code. Add the .env file to .gitignore. Rotate any secrets that were ever committed.",
        "tags": ["hardcoded-credentials", "secrets"]
    },
    {
        "finding_id": "B602",
        "cwe": "CWE-78",
        "reference_explanation": "subprocess is called with shell=True, which passes the command string to the system shell for interpretation. This enables shell metacharacters and makes command injection attacks possible.",
        "reference_why_dangerous": "With shell=True, an attacker who controls any part of the command string can inject shell metacharacters like semicolons, pipes, or backticks to execute arbitrary additional commands.",
        "reference_fix": "Replace shell=True with shell=False and pass the command as a list: subprocess.run(['cmd', 'arg1', 'arg2']). If shell=True is unavoidable, use shlex.quote() on all user-provided values.",
        "tags": ["command-injection", "shell"]
    },
    {
        "finding_id": "B605",
        "cwe": "CWE-78",
        "reference_explanation": "os.system() or a similar function is used to start a process via the system shell. Like subprocess with shell=True, this is vulnerable to command injection if any user input reaches the command.",
        "reference_why_dangerous": "Shell-based process execution with user-controlled input allows attackers to append additional shell commands using metacharacters, leading to arbitrary command execution.",
        "reference_fix": "Replace os.system() with subprocess.run() using a list of arguments and shell=False. This bypasses the shell entirely and prevents metacharacter injection.",
        "tags": ["command-injection", "os-system"]
    },
    {
        "finding_id": "B607",
        "cwe": "CWE-78",
        "reference_explanation": "A process is started using a partial or relative executable path rather than an absolute path. If the PATH environment variable is manipulated, a different executable could be run instead.",
        "reference_why_dangerous": "An attacker who can control the PATH environment variable or plant a malicious executable in a directory that appears earlier in PATH can hijack the process execution.",
        "reference_fix": "Always use absolute paths when starting processes. Use shutil.which('executable') to resolve the full path, then pass that absolute path to subprocess.",
        "tags": ["path-hijacking", "subprocess"]
    },
    {
        "finding_id": "B104",
        "cwe": "CWE-605",
        "reference_explanation": "A server socket is bound to 0.0.0.0, which means it listens on all available network interfaces including external-facing ones. This may unintentionally expose the service to the internet.",
        "reference_why_dangerous": "Binding to all interfaces means the service is reachable from any network, not just localhost. In cloud environments this can expose internal services externally.",
        "reference_fix": "Bind to a specific interface instead of 0.0.0.0. For local-only services use '127.0.0.1'. Use a reverse proxy or firewall rules to control external access.",
        "tags": ["network-exposure", "binding"]
    },
    {
        "finding_id": "hugging-face-access-token",
        "cwe": "CWE-798",
        "reference_explanation": "A HuggingFace API access token has been detected in the codebase. This token grants access to HuggingFace resources including model downloads and potentially private repositories.",
        "reference_why_dangerous": "Exposed API tokens can be used by attackers to impersonate the token owner, access private models or datasets, incur usage charges, or exfiltrate sensitive model artifacts.",
        "reference_fix": "Immediately rotate the exposed token in HuggingFace settings. Store the new token in an environment variable (HF_TOKEN) and load it with os.getenv(). Add .env to .gitignore.",
        "tags": ["api-key", "huggingface", "secret"]
    },
    {
        "finding_id": "generic-api-token",
        "cwe": "CWE-798",
        "reference_explanation": "A generic API token or credential has been detected hardcoded in the codebase. This credential grants access to an external service and is now exposed to anyone who can read the code.",
        "reference_why_dangerous": "Hardcoded API tokens in source code are exposed to all repository collaborators, CI/CD systems, and anyone who gains code access. They cannot be rotated without code changes.",
        "reference_fix": "Remove the hardcoded token and use environment variables instead. Rotate the exposed credential immediately. Use a secrets manager for production deployments.",
        "tags": ["api-key", "hardcoded-credentials"]
    }
]

#Embedding Model
_model=None

def get_embed_model()->SentenceTransformer:
    """Load sentence transformer once and cache in module scope"""
    global _model
    if _model is None:
        print("[eval] Loading embedding model")
        _model=SentenceTransformer(EMBED_MODEL)
    return _model

def embed(text:str):
    model=get_embed_model()
    return model.encode([text])
#Scoring functions
def score_relevancy(generated:str,reference:str)->float:
    """
    Answer Relevancy — measures semantic similarity between generated
    explanation and reference explanation using cosine similarity.

    Score range: 0.0 (completely unrelated) to 1.0 (identical meaning)
    Threshold: > 0.7 is acceptable, > 0.85 is good

    This is the PRIMARY metric. A high score means the LLM addressed
    the actual vulnerability, not just generated plausible-sounding text.
    """
    if not generated or not reference:
        return 0.0
    gen_emb=embed(generated)
    ref_embed=embed(reference)
    score=cosine_similarity(gen_emb,ref_embed)[0][0]
    return float(round(score,4))

def score_faithfulness(generated:str,context:str)->float:
    """
    Faithfulness — measures how well the generated explanation
    aligns with the RAG-retrieved context.

    Score range: 0.0 to 1.0
    Threshold: > 0.6 is acceptable (context is reference material,
    not the answer itself, so perfect alignment isn't expected)

    A low faithfulness score with high relevancy means the LLM
    answered correctly but from its training data, not from RAG context.
    """
    if not generated or not context:
        return 0.0
    gen_embed=embed(generated)
    ctx_embed=embed(context)
    score=cosine_similarity(gen_embed,ctx_embed)[0][0]
    return float(round(score,4))

def score_cwe_accuracy(generated_cwe:Optional[str],reference_cwe:str) -> float:
    """
    CWE Accuracy — binary check whether the correct CWE was identified.

    Score: 1.0 if correct CWE mentioned, 0.5 if CWE present but wrong,
        0.0 if no CWE generated.

    Partial credit (0.5) for generating any CWE — shows the model
    understands this is a security issue even if it misidentified the type.
    """
    if not generated_cwe:
        return 0.0
    if reference_cwe.upper() in generated_cwe.upper():
        return 1.0
    if "CWE" in generated_cwe.upper():
        return 0.5
    return 0.0

def compute_overall_score(relevancy:float,faithfullness:float,cwe_accuracy:float)->float:
    """
    Weighted overall score
    """
    return round(
        (relevancy*0.5)+(faithfullness*0.3)+(cwe_accuracy*0.2),4
    )

#SQLITE storage
def init_db():
    """Create Tables first"""
    os.makedirs(os.path.dirname(EVAL_DB_PATH),exist_ok=True)
    conn=sqlite3.connect(EVAL_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS eval_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_timestamp TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                relevancy_score REAL,
                faithfulness_score REAL,
                cwe_accuracy REAL,
                overall_score REAL,
                llm_model TEXT,
                prompt_version TEXT,
                generated_explanation TEXT,
                reference_explanation TEXT,
                passed INTEGER -- 1 if overall_score >= 0.6, else 0
                )
    """)
    conn.commit()
    conn.close()

def save_result(result:dict):
    """Save a single evaluation result to SQLite"""
    conn=sqlite3.connect(EVAL_DB_PATH)
    conn.execute("""
        INSERT INTO eval_results(
                run_timestamp, finding_id, relevancy_score, faithfulness_score, cwe_accuracy, overall_score, llm_model, prompt_version, generated_explanation, reference_explanation, passed
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,(
        result["run_timestamp"],
        result["finding_id"],
        result["relevancy_score"],
        result["faithfulness_score"],
        result["cwe_accuracy"],
        result["overall_score"],
        result.get("llm_model", "unknown"),
        result.get("prompt_version", "unknown"),
        result["generated_explanation"],
        result["reference_explanation"],
        1 if result["overall_score"] >= 0.6 else 0
    ))
    conn.commit()
    conn.close()

def get_eval_history(limit:int=50) -> list[dict]:
    """Fetch recent evaluation results"""
    try:
        conn=sqlite3.connect(EVAL_DB_PATH)
        rows=conn.execute("""
            SELECT run_timestamp,finding_id,relevancy_score,faithfulness_score,cwe_accuracy,overall_score,llm_model,prompt_version,passed
            FROM eval_results
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [
            {
                "run_timestamp": r[0],
                "finding_id": r[1],
                "relevancy_score": r[2],
                "faithfulness_score": r[3],
                "cwe_accuracy": r[4],
                "overall_score": r[5],
                "llm_model": r[6],
                "prompt_version": r[7],
                "passed": bool(r[8])
            }
            for r in rows
        ]
    except Exception as e:
        print(f"[eval] DB read error :{e}")
        return []
    
def get_summary_stats()-> dict:
    """Compute aggregate stats across all eval runs"""
    try:
        conn=sqlite3.connect(EVAL_DB_PATH)
        row=conn.execute("""
            SELECT
                    COUNT(*) AS total,
                    AVG(relevancy_score) AS avg_relevancy,
                    AVG(faithfulness_score) AS avg_faithfulness,
                    AVG(cwe_accuracy) AS avg_cwe,
                    AVG(overall_score) AS avg_overall,
                    SUM(passed) AS total_passed
            FROM eval_results
        """).fetchone()
        conn.close()
        if not row or row[0] ==0:
            return {}
        return{
            "total_evaluations": row[0],
            "avg_relevancy": round(row[1], 3),
            "avg_faithfulness": round(row[2], 3),
            "avg_cwe_accuracy": round(row[3], 3),
            "avg_overall": round(row[4], 3),
            "pass_rate": round(row[5] / row[0] * 100, 1)
        }
    except Exception as e:
        print(f"[eval] Stats error: {e}")
        return {}
    
#Neo4j helpers
def get_explained_findings_from_neo4j() ->list[dict]:
    """Fetch all findings with LLM explanations"""
    driver=GraphDatabase.driver(NEO4J_URI,auth=(NEO4J_USER,NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            result=session.run("""
            MATCH(n)
            WHERE (n:Vulnerability OR n:Secret) AND n.explanation IS NOT NULL
            RETURN CASE WHEN n:Vulnerability THEN n.id ELSE n.rule END AS finding_id,
                            n.explanation AS explanation,
                            n.why_dangerous AS why_dangerous,
                            n.fix AS fix,
                            n.cwe AS cwe,
                            n.llm_model AS llm_model,
                            n.llm_version AS prompt_version
        """)
            return [dict(r) for r in result]
    finally:
        driver.close()


#Core Eval function
def run_eval(verbose: bool = True) -> dict:
    """
    Run eval against all findings which have LLM generated explanation in Neo4j and ground truth reference.
    Returns summary statistics dict
    """
    init_db()

    gt_lookup={gt["finding_id"]: gt for gt in GROUND_TRUTH}

    generated_findings=get_explained_findings_from_neo4j()

    if not generated_findings:
        print("[eval] No explained findings in Neo4j")
        return {}

    run_timestamp= datetime.now().isoformat()
    results=[]
    skipped=0
    print(f"\n[eval] Evaluating {len(generated_findings)} findings against {len(gt_lookup)} ground truth entries...")
    print("-" * 60)

    for finding in generated_findings:
        fid= finding.get("finding_id","")
        gt=gt_lookup.get(fid)

        if not gt:
            skipped+=1
            continue

        generated_explanation= finding.get("explanation","")
        generated_cwe=finding.get("cwe","")

        if not generated_explanation:
            skipped+=1
            continue

        relevancy=score_relevancy(
            generated_explanation,gt["reference_explanation"]
        )
        faithfulness=score_faithfulness(
            generated_explanation,gt["reference_fix"]
        )

        cwe_acc=score_cwe_accuracy(generated_cwe,gt["cwe"])

        overall=compute_overall_score(relevancy,faithfulness, cwe_acc)

        res={
            "run_timestamp": run_timestamp,
            "finding_id": fid,
            "relevancy_score": relevancy,
            "faithfulness_score": faithfulness,
            "cwe_accuracy": cwe_acc,
            "overall_score": overall,
            "llm_model": finding.get("llm_model", "unknown"),
            "prompt_version": finding.get("prompt_version", "unknown"),
            "generated_explanation": generated_explanation,
            "reference_explanation": gt["reference_explanation"]
        }
        save_result(res)
        results.append(res)

        if verbose:
            status= "Pass" if overall >=0.6 else "FAIL"
            print(f"{status} | {fid:<35} | relevancy={relevancy:.3f} | faithfulness={faithfulness:.3f} | cwe={cwe_acc:.1f} | overall={overall:.3f}")
        
        print("-" * 60)
        print(f"[eval] Evaluated: {len(results)} | Skipped (no ground truth): {skipped}")

    #Summary stats
    if res:
        avg_relevancy    = sum(r["relevancy_score"] for r in results) / len(results)
        avg_faithfulness = sum(r["faithfulness_score"] for r in results) / len(results)
        avg_cwe          = sum(r["cwe_accuracy"] for r in results) / len(results)
        avg_overall      = sum(r["overall_score"] for r in results) / len(results)
        pass_count       = sum(1 for r in results if r["overall_score"] >= 0.6)
        
        summary={
            "total_evaluated": len(results),
            "skipped": skipped,
            "avg_relevancy": round(avg_relevancy, 3),
            "avg_faithfulness": round(avg_faithfulness, 3),
            "avg_cwe_accuracy": round(avg_cwe, 3),
            "avg_overall": round(avg_overall, 3),
            "pass_rate": round(pass_count / len(results) * 100, 1),
            "passed": pass_count,
            "failed": len(results) - pass_count
        }

        print(f"\n📊 Summary:")
        print(f"   Avg Relevancy:    {summary['avg_relevancy']:.3f}")
        print(f"   Avg Faithfulness: {summary['avg_faithfulness']:.3f}")
        print(f"   Avg CWE Accuracy: {summary['avg_cwe_accuracy']:.3f}")
        print(f"   Avg Overall:      {summary['avg_overall']:.3f}")
        print(f"   Pass Rate:        {summary['pass_rate']}% ({pass_count}/{len(results)})")

        return summary
    return {}
    

#CLI entry point
if __name__ == "__main__":
    print("[eval] Starting VulnGraph LLM Evaluation Harness")
    print("[eval] Metrics: Relevancy (50%) + Faithfulness (30%) + CWE Accuracy(20%)")
    print("[eval] Pass threshold: Overall score >=  0.60\n")
    summary= run_eval(verbose=True)
    if summary:
        print(f"\n[eval] Results saved to {EVAL_DB_PATH}")   