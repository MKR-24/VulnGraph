"""
api.py — FastAPI backend for VulnGraph
 
Endpoints:
    GET  /health              → service health check
    GET  /stats               → scan metrics
    GET  /findings            → all findings (optional ?severity=HIGH&source=bandit)
    GET  /findings/{id}       → single finding with LLM explanation
    GET  /graph               → attack path data as JSON for visualization
    POST /scan                → trigger full scan + load to Neo4j (background task)
    POST /explain             → trigger LLM explanation generation (background task)
 
Run with:
    uvicorn api:app --reload --port 8000
 
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from neo4j import GraphDatabase
from dotenv import load_dotenv
import os
from pathlib import Path
from agent import run_agent_for_finding

load_dotenv()

#Config
NEO4J_URI      = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "vulngraph123")

#APP
app= FastAPI(
    title="VulnGraph API",
    description="REST API for the VulnGraph ASPM Platform, Exposes scan results,attack graph data, and LLM generated vulnerability explanations.",
    version="0.1.0",
)

#Allow Streamlit frontend to call this api
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501","http://localhost:3000","*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
#Neo4j
def get_driver():
    return GraphDatabase.driver(NEO4J_URI,auth=(NEO4J_USER,NEO4J_PASSWORD))

#Pydantic models
class HealthResponse(BaseModel):
    status:str
    neo4j:str
    ollama:str
    version:str="0.1.0"

class StatsResponse(BaseModel):
    files:int
    vulnerabilities:int
    secrets:int
    high_critical: int
    total_findings: int
    explained:int

class FindingSummary(BaseModel):
    """Lightweight finding - used in list response."""
    node_id:str
    type:str
    id:str
    severity:str
    source:str
    file:Optional[str] = None
    has_explanation: bool = False

class FindingDetail(BaseModel):
    """Full finding with LLM explanation - used in single-item responses."""
    node_id:str
    type:str
    id:str
    severity:str
    source:str
    file:Optional[str]=None
    text:Optional[str] = None
    explanation:Optional[str]=None
    why_dangerous: Optional[str]=None
    fix:Optional[str]=None
    cwe:Optional[str]=None
    llm_model:Optional[str]=None

class GraphNode(BaseModel):
    id:str
    label:str
    properties:dict

class GraphEdge(BaseModel):
    source:str
    target:str
    relationship:str  # Has Vulnerability / contains

class GraphResponse(BaseModel):
    nodes:list[GraphNode]
    edges:list[GraphEdge]
    node_count:int
    edge_count:int

class ScanResponse(BaseModel):
    status:str
    message:str

class ExplainResponse(BaseModel):
    status:str
    message:str

class AgentRequest(BaseModel):
    finding_id: str = Field(..., description="Finding ID to analyze e.g. B404")
    file_path: Optional[str] = Field(None, description="Optional file path hint")
class AgentResponse(BaseModel):
    finding_id:   str
    final_answer: str
    patch:        dict
    steps_taken:  int
    tools_called: list[str]
    duration_sec: float
    model:        str
    timestamp:    str

class SBOMResponse(BaseModel):
    format: str
    path: str
    component_count: int
    sbom: dict

class RepoScanRequest(BaseModel):
    repo_url: str = Field(..., description="Public GitHub repo URL")
    
@app.get("/sbom", tags=["SBOM"])
def get_sbom(
    format: str = Query("cyclonedx", description="SBOM format: cyclonedx or spdx-json"),
    target: Optional[str] = Query(None, description="Target path to scan")
):
    """
    Generate and return a Software Bill of Materials.
    Supports CycloneDX (OWASP) and SPDX (Linux Foundation) formats.
    """
    try:
        from scanner import generate_sbom
        result = generate_sbom(path=target, format=format)
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Background task functions

def run_scan_task():
    """Run all scanners and load findings to Neo4j"""
    try:
        from scanner import scan_all
        from main import clear_and_load_data
        clear_and_load_data()
        print("[api] Background scan completed")
    except Exception as e:
        print(f"[api] Background scan failed: {e}")
    
def run_explain_task():
    """Generate LLM explanations for all unexplained findings."""
    try:
        from llm import explain_all_findings
        results= explain_all_findings()
        print(f"[api] Background explain complete:{results}")
    except Exception as e:
        print(f"[api] Background explain failed: {e}")
    
#Endpoints
@app.get("/health",response_model=HealthResponse,tags=["System"])
def health_check():
    """
    Check if VulnGraph services are running.
    """
    neo4j_status="unreachable"
    ollama_status="unreachable"

    #Neo4j
    try:
        with get_driver().session() as session:
            session.run("RETURN 1")
        neo4j_status="connected"
    except Exception:
        pass

    #Ollama
    try:
        import requests
        r=requests.get(f"{os.getenv('OLLAMA_URL','http://localhost:11434')}",timeout=3)
        if r.status_code==200:
            ollama_status="running"
    except Exception:
        pass

    overall="healthy" if neo4j_status=="connected" else "degraded"
    return HealthResponse(status=overall,neo4j=neo4j_status,ollama=ollama_status)

@app.get("/stats", response_model=StatsResponse, tags=["Findings"])
def get_status():
    """
    Return scan metrics: file count, vulnerability count, secret count,
    high/critical count, total findings and number of LLM explanations.
    """
    try:
        with get_driver().session() as session:
            row= session.run("""
                MATCH (f:File) WITH count(f) AS files
                OPTIONAL MATCH (v:Vulnerability) WITH files, count(v) AS vulns
                OPTIONAL MATCH (s:Secret) WITH files,vulns, count(s) AS secrets
                OPTIONAL MATCH (v2:Vulnerability) WHERE toUpper(v2.severity) IN ['CRITICAL','HIGH']
                WITH files , vulns, secrets, count(v2) AS high_critical
                OPTIONAL MATCH (n) WHERE (n:Vulnerability OR n:Secret) AND n.explanation IS NOT NULL
                RETURN files, vulns,secrets,high_critical, count(n) AS explained
                            """).single()
            if not row:
                raise HTTPException(status_code=404, detail="No data found-Scan first")

            return StatsResponse(
                files=row["files"],
                vulnerabilities=row["vulns"],
                secrets=row["secrets"],
                high_critical=row["high_critical"],
                total_findings=row["vulns"]+row["secrets"],
                explained=row["explained"]
                )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error:{str(e)}")

@app.get("/findings", response_model=list[FindingSummary], tags=["Findings"])
def get_findings(
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    source: Optional[str]=Query(None,description="Filter by scanner: bandit,trivy,gitleaks"),
    limit:int=Query(50, ge=1, le=500, description="Max results to return")
):
    """
    Return all findings
    GET/findings
    GET/findings?severity=HIGH
    GET /findings?source=bandit&severity=LOW
    GET /findings?limit=10
    """
    try:
        with get_driver().session() as session:
            where_clauses=[]
            params={"limit":limit}

            if severity:
                where_clauses.append("toUpper(n.severity)=toUpper($severity)")
                params["severity"]=severity
            if source:
                where_clauses.append("n.source=$source")
                params["source"]=source
            
            and_str=("AND "+" AND ".join(where_clauses)) if where_clauses else ""

            res=session.run(f"""
                MATCH (f:File)-[]->(n)
                WHERE n:Vulnerability OR  n:Secret
                {and_str}
                RETURN elementId(n) AS node_id,
                        labels(n)[0] AS type,
                        CASE WHEN n:Vulnerability THEN n.id ELSE n.rule END AS id,
                        CASE WHEN n:Vulnerability THEN coalesce(n.severity,'UNKNOWN') Else 'SECRET' END AS severity,
                        coalesce(n.source,'unknown') AS source,
                        f.path AS file,
                        n.explanation IS NOT NULL AS has_explanation
                LIMIT $limit
            """, **params)

            return [
                FindingSummary(
                    node_id = row["node_id"],
                    type=row["type"],
                    id=row["id"] or "UNKNOWN",
                    severity=row["severity"],
                    source=row["source"],
                    file=row["file"],
                    has_explanation=row["has_explanation"]
                )
                for row in res

            ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error:{str(e)}")

@app.get("/findings/{finding_id}", response_model=FindingDetail, tags=["Findings"])
def get_finding(finding_id:str):
    """
    Return single finding by id with full LLM explanation
    """
    try:
        with get_driver().session() as session:
            res=session.run("""
                        MATCH (f:File)-[]->(n)
                        WHERE (n:Vulnerability OR n:Secret)
                        AND (n.id =$fid OR n.rule =$fid)
                        RETURN elementId(n) AS node_id,
                                labels(n)[0] AS type,
                                CASE WHEN n:Vulnerability THEN n.id ELSE n.rule END AS id,
                                CASE WHEN n:Vulnerability THEN coalesce(n.severity,'UNKNOWN') ELSE 'SECRET' END AS severity,
                                coalesce(n.source,'unknown') AS source,
                                f.path AS file,
                                coalesce(n.text,n.title,'') AS text,
                                n.explanation AS explanation,
                                n.why_dangerous AS why_dangerous,
                                n.fix as fix,
                                n.cwe AS cwe,
                                n.llm_model AS llm_model
                            LIMIT 1                                      
                            """, fid=finding_id).single()
        if res is None:
            raise HTTPException(
                status_code=404,
                detail=f"Finding '{finding_id} not found. Check ID or run scan"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500,detail=f"DB error:{str(e)}")
    
    return FindingDetail(
        node_id=res["node_id"],
        type=res["type"],
        id=res["id"] or finding_id,
        severity=res['severity'],
        source=res["source"],
        file=res["file"],
        text=res["text"],
        explanation=res["explanation"],
        why_dangerous=res["why_dangerous"],
        fix=res["fix"],
        cwe=res["cwe"],
        llm_model=res["llm_model"]
    )
    

@app.get("/graph", response_model=GraphResponse,tags=["Graph"])
def get_graph(limit:int=Query(200,ge=1,le=1000)):
    """
    Return attack path graph  data as JSON-nodes and edges.
    Node labels: File, Vulnerability,Secret
    Edge types: HAS_Vulnerability, CONTAINS
    """
    try:
        with get_driver().session() as session:
            edge_res=session.run("""
                    MATCH (n)-[r]->(m)
                    RETURN elementId(n) AS src_id,
                            elementId(m) AS tgt_id,
                            labels(n)[0] AS src_label,
                            labels(m)[0] AS tgt_label,
                            type(r) AS rel_type,
                            properties(n) AS src_props,
                            properties(m) AS tgt_props
                    LIMIT $limit                                     
                """,limit=limit)
            nodes={}
            edges=[]
            for row in edge_res:
                # Source node add
                if row["src_id"] not in nodes:
                    nodes[row["src_id"]] = GraphNode(
                        id=row["src_id"],
                        label=row["src_label"],
                        properties=dict(row["src_props"])
                    )
                # Add target node
                if row["tgt_id"] not in nodes:
                    nodes[row["tgt_id"]] = GraphNode(
                        id=row["tgt_id"],
                        label=row["tgt_label"],
                        properties=dict(row["tgt_props"])
                    )
                # Add edge
                edges.append(GraphEdge(
                    source=row["src_id"],
                    target=row["tgt_id"],
                    relationship=row["rel_type"]
                ))
            return GraphResponse(
                nodes=list(nodes.values()),
                edges=edges,
                node_count=len(nodes),
                edge_count=len(edges)
            )
    except Exception as e:
        raise HTTPException(status_code=500,detail=f"DB error:{str(e)}")

@app.post("/scan",response_model=ScanResponse, status_code=202,tags=["Actions"])
def trigger_scan(background_task:BackgroundTasks):
    """
    Full scan start in background
    Returns 202 if the server accepts
    """
    background_task.add_task(run_scan_task)
    return ScanResponse(
        status="accepted",
        message="Scan started in background."
    )

@app.post("/explain",response_model=ExplainResponse,status_code=202,tags=["Actions"])
def trigger_explain(background_tasks: BackgroundTasks):
    """
    LLM explanation for unexplained findings
    """
    background_tasks.add_task(run_explain_task)
    return ExplainResponse(
        status="accepted",
        message="Explanation generation started"
    )

@app.post("/agent/fix", response_model=AgentResponse, tags=["Agent"])
async def agent_fix(request: AgentRequest, background_tasks: BackgroundTasks):
    """
    Synchronous endpoint — blocks for 60-120 seconds.
    For production use, convert to async with a job queue.
    """
    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None, 
        run_agent_for_finding, 
        request.finding_id, 
        request.file_path
    )
    return AgentResponse(**result)

def clone_and_scan(repo_url: str):
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, tmpdir],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            print(f"[api] Clone failed: {result.stderr}")
            return
        from scanner import scan_all
        findings = scan_all(target_dir=tmpdir)
        print(f"[api] Scan complete: { {k: len(v) for k, v in findings.items()} }")
    
@app.post("/scan/repo", tags=["Actions"], status_code=202)
async def scan_repo(request: RepoScanRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(clone_and_scan, request.repo_url)
    return {"status": "accepted", "repo": request.repo_url}

#Entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app",host="0.0.0.0",port=8000,reload=True)