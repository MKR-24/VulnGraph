"""
Tool implementations for VulnGraph ReAct agent

Each tool has clear function:
Input: typed parameters
Output: ToolResult with status ,data and error

Tools:
search_knowledge_base - semantic search over CWE/OWASP/Bandit docs
get_file_context- read code around specific line number
query_attack_graph - query Neo4j for finding details and relationships
generate_patch- use LLM to generate a code fix for finding
get_finding_explanation - fetch existing LLM explanation from Neo4j
"""
import os
import json
from pathlib import Path
from typing import Optional
from dataclasses import dataclass,field
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

#Config
NEO4J_URI      = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "vulngraph123")
BASE_DIR       = Path(__file__).parent.parent.resolve()
CONTEXT_LINES  = 10  # lines of code to show around the vulnerable line

#ToolResult
@dataclass
class ToolResult:
    """
    Standard return type for all
    The agent uses status to decide whether to retry or move on.
    Data is what gets injected into agent's observation
    """
    tool_name: str
    status: str
    data: str =""
    metadata: dict=field(default_factory=dict)
    error: str=""

    def to_observation(self)->str:
        """Format result as observation string for agent's reasoning loop"""
        if self.status=="error":
            return f"[{self.tool_name}] ERROR: {self.error}"
        if self.status=="empty":
            return f"[{self.tool_name}] No results found. "
        return  f"[{self.tool_name}] \n {self.data}"
    
def search_knowledge_base(query:str,top_k: int=3)->ToolResult:
    """
    Semantic search over the VulnGraph knowledge base (CWE, OWASP, Bandit docs).
    Uses the same ChromaDB collection as the RAG pipeline.

    Args:
        query: natural language search query e.g. "subprocess command injection"
        top_k: number of documents to retrieve (default 3)

    Returns:
        ToolResult with formatted context string ready for agent observation
    """

    try:
        from rag import retrieve_context
        context =retrieve_context(
            finding_id=query,
            find_txt=query,
            top_k=top_k
        )
        if not context:
            return ToolResult(
                tool_name="search_knowledge_base",
                status="empty",
                data="",
                metadata={"query":query}
            )
        return ToolResult(
            tool_name="search_knowledge_base",
            status="success",
            data=context,
            metadata={"query":query, "top_k":top_k}
        )
    except Exception as e:
        return ToolResult(
            tool_name="search_knowledge_base",
            status="error",
            error=str(e),
            metadata={"query":query}
        )
    
def get_file_context(
    file_path: str,
    line_number: int,
    context_lines: int = CONTEXT_LINES,
    target_dir: Optional[str] = None
) -> ToolResult:
    """
    Read code around a specific line number from a file.
    The agent uses this to see the actual vulnerable code before generating a patch.

    Args:
        file_path:     relative path to file (as stored in Neo4j)
        line_number:   the vulnerable line number
        context_lines: how many lines before/after to include
        target_dir:    override base directory (for scanning external repos)

    Returns:
        ToolResult with code snippet and line numbers
    """
    try:
        base=Path(target_dir) if target_dir else BASE_DIR
        full_path=base/file_path

        if not full_path.exists():
            full_path=Path(file_path)
            if not full_path.exists():
                return ToolResult(
                tool_name="get_file_context",
                status="error",
                error=f"File not found: {file_path}",
                metadata={"file_path":file_path,"line_number":line_number}
            )
        with open(full_path,"r",encoding="utf-8",errors="replace") as f:
            lines=f.readlines()

        total_lines=len(lines)
        start=max(0,line_number-context_lines-1)
        end=min(total_lines,line_number+context_lines)

        snippet_lines=[]
        for i , line in enumerate(lines[start:end],start=start+1):
            marker=">>>"if i==line_number else "   "
            snippet_lines.append(f"{marker}{i:4d} | {line.rstrip()}")

        snippet= "\n".join(snippet_lines)
        data=f"File: {file_path}\n Vulnerable Line: {line_number}\n\n{snippet}"

        return ToolResult(
                tool_name="get_file_context",
                status="success",
                data=data,
                metadata={"file_path":file_path, "line_number":line_number, "start_line": start+1,"end_line":end,"total_lines":total_lines}
        )
    except Exception as e:
        return ToolResult(
                tool_name="get_file_context",
                status="error",
                error=str(e),
                metadata={"file_path":file_path, "line_number":line_number}
        )
    
def query_attack_graph(finding_id:str)-> ToolResult:
    """
    Query Neo4j for a finding's details, connected files, and attack path context.
    Gives the agent graph-level context — not just the finding in isolation.

    Args:
        finding_id: vulnerability/rule ID e.g. "B404", "CVE-2025-1234"

    Returns:
        ToolResult with finding details, connected files, and severity
    """
    try:
        driver=GraphDatabase.driver(NEO4J_URI,auth=(NEO4J_USER,NEO4J_PASSWORD))
        with driver.session() as session:
            res=session.run("""
                        MATCH (f:File)-[r]->(n)
                        WHERE (n:Vulnerability OR n:Secret)
                        AND (n.id =$fid OR n.rule=$fid)
                        RETURN f.path AS file_path,
                                type(r) AS relationship,
                                labels(n)[0] AS node_type,
                                CASE WHEN n:Vulnerability THEN n.id ELSE n.rule END AS id,
                                CASE WHEN n:Vulnerability THEN coalesce(n.severity,"UNKNOWN")
                                ELSE 'SECRET' END AS severity,
                                coalesce(n.source,'unknown') AS source,
                                coalesce(n.text,n.title,'') AS description,
                                n.explanation AS existing_explanation,
                                n.cwe AS cwe
                            """, fid=finding_id)
            rows=[dict(r) for r in res]
            driver.close()
        
        if not rows:
            return ToolResult(
                tool_name="query_attack_graph",
                status="empty",
                metadata={"finding_id": finding_id}
            )
        # Format as readable summary
        lines = [f"Finding: {finding_id}"]
        lines.append(f"Type: {rows[0]['node_type']}")
        lines.append(f"Severity: {rows[0]['severity']}")
        lines.append(f"Source: {rows[0]['source']}")
        if rows[0].get("cwe"):
            lines.append(f"CWE: {rows[0]['cwe']}")
        if rows[0].get("description"):
            lines.append(f"Description: {rows[0]['description'][:200]}")
        if rows[0].get("existing_explanation"):
            lines.append(f"Existing explanation: {rows[0]['existing_explanation'][:200]}")

        lines.append(f"\n Affected files ({len(rows)})")
        for row in rows:
            lines.append(f" -{row['file_path']} [{row['relationship']}]")

        return ToolResult(
            tool_name="query_attack_graph",
            status="success",
            data="\n".join(lines),
            metadata={
                "finding_id": finding_id,
                "affected_files": [r["file_path"] for r in rows],
                "severity": rows[0]["severity"],
                "source": rows[0]["source"],
                "node_type": rows[0]["node_type"],
                "description": rows[0].get("description", "")
            }
        )
    except Exception as e:
        return ToolResult(
            tool_name="query_attack_graph",
            status="error",
            error=str(e),
            metadata={"finding_id": finding_id}
        )
    
def generate_patch(
    file_path: str,
    line_number: int,
    finding_id: str,
    code_context: str,
    vulnerability_description: str,
    knowledge_context: str = ""
) -> ToolResult:
    """
    Use the LLM to generate a concrete code patch for a vulnerability.
    This is the most complex tool — it synthesizes all previous observations.

    Args:
        file_path:                  path to the vulnerable file
        line_number:                line number of the vulnerability
        finding_id:                    vulnerability ID (B404, CVE-xxx, etc.)
        code_context:                   code snippet from get_file_context
        vulnerability_description:         what the vulnerability is
        knowledge_context:              RAG-retrieved security references

    Returns:
        ToolResult with the generated patch as a unified diff
    """
    import requests as http_requests

    ollama_url =os.getenv("OLLAMA_URL","http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL","llama3.2:3b")

    prompt = f"""You are a senior security engineer. Generate a concrete code patch to fix this vulnerability.

        Vulnerability: {finding_id}
        File: {file_path} (line {line_number})
        Description: {vulnerability_description}
        
        Current code:
        {code_context}
        
        Security references:
        {knowledge_context if knowledge_context else "No additional context available."}
        
        Respond ONLY with a JSON object — no preamble, no markdown:
        {{
        "patch_description": "One sentence describing what the patch does",
        "patched_code": "The fixed version of the vulnerable code section",
        "explanation": "Why this patch fixes the vulnerability",
        "breaking_changes": "Any breaking changes or migration notes, or null if none"
    }}"""
    try:
        response=http_requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": ollama_model,
                "prompt":prompt,
                "stream":False,
                "format":"json",
                "options":{"temperature":0.1,"num_predict":600}
            },
            timeout=120
        )
        response.raise_for_status()
        raw= response.json().get("response","").strip()

        #Strip markdown fences if model ignores format=json
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        parsed = json.loads(raw)
        required = {"patch_description", "patched_code", "explanation"}
        if not required.issubset(parsed.keys()):
            return ToolResult(
                tool_name="generate_patch",
                status="error",
                error=f"LLM response missing required fields: {parsed.keys()}",
                metadata={"finding_id": finding_id}
            )
        data= (
            f"Patch for {finding_id} in {file_path}:{line_number}\n\n"
            f"Description: {parsed['patch_description']}\n\n"
            f"Fixed code:\n{parsed['patched_code']}\n\n"
            f"Why this fixes it: {parsed['explanation']}\n"
        )
        if parsed.get("breaking_changes"):
            data+=f"\nBreaking changes: {parsed['breaking_changes']}"

        return ToolResult(
            tool_name="generate_patch",
            status="success",
            data=data,
            metadata={
                "finding_id": finding_id,
                "file_path": file_path,
                "line_number": line_number,
                "patch": parsed
            }
        )
    except json.JSONDecodeError as e:
        return ToolResult(
            tool_name="generate_patch",
            status="error",
            error=f"JSON parse failed: {e}. Raw: {raw[:200]}",
            metadata={
                "finding_id": finding_id
            }
        )
    except Exception as e:
        return ToolResult(
            tool_name="generate_patch",
            status="error",
            error=str(e),
            metadata={
                "finding_id": finding_id
            }
        )

def get_finding_explanation(finding_id: str) -> ToolResult:
    """
    Fetch the existing LLM-generated explanation for a finding from Neo4j.
    Use this to check if a finding already has an explanation before generating
    a new one — avoids redundant LLM calls.

    Args:
        finding_id: vulnerability/rule ID e.g. "B404", "CVE-2024-1234"

    Returns:
        ToolResult with explanation, why_dangerous, fix, and cwe fields
    """
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session() as session:
            result = session.run("""
                MATCH (n)
                WHERE (n:Vulnerability OR n:Secret)
                AND (n.id = $fid OR n.rule = $fid)
                AND n.explanation IS NOT NULL
                RETURN  n.explanation    AS explanation,
                        n.why_dangerous  AS why_dangerous,
                        n.fix            AS fix,
                        n.cwe            AS cwe,
                        n.llm_model      AS llm_model,
                        n.llm_version    AS prompt_version
                LIMIT 1
            """, fid=finding_id).single()
        driver.close()

        if not result:
            return ToolResult(
                tool_name="get_finding_explanation",
                status="empty",
                metadata={"finding_id": finding_id}
            )

        data = (
            f"Existing explanation for {finding_id}:\n\n"
            f"WHAT: {result['explanation']}\n\n"
            f"RISK: {result['why_dangerous']}\n\n"
            f"FIX: {result['fix']}\n\n"
            f"CWE: {result.get('cwe') or 'N/A'}\n"
            f"Model: {result.get('llm_model') or 'unknown'}"
        )

        return ToolResult(
            tool_name="get_finding_explanation",
            status="success",
            data=data,
            metadata={
                "finding_id": finding_id,
                "explanation": result["explanation"],
                "why_dangerous": result["why_dangerous"],
                "fix": result["fix"],
                "cwe": result.get("cwe"),
                "llm_model": result.get("llm_model")
            }
        )
    except Exception as e:
        return ToolResult(
            tool_name="get_finding_explanation",
            status="error",
            error=str(e),
            metadata={"finding_id": finding_id}
        )
#Tool Registry
# The agent uses this to discover available tools at runtime.
# The MCP server also reads this registry to expose tools over the protocol.
TOOL_REGISTRY = {
    "search_knowledge_base": {
        "function": search_knowledge_base,
        "description": "Search the security knowledge base (CWE, OWASP, Bandit) for information about a vulnerability type. Use this first to understand what a finding means.",
        "parameters": {
            "query": "Search query string e.g. 'subprocess command injection'",
            "top_k": "Number of documents to retrieve (default 3)"
        },
        "required": ["query"]
    },
    "get_file_context": {
        "function": get_file_context,
        "description": "Read the code around a specific line number in a file. Use this to see the actual vulnerable code before generating a patch.",
        "parameters": {
            "file_path": "Relative path to the file as stored in Neo4j",
            "line_number": "The vulnerable line number",
            "context_lines": "Lines of context around the vulnerable line (default 10)"
        },
        "required": ["file_path", "line_number"]
    },
    "query_attack_graph": {
        "function": query_attack_graph,
        "description": "Query the Neo4j attack graph for a finding's details, severity, and which files are affected. Use this to understand the scope of a vulnerability.",
        "parameters": {
            "finding_id": "Vulnerability or rule ID e.g. 'B404', 'CVE-2025-1234'"
        },
        "required": ["finding_id"]
    },
    "generate_patch": {
        "function": generate_patch,
        "description": "Generate a concrete code patch to fix a vulnerability. Use this last, after you have retrieved knowledge context and file context.",
        "parameters": {
            "file_path": "Path to the vulnerable file",
            "line_number": "Line number of the vulnerability",
            "finding_id": "Vulnerability ID",
            "code_context": "Code snippet from get_file_context",
            "vulnerability_description": "Description of the vulnerability",
            "knowledge_context": "RAG context from search_knowledge_base (optional)"
        },
        "required": ["file_path", "line_number", "finding_id", "code_context", "vulnerability_description"]
    },
    "get_finding_explanation": {
    "function": get_finding_explanation,
    "description": "Fetch the existing LLM explanation for a finding from Neo4j. Use this before generate_patch to check if an explanation already exists and understand the vulnerability context.",
    "parameters": {
        "finding_id": "Vulnerability or rule ID e.g. 'B404', 'CVE-2024-1234'"
    },
    "required": ["finding_id"]
    }
}
def get_tool_description()-> str:
    """
    Format all tool descriptions for injection into the agent's system prompt.
    The agent reads this to know what tools are available.
    """
    lines = ["Available tools:\n"]
    for name, info in TOOL_REGISTRY.items():
        lines.append(f"- {name}: {info['description']}")
        required = info.get("required", [])
        lines.append(f"  Required parameters: {', '.join(required)}")
    return "\n".join(lines)

# ── CLI test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Testing VulnGraph agent tools\n")

    # Test 1: Knowledge base search
    print("=" * 50)
    print("Test 1: search_knowledge_base")
    result = search_knowledge_base("subprocess command injection B404")
    print(result.to_observation()[:300])

    # Test 2: File context
    print("\n" + "=" * 50)
    print("Test 2: get_file_context")
    result = get_file_context("app/scanner.py", 30)
    print(result.to_observation()[:300])

    # Test 3: Attack graph query
    print("\n" + "=" * 50)
    print("Test 3: query_attack_graph")
    result = query_attack_graph("B404")
    print(result.to_observation())

    # Test 4: Tool registry
    print("\n" + "=" * 50)
    print("Test 4: Tool descriptions")
    print(get_tool_description())

    # Test 5: Get existing explanation
    print("\n" + "=" * 50)
    print("Test 5: get_finding_explanation")
    result = get_finding_explanation("B404")
    print(result.to_observation()[:300])