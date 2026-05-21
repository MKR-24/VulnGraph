"""
agent.py - ReAct agent for VulnGraph

The loop:
    1. THINK  — agent reasons about what it knows and what it needs
    2. ACT    — agent calls a tool with specific parameters
    3. OBSERVE — agent reads the tool result
    4. REPEAT  — until agent has enough to give a final answer

For VulnGraph, the agent's job is:
    Given a finding ID → understand it → see the code → generate a patch
"""
import json
import os
import argparse
from datetime import datetime
from typing import Optional
from dotenv import load_dotenv


from tools import(
    TOOL_REGISTRY,
    ToolResult
)

load_dotenv()

#Config
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL", "llama3.2:3b")


#Tool executor
def execute_tool(tool_name:str,parameters:dict)->ToolResult:
    """
    Execute a tool by name with given parameters.
    Looks up the tool in TOOL_REGISTRY and calls it.
    """
    if tool_name not in TOOL_REGISTRY:
        return ToolResult(
            tool_name=tool_name,
            status="error",
            error=f"Unknown tool '{tool_name}'Available: {list(TOOL_REGISTRY.keys())}"
        )
    tool_fn=TOOL_REGISTRY[tool_name]["function"]
    req=TOOL_REGISTRY[tool_name].get("required",[])

    #check required params
    missing=[p for p in req if p not in parameters]
    if missing:
        return ToolResult(
            tool_name=tool_name,
            status="error",
            error=f"Missing required parameters :{missing} "

        )
    try:
        return tool_fn(**parameters)
    except TypeError as e:
        return ToolResult(
            tool_name=tool_name,
            status="error",
            error=f"Parameter error:{e}"
        )
def _build_final_answer(finding_id, graph_result, kb_result,explanation_result, file_result, patch_result) -> str:
    parts = [f"# Security Analysis: {finding_id}\n"]

    if graph_result.status == "success":
        parts.append(f"## Finding Details\n{graph_result.data}\n")

    if explanation_result.status == "success":
        parts.append(f"## AI Explanation\n{explanation_result.data}\n")

    if kb_result.status == "success":
        parts.append(f"## Security References\n{kb_result.data[:500]}\n")

    if file_result and file_result.status == "success":
        parts.append(f"## Vulnerable Code\n{file_result.data}\n")

    if patch_result and patch_result.status == "success":
        parts.append(f"## Generated Patch\n{patch_result.data}\n")
    else:
        parts.append("## Patch\nPatch generation failed or was skipped.\n")

    return "\n".join(parts)
#Agent run
class Agent:
    """
    ReAct agent that analyzes vulnerability findings and generates patches.

    The agent maintains:
    - messages: full conversation history (system + user + assistant turns)
    - steps: count of reasoning steps taken
    - observations: list of tool results for final summary
    """
    def __init__(self,verbose:bool=True):
        self.verbose=verbose
        self.observations=[]
        self.tools_called=[]

    def _log(self,msg:str,prefix:str=""):
        if self.verbose:
            print(f"{prefix}{msg}")

    def run(self, finding_id: str, file_path: Optional[str] = None) -> dict:
        start_time = datetime.now()
        self._log(f"\n{'='*60}")
        self._log(f"VulnGraph Agent starting for finding: {finding_id}")
        self._log(f"{'='*60}\n")

        # Step 1 — Query attack graph
        self._log("[Step 1/5] Querying attack graph...")
        graph_result = execute_tool("query_attack_graph", {"finding_id": finding_id})
        self._log(f"Status: {graph_result.status}")
        self.observations.append({
            "step": 1,
            "tool": "query_attack_graph",
            "status": graph_result.status,
            "observation": graph_result.data[:200]
        })
        # Step 2 — Search knowledge base
        self._log("[Step 2/5] Searching knowledge base...")
        kb_query = finding_id
        if graph_result.status == "success":
            desc = graph_result.metadata.get("description", "")
            severity = graph_result.metadata.get("severity", "")
            source = graph_result.metadata.get("source", "")
            kb_query = f"{finding_id} {desc} {severity} {source}".strip()
            self._log(f"KB query: {kb_query}")

        kb_result = execute_tool("search_knowledge_base", {"query": kb_query})
        self._log(f"Status: {kb_result.status}")
        self.observations.append({
            "step": 2,
            "tool": "search_knowledge_base",
            "status": kb_result.status,
            "observation": kb_result.data[:200]
        })
        # Step 3 — Get existing explanation
        self._log("[Step 3/5] Fetching existing explanation...")
        explanation_result = execute_tool("get_finding_explanation", {"finding_id": finding_id})
        self._log(f"Status: {explanation_result.status}")
        self.observations.append({
            "step": 3,
            "tool": "get_finding_explanation",
            "status": explanation_result.status,
            "observation": explanation_result.data[:200]
        })
        # Step 4 — Get file context
        # Extract file path from graph result if not provided
        actual_file = file_path
        if not actual_file and graph_result.status == "success":
            files = graph_result.metadata.get("affected_files", [])
            if files:
                actual_file = files[0]
                if not actual_file.startswith("app/"):
                    actual_file=f"app/{actual_file}"
                self._log(f"Discovered file from graph: {actual_file}")

        file_result = None
        if actual_file:
            self._log(f"[Step 4/5] Getting file context for {actual_file}...")
            file_result = execute_tool("get_file_context", {
                "file_path": actual_file,
                "line_number": 1
            })
            self._log(f"Status: {file_result.status}")
            self.observations.append({
            "step": 4,
            "tool": "get_file_context",
            "status": file_result.status,
            "observation": file_result.data[:200] if file_result.status== "success" else file_result.error
            })
        else:
            self._log("[Step 4/5] No file path available — skipping file context")

        # Step 5 — Generate patch with all gathered context
        self._log("[Step 5/5] Generating patch...")
        patch_result = None
        if actual_file and file_result and file_result.status == "success":
            patch_result = execute_tool("generate_patch", {
                "file_path": actual_file,
                "line_number": graph_result.metadata.get("line_number", 1) or 1,
                "finding_id": finding_id,
                "code_context": file_result.data,
                "vulnerability_description": graph_result.data,
                "knowledge_context": kb_result.data if kb_result.status == "success" else ""
            })
            self._log(f"Status: {patch_result.status if patch_result else 'skipped'}")
            self.observations.append({
            "step": 5,
            "tool": "generate_patch",
            "status": patch_result.status if patch_result else "skipped",
            "observation": patch_result.data[:200] if patch_result and patch_result.status=="success" else ""
            })
        # Build final answer from all gathered context
        final_answer = _build_final_answer(
            finding_id, graph_result, kb_result,
            explanation_result, file_result, patch_result
        )

        duration = (datetime.now() - start_time).total_seconds()
        tools_called = ["query_attack_graph", "search_knowledge_base",
                        "get_finding_explanation"]
        if file_result:
            tools_called.append("get_file_context")
        if patch_result:
            tools_called.append("generate_patch")

        self._log(f"\nAgent completed in {duration:.1f}s")
        self._log(f"Tools used: {' → '.join(tools_called)}")
        
        return {
            "finding_id": finding_id,
            "final_answer": final_answer,
            "patch": patch_result.metadata.get("patch", {}) if patch_result and patch_result.status == "success" else {},
            "steps_taken": 5,
            "tools_called": tools_called,
            "observations": self.observations,
            "duration_sec": round(duration, 2),
            "model": OLLAMA_MODEL,
            "timestamp": datetime.now().isoformat()
        }
    
def run_agent_for_finding(finding_id:str, file_path:Optional[str]=None)->dict:
    """
    For calling agent using FASTAPI
    """
    agent=Agent(verbose=False)
    return agent.run(finding_id,file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnGraph ReAct Agent")
    parser.add_argument("--finding", required=True, help="Finding ID to analyze e.g. B404")
    parser.add_argument("--file", default=None, help="File path hint (optional)")
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose output")
    args = parser.parse_args()

    agent = Agent(verbose=not args.quiet)
    result = agent.run(args.finding, args.file)

    print("\n" + "="*60)
    print("FINAL RESULT")
    print("="*60)
    print(f"Finding:      {result['finding_id']}")
    print(f"Steps taken:  {result['steps_taken']}")
    print(f"Tools called: {' → '.join(result['tools_called'])}")
    print(f"Duration:     {result['duration_sec']}s")
    if result.get("patch"):
        print(f"\nPatch generated: {result['patch'].get('patch_description', 'N/A')}")
    print(f"\nFinal Answer:\n{result['final_answer']}")