"""
mcp_server.py — VulnGraph MCP Server

Exposes VulnGraph's security analysis tools over the Model Context Protocol (MCP).
Any MCP-compatible client (Claude Desktop, Cursor, other agents) can use these tools
to analyze vulnerabilities, query the attack graph, and generate patches.

Architecture:
    tools.py          — pure Python tool implementations
    mcp_server.py     — exposes tools.py over MCP protocol (this file)
    agent.py          — VulnGraph's own deterministic pipeline using tools.py

This separation means tools work in three ways:
    1. Called directly by agent.py (deterministic pipeline)
    2. Called by MCP clients via this server (Claude Desktop, Cursor, etc.)
    3. Called via FastAPI endpoints
"""
import asyncio
import json
import os
import sys
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types
from rag import get_collection
from tools import (
    search_knowledge_base,
    get_file_context,
    query_attack_graph,
    generate_patch,
    get_finding_explanation,
    TOOL_REGISTRY
)

load_dotenv()

server=Server("vulngraph")

#Tool definition in MCP format
@server.list_tools()
async def list_tools()-> list[types.Tool]:
    return [
        types.Tool(
            name="search_knowledge_base",
            description="Search the VulnGraph security knowledge base containing CWE definitions, OWASP Top 10, and Bandit rule documentation. Use this to understand what a vulnerability type means and get remediation context.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query e.g. 'subprocess command injection B404' or 'hardcoded password CWE-259'"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of documents to retrieve (default 3)",
                        "default": 3
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="get_file_context",
            description="Read the code around a specific line number in a file. Use this to see the actual vulnerable code before generating a patch.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to the file e.g. 'app/scanner.py'"
                    },
                    "line_number": {
                        "type": "integer",
                        "description": "The vulnerable line number"
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Lines of context around the vulnerable line (default 10)",
                        "default": 10
                    }
                },
                "required": ["file_path", "line_number"]
            }
        ),
        types.Tool(
            name="query_attack_graph",
            description="Query the Neo4j attack graph for a finding's details, severity, affected files, and attack path context. Returns CWE, description, and existing LLM explanation if available.",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "Vulnerability or rule ID e.g. 'B404', 'CVE-2024-1234', 'hugging-face-access-token'"
                    }
                },
                "required": ["finding_id"]
            }
        ),
        types.Tool(
            name="generate_patch",
            description="Generate a concrete code patch to fix a security vulnerability. Call this after gathering context from query_attack_graph, search_knowledge_base, and get_file_context.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the vulnerable file"
                    },
                    "line_number": {
                        "type": "integer",
                        "description": "Line number of the vulnerability"
                    },
                    "finding_id": {
                        "type": "string",
                        "description": "Vulnerability ID e.g. B404"
                    },
                    "code_context": {
                        "type": "string",
                        "description": "Code snippet from get_file_context"
                    },
                    "vulnerability_description": {
                        "type": "string",
                        "description": "Description of what the vulnerability is"
                    },
                    "knowledge_context": {
                        "type": "string",
                        "description": "Security references from search_knowledge_base (optional)",
                        "default": ""
                    }
                },
                "required": ["file_path", "line_number", "finding_id", "code_context", "vulnerability_description"]
            }
        ),
        types.Tool(
            name="get_finding_explanation",
            description="Fetch the existing LLM-generated explanation for a vulnerability from the VulnGraph database. Returns what the vulnerability is, why it's dangerous, how to fix it, and the CWE reference.",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "Vulnerability or rule ID e.g. 'B404', 'CVE-2024-1234'"
                    }
                },
                "required": ["finding_id"]
            }
        )
    ]
#Tool handlers
@server.call_tool()
async def call_tool(name: str, arguments: dict)-> list[types.TextContent]:
    """
    Handle tool calls from MCP clients.
    Dispatches to the appropriate tool function and returns results
    """
    loop=asyncio.get_event_loop()
    
    try:
        if name == "search_knowledge_base":
            res=await loop.run_in_executor(
                None,
                lambda: search_knowledge_base(
                    query=arguments["query"],
                    top_k= arguments.get("top_k",3)
                )
            )
        elif name == "get_file_context":
            res = await loop.run_in_executor(
                None,
                lambda: get_file_context(
                    file_path=arguments["file_path"],
                    line_number=arguments["line_number"],
                    context_lines=arguments.get("context_lines", 10)
                )
            )
        elif name == "query_attack_graph":
            res = await loop.run_in_executor(
                None,
                lambda: query_attack_graph(
                    finding_id=arguments["finding_id"]
                )
            )
        elif name == "generate_patch":
            res = await loop.run_in_executor(
                None,
                lambda: generate_patch(
                    file_path=arguments["file_path"],
                    line_number=arguments["line_number"],
                    finding_id=arguments["finding_id"],
                    code_context=arguments["code_context"],
                    vulnerability_description=arguments["vulnerability_description"],
                    knowledge_context=arguments.get("knowledge_context", "")
                )
            )
        elif name == "get_finding_explanation":
            res = await loop.run_in_executor(
                None,
                lambda: get_finding_explanation(
                    finding_id=arguments["finding_id"]
                )
            )
        else:
            return [types.TextContent(
                type="text",
                text=f"Unknown tool: {name}. Available tools: {list(TOOL_REGISTRY.keys())}"
            )]
        if res.status== "error":
            resp_text=f"Error: {res.error}"
        elif res.status == "empty":
            resp_text = f"No results found for this query."
        else:
            resp_text = res.data

        return [types.TextContent(type="text", text=resp_text)]
    except Exception as e:
        return [types.TextContent(
            type="text",
            text=f"Tool execution failed: {str(e)}"
        )]
    
#Server info

@server.list_resources()
async def list_resources()->list[types.Resource]:
    """Expose KB stats as resource"""
    return [
        types.Resource(
            uri="vulngraph://knowledge-base/stats",
            name="Knowledge Base Stats",
            description="Statistics about the VulnGraph security knowledge base",
            mimeType="application/json"
        )
    ]

@server.read_resource()
async def read_resource(uri:str)->str:
    """Return KB stats"""
    if uri == "vulngraph://knowledge-base/stats":
        try :
            collection=get_collection()
            ct= collection.count()
            return json.dumps({
                "total_documents":ct,
                "collection_name": "vulngraph-knowledge",
                "embed-model": "all-MiniLM-L6-v2"

            })
        except Exception as e:
            return json.dumps({"error": str(e)})
    raise ValueError(f"Unknown resource: {uri}")

#Entry point

async def main():
    print("[mcp] VulnGraph MCP Server starting...", file=sys.stderr, flush=True)
    print(f"[mcp] Exposing {len(TOOL_REGISTRY)} tools", file = sys.stderr, flush=True)
    print("[mcp] Ready for connections",file=sys.stderr, flush=True)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )
if __name__ == "__main__":
    asyncio.run(main())