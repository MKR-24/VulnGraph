from platform import node
import streamlit as st
from neo4j import GraphDatabase
from pyvis.network import Network
import os
from dotenv import load_dotenv
from scanner import scan_all
import time
from pathlib import Path
time.sleep(5)
API_KEY = "sk-1234567890abcdef1234567890abcdef12345678"
#Neo4j connection setup
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j" ,"vulngraph123"))
BASE_DIR = Path(__file__).parent.parent.resolve()
def normalize_path(raw_path: str) -> str:
    """Convert absolute or relative path to project-relative forward-slash path."""
    path_str = str(raw_path).replace("\\", "/").strip()
    base_str = str(BASE_DIR).replace("\\", "/") + "/"
    if path_str.startswith(base_str):
        path_str = path_str[len(base_str):]
    path_str = path_str.lstrip("./")
    return path_str if path_str else ""
def clear_and_load():
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")  # Clear existing da
    findings = scan_all()
    with driver.session() as session:
        # Create File nodes
        for root, _, files in os.walk("."):
            if any(x in root for x in ['.git', "tools", ".venv", "__pycache__"]):
                continue
            for f in files:
                path = os.path.join(root, f).replace("\\", "/").lstrip("./")
                session.run("MERGE (f:File {path: $path})", path=path)
        #Secrets from GitLeaks
        for item in findings["gitleaks"]:
            file_path = normalize_path(item["File"])
            if not file_path:
                continue
            session.run("""
                MATCH (f:File {path: $file_path})
                MERGE (s:Secret {rule: $rule, line: $line})
                MERGE (f)-[:CONTAINS]->(s)
            """, file_path=file_path, rule=item["RuleID"], line=item["Startline"])

        #Vulnerabilities from Bandit
        project_root=str(BASE_DIR).replace("\\", "/") + "/"
        for item in findings["bandit"]:
            file_path= normalize_path(item["filename"])

            if not file_path or ".." in file_path:
                continue

            issue_id= item.get("issue_code", "UNKNOWN")
            severity= item.get("issue_severity", "UNDEFINED")
            issue_text= item.get("issue_text", "")[:150]

            session.run("""
                MATCH (f:File {path: $file_path})
                MERGE (v:Vulnerability {id: $issue_id, severity: $severity})
                ON CREATE SET v.text = $text,v.confidence= $confidence
                MERGE (f)-[:HAS_VULNERABILITY]->(v)
            """,
            file_path=file_path,
            issue_id=issue_id,
            severity=severity,
            text=issue_text,
            confidence=item.get("issue_confidence", "UNDEFINED")
            )

        #Vulnerabilities from Trivy
        for result_obj in findings["trivy"]:
            target_path= result_obj.get("Target", "").replace("\\", "/")
            if not target_path or any(x in target_path for x in ['.git', "tools", ".venv",]):
                continue
            #match file node
            session.run("MERGE (f:File {path: $path})", path=target_path)

            #Trivy Vulnerabilities
            for vuln in result_obj.get("Vulnerabilities", []):
                vuln_id= vuln.get("VulnerabilityID", "UNKNOWN")
                severity= vuln.get("Severity", "UNKNOWN")
                title= vuln.get("Title", "")[:100]
                session.run("""
                    MATCH (f:File {path: $path})
                    MERGE (v:Vulnerability {id: $vuln_id, severity: $severity})
                    ON CREATE SET v.title = $title
                    MERGE (f)-[:HAS_VULNERABILITY]->(v)
                """, path=target_path, vuln_id=vuln_id, severity=severity, title=title)

            #Trivy Secrets
            for secret in result_obj.get("Secrets", []):
                rule_id= secret.get("RuleID", "UNKNOWN")
                match_str= secret.get("Match", "")[:100]
                session.run("""
                    MATCH (f:File {path: $path})
                    MERGE (s:Secret {rule: $rule_id})
                    ON CREATE SET s.match = $match
                    MERGE (f)-[:CONTAINS]->(s)
                """, path=target_path, rule_id=rule_id, match=match_str)

def generate_graph():
    with driver.session() as session:
        # Fetch nodes and relationships
        result = session.run("""
            MATCH (n)-[r]->(m)
            RETURN n, r, m
            ORDER BY id(n), id(r)
        """)
        isolated_nodes = session.run("""
            MATCH (n)
            WHERE NOT (n)--()
            RETURN n
            """)
        net= Network(height="750px", width="100%", directed=True,bgcolor="#0e1117",font_color="white")
        net.toggle_physics(True)
        net.set_options('''
        {
        "edges": {
            "arrows": {
            "to": {
                "enabled": true,
                "scaleFactor": 1.5
            }
            },
            "arrowStrikethrough": true,
            "width": 2.5,
            "color": "#aaaaaa"
        },
        "physics": {
            "enabled": true,
            "barnesHut": {
            "gravitationalConstant": -8000,
            "springLength": 180,
            "springConstant": 0.05
            }
        }
        }
        ''')
        nodes_added = set()
        def add_node(node):
            node_id= node.element_id
            if node_id in nodes_added:
                return
            label = list(node.labels)[0]
            title = ""
            if 'path' in node:
                title = f"File: {node['path']}"
            elif 'rule' in node:
                title = f"Secret: {node['rule']} (line {node.get('line','?')})"
            elif 'id' in node:
                title = f"Vuln: {node['id']} ({node.get('severity','?')})"
                if 'text' in node:
                    title += f"\n{node['text']}"
                if 'title' in node:
                    title += f"\n{node['title']}"
            color_map ={ 
                'File': '#61afef',
                'Secret': '#e06c75',
                'Vulnerability': '#d19a66'
            }
            color= color_map.get(label, '#98c379')
            net.add_node(node_id, label=label, title=title, color=color)
            nodes_added.add(node_id)      
        for record in result:
            n = record["n"]
            m = record["m"]
            r = record["r"]
            add_node(n)
            if m:
                add_node(m)
            if r:
                net.add_edge(r.start_node.element_id, r.end_node.element_id, color="#888",width=2.5,arrows="to")

        for record in isolated_nodes:
            add_node(record["n"])
        
        os.makedirs("tmp", exist_ok=True)
        html_path = "tmp/vulngraph.html"
        net.save_graph(html_path)
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
        
st.set_page_config(page_title="VulnGraph", layout="wide")
st.title("VulnGraph - Code Vulnerability Visualization")
st.markdown("Visualize code vulnerabilities and secrets using Neo4j and Streamlit.")    

if st.button("Scan and Load Data",type="primary"):
    with st.spinner("Scanning code and loading data into Neo4j..."):
        clear_and_load()
    st.success("Data loaded successfully!")
if st.button("Refresh Graph"):
    st.rerun()
html_content = generate_graph()
if html_content:
    st.components.v1.html(html_content, height=700, scrolling=True)
else:
    st.info("No data available to display. Please run a scan first.")