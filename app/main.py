import streamlit as st
from neo4j import GraphDatabase
from pyvis.network import Network
import os
import time
from dotenv import load_dotenv
from pathlib import Path
import json
import html

load_dotenv()

BASE_DIR = Path(__file__).parent.parent.resolve()
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "vulngraph123")

from schemas import(
    parse_bandit_findings,
    parse_trivy_results,
    parse_gitleaks_findings
)
DEMO_DATA_PATH = BASE_DIR / "app" / "demo_data.json"
def load_demo_data() -> dict:
    """Load static demo data when Neo4j is unavailable."""
    try:
        with open(DEMO_DATA_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"findings": [], "stats": {}, "source": "static_demo"}

def is_neo4j_available() -> bool:
    """Check if Neo4j is reachable."""
    try:
        with get_driver().session() as session:
            session.run("RETURN 1")
        return True
    except Exception:
        return False
#Streamlit Page Configuration
st.set_page_config(
    page_title="VulnGraph",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

#CSS
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0d1117;
    color: #c9d1d9;
}
.stApp { background: #0d1117; }
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}


[data-testid="stSidebar"] {
    background: #010409;
    border-right: 1px solid #21262d;
}
[data-testid="stSidebar"] * { color: #c9d1d9 !important; }
:root { --accent: #4fc3a1; --accent-dim: #2a5c4e; }

.stButton > button {
    background: transparent;
    color: var(--accent) !important;
    border: 1px solid var(--accent);
    border-radius: 4px;
    font-family: 'Inter', sans-serif;
    font-weight: 600;
    font-size: 13px;
    letter-spacing: 0;
    padding: 8px 20px;
    transition: background 0.15s ease;
    text-transform: none;
}
.stButton > button:hover {
    background: var(--accent-dim);
    transform: none;
    box-shadow: none;
}

[data-testid="stMetric"] {
    background: #010409;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 14px;
}
[data-testid="stMetric"] label {
    color: #8b949e !important;
    font-size: 11px !important;
    font-weight: 500;
    text-transform: none;
    letter-spacing: 0;
}
[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: #e6edf3 !important;
    font-family: 'JetBrains Mono', monospace;
    font-size: 26px !important;
    font-weight: 600;
}

code {
    font-family: 'JetBrains Mono',monospace;
    background: #161b22;
    color: var(--accent);
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 12px;
}
.sidebar-section {
    font-size: 11px;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 20px 0 8px 0;
}
.app-title {
    font-family: 'Inter', sans-serif;
    font-size: 24px;
    font-weight: 600;
    color: #e6edf3;      
    letter-spacing: -0.3px;
}
.app-subtitle {
    font-size: 12px;
    color: #8b949e;
    margin-top: 2px;
}
.finding-card {
    background: #010409;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 10px 12px;
    margin-bottom: 6px;
}     
.graph-container {
    border: 1px solid #21262d;
    border-radius: 6px;
    overflow: hidden;
    background: #010409;
}  
[data-testid="stTabs"] [data-baseweb="tab-highlight"] {
    background-color: var(--accent);
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    color: #8b949e;
}
[data-testid="stTabs"] [aria-selected="true"] {
    color: #e6edf3 !important;
}                    
</style>
""", unsafe_allow_html=True)

#Connect to Neo4j
@st.cache_resource
def get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def normalize_path(raw_path: str) -> str:
    path_str = str(raw_path).replace("\\", "/").strip()
    base_str = str(BASE_DIR).replace("\\", "/") + "/"
    if path_str.startswith(base_str):
        path_str = path_str[len(base_str):]
    path_str = path_str.lstrip("./")
    return path_str if path_str else ""

# Loading Data

def clear_and_load_data():
    from scanner import scan_all
    driver = get_driver()
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
    
    findings = scan_all()
    with driver.session() as session:
        for root, _, files in os.walk(BASE_DIR):
            if any(x in root for x in [".git", "node_modules", ".venv","tools","__pycache__","tmp","data"]):
                continue
            for file in files:
                path=normalize_path(os.path.join(root, file))
                if path:
                    session.run("MERGE (f:File {path: $path})", path=path)
        
        #Gitleaks
        git_valid, git_failed= parse_gitleaks_findings(findings["gitleaks"])
        for finding in git_valid:
            file_path=normalize_path(finding.file_path)
            if not file_path:
                continue
            session.run("""
                MATCH (f:File {path: $file_path}) 
                MERGE (s:Secret {rule: $rule, source: 'gitleaks'})
                ON CREATE SET s.line = $line
                MERGE (f)-[:CONTAINS]->(s)           
            """, file_path=file_path, rule=finding.finding_id, line=finding.line_number or 0)

        #BANDIT
        bandit_valid,bandit_failed=parse_bandit_findings(findings["bandit"])

        for finding in bandit_valid:
            file_path = normalize_path(finding.file_path)
            if not file_path or ".." in file_path:
                continue
            session.run(""" 
                MATCH (f:File {path: $file_path})
                MERGE (v:Vulnerability {id: $issue_id,  source: 'bandit'})
                ON CREATE SET v.severity = $severity, v.text = $text, v.confidence = $confidence,v.cwe=$cwe
                ON MATCH SET v.severity = $severity        
                MERGE (f)-[:HAS_VULNERABILITY]->(v)
            """, 
                file_path=file_path,
                issue_id= finding.finding_id,
                severity=finding.severity.value,
                text=finding.text,
                confidence=finding.confidence or "UNDEFINED",
                cwe=finding.cwe or ""
            )
     
        #TRIVY
        trivy_valid,trivy_failed=parse_trivy_results(findings["trivy"])
        for finding in trivy_valid:
            target_path = normalize_path(finding.file_path)
            if not target_path or any(x in target_path for x in [".git", ".venv","tools"]):
                continue
            session.run("MERGE (f:File {path: $path})", path=target_path)
            session.run(""" 
                    MATCH (f:File {path: $file_path})
                    MERGE (v:Vulnerability {id: $vuln_id, source: 'trivy'})
                    ON CREATE SET v.severity = $severity, v.title = $title,v.pkg_name=$pkg_name,v.fixed_version=$fixed_version
                    ON MATCH SET v.severity = $severity
                    MERGE (f)-[:HAS_VULNERABILITY]->(v)
                """, 
                    file_path=target_path,
                    vuln_id=finding.finding_id,
                    severity=finding.severity.value,
                    title=finding.title or "",
                    pkg_name=finding.pkg_name or "",
                    fixed_version=finding.fixed_version or ""
                )
        trivy_secrets = [f for f in trivy_valid if not f.finding_id.startswith("CVE-")]
        for finding in trivy_secrets:
            target_path=normalize_path(finding.file_path)
            if not target_path:
                continue
            session.run("""
                MATCH (f: File {path: $path})
                MERGE (s:Secret {rule: $rule_id, source: 'trivy'})
                ON CREATE SET s.match= $match
                MERGE (f)-[:CONTAINS]->(s)
            """, path=target_path,rule_id=finding.finding_id,match=finding.text[:100])
    return findings

#Statistics
def get_stats():
    if not is_neo4j_available():
        demo = load_demo_data()
        s = demo.get("stats", {})
        return {
            "files": s.get("files", 0),
            "vulns": s.get("vulns", 0),
            "secrets": s.get("secrets", 0),
            "high_critical": s.get("high_critical", 0)
        }
    try:
        with get_driver().session() as session:
            row = session.run("""
                MATCH (f:File) WITH count(f) AS files
                OPTIONAL MATCH (v:Vulnerability) WITH files, count(v) AS vulns
                OPTIONAL MATCH (s:Secret) WITH files, vulns, count(s) AS secrets
                OPTIONAL MATCH (v2:Vulnerability) WHERE toUpper(v2.severity) IN ['CRITICAL', 'HIGH']
                RETURN files, vulns, secrets, count(v2) AS high_critical
            """).single()
            if row:
                return dict(row)
    except Exception:
        pass
    return {"files": 0, "vulns": 0, "secrets": 0, "high_critical": 0}

def get_severity_breakdown():
    try:
        with get_driver().session() as session:
            return [(r["severity"], r["count"]) for r in session.run("""
                MATCH (v:Vulnerability)
                RETURN toUpper(v.severity) AS severity, count(v) AS count
                ORDER BY count DESC
            """)]
    except Exception:
        return []
    
def get_recent_findings(limit=10):
    if not is_neo4j_available():
        demo = load_demo_data()
        findings = demo.get("findings", [])[:limit]
        return [
            {
                "file": f.get("file", ""),
                "type": f.get("type", ""),
                "id": f.get("id", ""),
                "severity": f.get("severity", "UNKNOWN"),
                "source": f.get("source", "")
            }
            for f in findings
        ]
    try:
        with get_driver().session() as session:
            return [dict(r) for r in session.run("""
                MATCH (f:File)-[]->(n)
                WHERE n:Vulnerability OR n:Secret
                RETURN f.path AS file,
                    labels(n)[0] AS type,
                    CASE WHEN n:Vulnerability THEN n.id ELSE n.rule END AS id,
                    CASE WHEN n:Vulnerability THEN n.severity ELSE 'SECRET' END AS severity,
                    n.source AS source
                LIMIT $limit
            """, limit=limit)]
    except Exception:
        return []

@st.cache_data(ttl=10)
def ollama_status():
    from llm import check_ollama_health
    return check_ollama_health()

def get_explained_findings(limit = 5):
    """Fetch nodes which have LLM explanations."""
    if not is_neo4j_available():
        demo = load_demo_data()
        explained = [f for f in demo.get("findings", []) if f.get("explanation")][:limit]
        return explained
    try:
        with get_driver().session() as session:
            return [dict(r) for r in session.run("""
                MATCH (n)
                WHERE (n:Vulnerability OR n:Secret) AND n.explanation IS NOT NULL
                RETURN labels(n)[0] AS type,
                    CASE WHEN n:Vulnerability THEN n.id ELSE n.rule END AS id,
                    CASE WHEN n:Vulnerability THEN n.severity ELSE 'SECRET' END AS severity,
                    n.explanation AS explanation,
                    n.why_dangerous AS why_dangerous,
                    n.fix AS fix,
                    n.cwe AS cwe
                LIMIT $limit
            """, limit=limit)]
    except Exception:
        return []
#Creating the Graph

def generate_graph():
    try:
        with get_driver().session() as session:
            result = list(session.run("MATCH (n)-[r]->(m) RETURN n, r, m"))
            isolated =list(session.run("MATCH (n) WHERE NOT (n)--() RETURN n"))
    except Exception:
            return None
    if not result and not isolated:
        return None
    
    net = Network(height="650px", width="100%", directed=True, bgcolor="#0d1117", font_color="#c9d1d9")
    net.toggle_physics(True)
    net.set_options("""
        {
        "edges": {
            "arrows": {"to": {"enabled": true, "scaleFactor": 1.5}},
            "color": {"color": "#1e3a5f", "highlight": "#4a90d9"},
            "width": 1.8,
            "smooth": {"enabled": true, "type": "continuous"}
        },
        "nodes": {
            "font": {"color": "#c9d1d9", "size": 13, "face": "monospace"},
            "borderWidth": 2
        },
        "physics": {
            "enabled": true,
            "barnesHut": {"gravitationalConstant": -7000, "springLength": 200, "damping": 0.15}
        },
        "interaction": {"hover": true, "tooltipDelay": 100, "hideEdgesOnDrag": true}
    }
    """)
    SEV_COLORS = {"CRITICAL": "#ff4444", "HIGH": "#ff8c00", "MEDIUM": "#ffd700", "LOW": "#4fc3a1"}
    nodes_added = set()

    def add_node(node):
        nid = node.element_id
        if nid in nodes_added:
            return
        label = list(node.labels)[0]
        source= node.get("source", "")

        if label == "File":
            path= node.get("path", "")
            short = path.split("/")[-1] or path
            title = f" {path}"
            display = f"{short}"
            color = {"background": "#1a2744", "border": "#2d5a8e", "highlight": {"border": "#00c9ff"}}
            size = 18

        elif label == "Secret":
            rule = node.get("rule", "?")
            title = f"Secret | Rule: {rule} | Line: {node.get('line','?')} | Source: {source}"
            display = f"{rule[:20]}"
            color = {"background": "#3d1a1a", "border": "#e06c75", "highlight": {"border": "#ff4444"}}
            size = 22

        else:  # Vulnerability
            vid = node.get("id", "?")
            sev = (node.get("severity") or "UNKNOWN").upper()
            sev_color = SEV_COLORS.get(sev, "#8b949e")
            text = node.get("text") or node.get("title") or ""
            explanation = node.get("explanation", "")
            title = f"{vid} | {sev} | {source}"
            if text:
                title += f"\n{text[:120]}"
            if explanation:
                title += f"\n\n{explanation[:200]}"
            display = f"{vid[:18]}"
            color = {"background": "#2a1f0a", "border": sev_color, "highlight": {"border": sev_color}}
            size = 26 if sev in ["CRITICAL", "HIGH"] else 20

        net.add_node(nid, label=display, title=title, color=color, size=size)
        nodes_added.add(nid)

    for record in result:
        add_node(record["n"])
        add_node(record["m"])
        r = record["r"]
        net.add_edge(r.start_node.element_id, r.end_node.element_id, color="#1e3a5f", width=2, arrows="to")

    for record in isolated:
        add_node(record["n"])

    os.makedirs("tmp", exist_ok=True)
    path="tmp/vulngraph.html"
    net.save_graph(path)

    with open(path,"r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace("<body>", "<body style='background:#0d1117;margin:0;padding:0;'>")
    html = html.replace("background-color:#ffffff", "background-color:#0d1117")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

#Sidebar
def render_sidebar(stats, severity_breakdown):
    with st.sidebar:
        st.markdown("""
        <div style='text-align:center;padding:8px 0 20px 0;'>
            <div style='font-family:Inter,sans-serif;font-size:22px;font-weight:700;'>VulnGraph</div>
            <div style='font-size:11px;color:#8b949e;letter-spacing:1px;margin-top:4px;'>
                ASPM PLATFORM 
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="sidebar-section">Controls</div>', unsafe_allow_html=True)

        if st.button("Run Full Scan", type="primary", use_container_width=True):
            if not is_neo4j_available():
                st.error("Neo4j is not running. Start Docker first: docker start vulngraph-neo4j")
            else:
                with st.spinner("Running scanners..."):
                    findings = clear_and_load_data()
                    counts = {k: len(v) for k, v in findings.items()}
                st.success(f"Done — {counts}")
                st.rerun()

        if st.button("Refresh View", use_container_width=True):
            st.rerun()

        st.markdown('<div class="sidebar-section">Risk Summary</div>', unsafe_allow_html=True)
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric("Files", stats["files"])
            st.metric("Secrets", stats["secrets"])
        with col_b:
            st.metric("Vulns", stats["vulns"])
            st.metric("High/Crit", stats["high_critical"])

        if severity_breakdown:
            st.markdown('<div class="sidebar-section">Severity Breakdown</div>', unsafe_allow_html=True)
            SEV_COLORS = {"CRITICAL": "#ff4444", "HIGH": "#ff8c00", "MEDIUM": "#ffd700", "LOW": "#4fc3a1"}
            for sev, count in severity_breakdown:
                color = SEV_COLORS.get(sev.upper(), "#8b949e")
                pct = min(count / max(stats["vulns"], 1) * 100, 100)
                st.markdown(f"""
                <div style='margin:6px 0;'>
                    <div style='display:flex;justify-content:space-between;margin-bottom:3px;'>
                        <span style='font-family:JetBrains Mono;font-size:11px;color:{color};'>{sev}</span>
                        <span style='font-family:JetBrains Mono;font-size:11px;color:#8b949e;'>{count}</span>
                    </div>
                    <div style='background:#1e2d40;border-radius:3px;height:4px;'>
                        <div style='width:{pct:.0f}%;background:{color};height:4px;border-radius:3px;'></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown('<div class="sidebar-section">Legend</div>', unsafe_allow_html=True)
        st.markdown("""
        <div style='font-family:JetBrains Mono,monospace;font-size:11px;line-height:2;'>
            <span style='color:#61afef;'>■</span> File node<br>
            <span style='color:#e06c75;'>■</span> Secret / leaked key<br>
            <span style='color:#ff8c00;'>■</span> Vulnerability<br>
            <span style='color:#8b949e;'>──</span> Attack path edge
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="sidebar-section">Stack</div>', unsafe_allow_html=True)
        st.markdown("""
        <div style='font-size:11px;color:#8b949e;line-height:1.8;font-family:JetBrains Mono;'>
            Gitleaks · Trivy · Bandit<br>
            Neo4j · Pyvis · Streamlit<br>
            Llama 3.2 via Ollama
        </div>
        """, unsafe_allow_html=True)

#MAIN Page
def render_main(stats, recent_findings):
    st.markdown("""
    <div style='padding:4px 0 20px 0;'>
        <div class='app-title' style='text-align:left;'>VulnGraph</div>
        <div class='app-subtitle'>APPLICATION SECURITY POSTURE MANAGEMENT</div>
    </div>
    """, unsafe_allow_html=True)

    # Metrics row
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Files Scanned", stats["files"])
    c2.metric("Vulnerabilities", stats["vulns"])
    c3.metric("Secrets Found", stats["secrets"])
    c4.metric("High / Critical", stats["high_critical"])
    c5.metric("Total Findings", stats["vulns"] + stats["secrets"])

    st.markdown("<hr style='margin:8px 0 20px 0;'>", unsafe_allow_html=True)

    graph_col, detail_col = st.columns([3, 1])

    with graph_col:
        st.markdown(
        '<div class="sidebar-section">Attack Path Graph</div>'
        , unsafe_allow_html=True)
        html_content = generate_graph() if is_neo4j_available() else None
        if html_content:
            st.markdown('<div class="graph-container">', unsafe_allow_html=True)
            st.components.v1.html(html_content, height=660, scrolling=False)
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style='height:400px;display:flex;align-items:center;justify-content:center;
                        border:1px dashed #1e2d40;border-radius:10px;color:#8b949e;
                        font-family:JetBrains Mono;font-size:13px;'>
                No data — run a scan to populate the graph
            </div>
            """, unsafe_allow_html=True)

    with detail_col:
        st.markdown('<div class="sidebar-section">Recent Findings</div>'
        , unsafe_allow_html=True)

        SEV_COLORS = {
            "CRITICAL": "#ff4444", "HIGH": "#ff8c00", "MEDIUM": "#ffd700",
            "LOW": "#4fc3a1", "SECRET": "#c678dd", "UNDEFINED": "#8b949e", "UNKNOWN": "#8b949e"
        }

        if recent_findings:
            for f in recent_findings:
                sev = (f.get("severity") or "UNKNOWN").upper()
                color = SEV_COLORS.get(sev, "#8b949e")
                icon = "S" if f.get("type") == "Secret" else "V"
                file_short = (f.get("file") or "").split("/")[-1] or "unknown"
                vuln_id = (f.get("id") or "")[:24]
                vuln_id=html.escape(vuln_id)
                file_short=html.escape(file_short)
                st.markdown(f"""
                <div style='background:#0d1117;border:1px solid #1e2d40;border-left:3px solid {color};
                            border-radius:6px;padding:10px 12px;margin-bottom:8px;'>
                    <div style='font-family:JetBrains Mono;font-size:11px;color:{color};font-weight:700;margin-bottom:4px;'>
                        {icon} {sev}
                    </div>
                    <div style='font-family:JetBrains Mono;font-size:10px;color:#c9d1d9;word-break:break-all;margin-bottom:3px;'>
                        {vuln_id}
                    </div>
                    <div style='font-size:10px;color:#8b949e;'>{file_short}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style='font-size:12px;color:#8b949e;font-family:JetBrains Mono;
                        padding:20px 0;text-align:center;'>No findings yet</div>
            """, unsafe_allow_html=True)

        # LLM Explanations panel
        st.markdown("<hr style='margin:20px 0 16px 0;'>", unsafe_allow_html=True)
        tab1, tab2 = st.tabs(["Patch Agent", "AI Explanations"])
        with tab1:
            finding_input = st.text_input("Finding ID", placeholder="e.g. B404")
            if st.button("Generate Patch", use_container_width=True):
                if finding_input:
                    with st.spinner(f"Agent analyzing {finding_input}..."):
                        from agent import run_agent_for_finding
                        agent_result = run_agent_for_finding(finding_input)
                        answer=agent_result['final_answer']
                        display=answer[:500] +("..." if len(answer) > 500 else "")
                        display=html.escape(display)
                    st.markdown(f"""
                    <div style='background:#0d1117;border:1px solid #1e2d40;border-radius:6px;
                                padding:12px;font-family:JetBrains Mono;font-size:10px;
                                color:#c9d1d9;margin-top:8px;'>
                        {display}
                    </div>
                    """, unsafe_allow_html=True)
        with tab2:
            st.markdown('<div class="sidebar-section">AI Explanations</div>', unsafe_allow_html=True)
            ollama_up = ollama_status()
            if not ollama_up:
                st.markdown("""
                <div style='background:#1a1a0d;border:1px solid #3d3000;border-radius:6px;
                            padding:10px 12px;font-size:11px;color:#ffd700;
                            font-family:JetBrains Mono;line-height:1.8;'>
                            Ollama not running<br>
                    <span style='color:#8b949e;'>Start with: ollama serve</span>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div style='background:#0a1f0a;border:1px solid #1a3d1a;border-radius:6px;
                            padding:8px 12px;font-size:11px;color:#4fc3a1;
                            font-family:JetBrains Mono;margin-bottom:10px;'>
                    ✓ Ollama connected
                </div>
                """, unsafe_allow_html=True)

                if st.button("Explain Findings", use_container_width=True):
                    if not is_neo4j_available():
                        st.error("Neo4j is not running. Start Docker first: docker start vulngraph-neo4j")
                    else:
                        from llm import explain_all_findings
                        progress_bar = st.progress(0)
                        status_text  = st.empty()

                        def on_progress(current, total, message):
                            progress_bar.progress(current / total)
                            status_text.markdown(
                                f"<div style='font-family:JetBrains Mono;font-size:10px;color:#8b949e;'>"
                                f"{message} ({current}/{total})</div>",
                                unsafe_allow_html=True
                            )
                    
                        results= explain_all_findings(on_progress)
                        progress_bar.progress(1.0)

                        if results.get("error"):
                            st.error(results["error"])
                        else:
                            st.markdown(f"""
                            <div style='background:#0a1f0a;border:1px solid #1a3d1a;border-radius:6px;
                                        padding:10px 12px;font-family:JetBrains Mono;font-size:11px;
                                        color:#4fc3a1;line-height:1.8;margin-top:8px;'>
                                ✓ {results['success']} explained<br>
                                <span style='color:#ff8c00;'>✗ {results['failed']} failed</span>
                            </div>
                            """, unsafe_allow_html=True)
                            time.sleep(1)
                            st.rerun()
    
            # Show sample of existing explanations
            explained = get_explained_findings()
            if explained:
                st.markdown('<div class="sidebar-section">Latest Explanations</div>'
                , unsafe_allow_html=True)
                for item in explained[:3]:
                    sev = (item.get("severity") or "").upper()
                    SEV_COLORS = {"CRITICAL":"#ff4444","HIGH":"#ff8c00","MEDIUM":"#ffd700","LOW":"#4fc3a1"}
                    color = SEV_COLORS.get(sev, "#8b949e")
                    explanation = html.escape(item.get('explanation', '—'))
                    why_dangerous = html.escape(item.get('why_dangerous', '—'))
                    fix = html.escape(item.get('fix', '—'))
                    cwe = html.escape(item.get('cwe', 'N/A'))

                    with st.expander(f"{item.get('id', item.get('rule', '?'))[:20]} — {sev}"):
                        st.markdown(f"""
                        <div style='font-family:JetBrains Mono;font-size:11px;line-height:1.8;'>
                            <span style='color:#8b949e;'>WHAT</span><br>
                            <span style='color:#c9d1d9;'>{explanation}</span><br><br>
                            <span style='color:#8b949e;'>RISK</span><br>
                            <span style='color:{color};'>{why_dangerous}</span><br><br>
                            <span style='color:#8b949e;'>FIX</span><br>
                            <span style='color:#4fc3a1;'>{fix}</span><br><br>
                            <span style='color:#8b949e;'>CWE: {cwe}</span>
                        </div>
                        """, unsafe_allow_html=True)

#Main Fn
def main():
    stats= get_stats()
    severity = get_severity_breakdown() if is_neo4j_available() else []
    render_sidebar(stats, severity)
    render_main(stats, get_recent_findings())

main()

        