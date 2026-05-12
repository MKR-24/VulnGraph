import streamlit as st
from neo4j import GraphDatabase
from pyvis.network import Network
import os
import time
from dotenv import load_dotenv
from scanner import scan_all
from llm import explain_all_findings,check_ollama_health
from pathlib import Path

load_dotenv()

BASE_DIR = Path(__file__).parent.parent.resolve()
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "vulngraph123")

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
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600&display=swap');

            html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0a0e1a;
    color: #c9d1d9;
}
.stApp { background: #0a0e1a; }
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}


[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #1e2d40;
}
[data-testid="stSidebar"] * { color: #c9d1d9 !important; }

.stButton > button {
    background: linear-gradient(135deg, #00ff88 0%, #00c9ff 100%);
    color: #0a0e1a !important;
    border: none;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    font-size: 13px;
    letter-spacing: 0.5px;
    padding: 10px 24px;
    transition: all 0.2s ease;
    text-transform: uppercase;
}
.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 0 20px rgba(0, 255, 136, 0.4);
}

[data-testid="stMetric"] {
    background: #0d1117;
    border: 1px solid #1e2d40;
    border-radius: 8px;
    padding: 16px;
}
[data-testid="stMetric"] label {
    color: #8b949e !important;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px !important;
    text-transform: uppercase;
    letter-spacing: 1px;
}
[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: #00ff88 !important;
    font-family: 'JetBrains Mono', monospace;
    font-size: 28px !important;
    font-weight: 700;
}

div[data-testid="stAlert"] { border-radius: 6px; }

[data-testid="stExpander"] {
    background: #0d1117;
    border: 1px solid #1e2d40;
    border-radius: 8px;
}

hr { border-color: #1e2d40; }

code {
    font-family: 'JetBrains Mono', monospace;
    background: #161b22;
    color: #00ff88;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12px;
}

.vulngraph-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 28px;
    font-weight: 700;
    background: linear-gradient(135deg, #00ff88, #00c9ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: -0.5px;
}
.vulngraph-subtitle {
    font-size: 13px;
    color: #8b949e;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
}
.sidebar-section {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: #8b949e;
    margin: 16px 0 8px 0;
    border-bottom: 1px solid #1e2d40;
    padding-bottom: 4px;
}
.graph-container {
    border: 1px solid #1e2d40;
    border-radius: 10px;
    overflow: hidden;
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
        
        for item in findings["gitleaks"]:
            file_path = normalize_path(item.get("File", ""))
            if not file_path:
                continue
            session.run(""" 
                MATCH (f:File {path: $file_path})
                MERGE (s:Secret {rule: $rule, line: $line, source: 'gitleaks'})
                MERGE (f)-[:CONTAINS]->(s)
            """, file_path=file_path, rule=item["RuleID"], line=item["Startline"]) 

        for item in findings["bandit"]:
            file_path = normalize_path(item.get("filename", ""))
            if not file_path or ".." in file_path:
                continue
            session.run(""" 
                MATCH (f:File {path: $file_path})
                MERGE (v:Vulnerability {id: $issue_id,  source: 'bandit'})
                ON CREATE SET v.severity = $severity, v.text = $text, v.confidence = $confidence
                ON MATCH SET v.severity = $severity        
                MERGE (f)-[:HAS_VULNERABILITY]->(v)
            """, 
                file_path=file_path,
                issue_id=item.get("test_id","UNKNOWN"),
                severity=item.get("issue_severity","UNDEFINED"),
                text=f"{item.get('test_name','')} — {item.get('issue_text','')}".strip("— ")[:150],
                confidence=item.get("issue_confidence","UNDEFINED")
            )
     

        for result_obj in findings["trivy"]:
            target_path = normalize_path(result_obj.get("Target", ""))
            if not target_path or any(x in target_path for x in [".git", ".venv","tools"]):
                continue
            session.run("MERGE (f:File {path: $path})", path=target_path)
            for vuln in result_obj.get("Vulnerabilities", []):
                session.run(""" 
                    MATCH (f:File {path: $file_path})
                    MERGE (v:Vulnerability {id: $vuln_id, source: 'trivy'})
                    ON CREATE SET v.severity = $severity, v.title = $title
                    ON MATCH SET v.severity = $severity
                    MERGE (f)-[:HAS_VULNERABILITY]->(v)
                """, 
                    file_path=target_path,
                    vuln_id=vuln.get("VulnerabilityID","UNKNOWN"),
                    severity=vuln.get("Severity","UNDEFINED"),
                    title=vuln.get("Title","")[:100],
                )
            for secret in result_obj.get("Secrets", []):
                session.run(""" 
                    MATCH (f:File {path: $file_path})
                    MERGE (s:Secret {rule: $rule_id, source: 'trivy'})
                    ON CREATE SET s.match= $match
                    MERGE (f)-[:CONTAINS]->(s)
                """, 
                    file_path=target_path,
                    rule_id=secret.get("RuleID","UNKNOWN"),
                    match=secret.get("Match","")[:100]
                )
    return findings

#Statistics
def get_stats():
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
    return check_ollama_health()

def get_explained_findings(limit = 5):
    """Fetch nodes which have LLM explanations."""
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
@st.cache_data(ttl=30)
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
    net.set_options('''
        {
        "edges": {
            "arrows": {"to": {"enabled": true, "scaleFactor": 1.5}},
            "color": {"color": "#1e3a5f", "highlight": "#00ff88"},
            "width": 1.8,
            "smooth": {"enabled": true, "type": "continuous"}
        },
        "nodes": {
            "font": {"color": "#c9d1d9", "size": 13, "face": "monospace"},
            "borderWidth": 2,
            "shadow": {"enabled": true, "color": "rgba(0,255,136,0.15)", "size": 8}
        },
        "physics": {
            "enabled": true,
            "barnesHut": {"gravitationalConstant": -7000, "springLength": 200, "damping": 0.15}
        },
        "interaction": {"hover": true, "tooltipDelay": 100, "hideEdgesOnDrag": true}
    }
    ''')
    SEV_COLORS = {"CRITICAL": "#ff4444", "HIGH": "#ff8c00", "MEDIUM": "#ffd700", "LOW": "#00ff88"}
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
            title = f"📄 {path}"
            display = f"📄 {short}"
            color = {"background": "#1a2744", "border": "#2d5a8e", "highlight": {"border": "#00c9ff"}}
            size = 18

        elif label == "Secret":
            rule = node.get("rule", "?")
            title = f"🔑 Secret | Rule: {rule} | Line: {node.get('line','?')} | Source: {source}"
            display = f"🔑 {rule[:20]}"
            color = {"background": "#3d1a1a", "border": "#e06c75", "highlight": {"border": "#ff4444"}}
            size = 22

        else:  # Vulnerability
            vid = node.get("id", "?")
            sev = (node.get("severity") or "UNKNOWN").upper()
            sev_color = SEV_COLORS.get(sev, "#8b949e")
            text = node.get("text") or node.get("title") or ""
            explanation = node.get("explanation", "")
            title = f"⚠️ {vid} | {sev} | {source}"
            if text:
                title += f"\n{text[:120]}"
            if explanation:
                title += f"\n\n💡 {explanation[:200]}"
            display = f"⚠️ {vid[:18]}"
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
            <div style='font-family:JetBrains Mono,monospace;font-size:22px;font-weight:700;
                        background:linear-gradient(135deg,#00ff88,#00c9ff);
                        -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                        background-clip:text;'>🛡️ VulnGraph</div>
            <div style='font-size:11px;color:#8b949e;letter-spacing:1px;margin-top:4px;'>
                ASPM PLATFORM v0.1
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="sidebar-section">Controls</div>', unsafe_allow_html=True)

        if st.button("▶ Run Full Scan", type="primary", use_container_width=True):
            with st.spinner("Running scanners..."):
                findings = clear_and_load_data()
                counts = {k: len(v) for k, v in findings.items()}
            st.success(f"Done — {counts}")
            st.rerun()

        if st.button("↺ Refresh View", use_container_width=True):
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
            SEV_COLORS = {"CRITICAL": "#ff4444", "HIGH": "#ff8c00", "MEDIUM": "#ffd700", "LOW": "#00ff88"}
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
                        <div style='width:{pct:.0f}%;background:{color};height:4px;border-radius:3px;
                                    box-shadow:0 0 6px {color}88;'></div>
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
            Llama 3.1 via Ollama
        </div>
        """, unsafe_allow_html=True)

#MAIN Page
def render_main(stats, recent_findings):
    st.markdown("""
    <div style='padding:8px 0 24px 0;'>
        <div class='vulngraph-title'>VulnGraph</div>
        <div class='vulngraph-subtitle'>// APPLICATION SECURITY POSTURE MANAGEMENT</div>
    </div>
    """, unsafe_allow_html=True)

    # Metrics row
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("📁 Files Scanned", stats["files"])
    c2.metric("🔍 Vulnerabilities", stats["vulns"])
    c3.metric("🔑 Secrets Found", stats["secrets"])
    c4.metric("🚨 High / Critical", stats["high_critical"])
    c5.metric("⚡ Total Findings", stats["vulns"] + stats["secrets"])

    st.markdown("<hr style='margin:8px 0 20px 0;'>", unsafe_allow_html=True)

    graph_col, detail_col = st.columns([3, 1])

    with graph_col:
        st.markdown("""
        <div style='font-family:JetBrains Mono;font-size:11px;color:#8b949e;
                    text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;'>
            Attack Path Graph
        </div>
        """, unsafe_allow_html=True)
        html_content = generate_graph()
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
        st.markdown("""
        <div style='font-family:JetBrains Mono;font-size:11px;color:#8b949e;
                    text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;'>
            Recent Findings
        </div>
        """, unsafe_allow_html=True)

        SEV_COLORS = {
            "CRITICAL": "#ff4444", "HIGH": "#ff8c00", "MEDIUM": "#ffd700",
            "LOW": "#00ff88", "SECRET": "#c678dd", "UNDEFINED": "#8b949e", "UNKNOWN": "#8b949e"
        }

        if recent_findings:
            for f in recent_findings:
                sev = (f.get("severity") or "UNKNOWN").upper()
                color = SEV_COLORS.get(sev, "#8b949e")
                icon = "🔑" if f.get("type") == "Secret" else "⚠️"
                file_short = (f.get("file") or "").split("/")[-1] or "unknown"
                vuln_id = (f.get("id") or "")[:24]
                st.markdown(f"""
                <div style='background:#0d1117;border:1px solid #1e2d40;border-left:3px solid {color};
                            border-radius:6px;padding:10px 12px;margin-bottom:8px;'>
                    <div style='font-family:JetBrains Mono;font-size:11px;color:{color};font-weight:700;margin-bottom:4px;'>
                        {icon} {sev}
                    </div>
                    <div style='font-family:JetBrains Mono;font-size:10px;color:#c9d1d9;word-break:break-all;margin-bottom:3px;'>
                        {vuln_id}
                    </div>
                    <div style='font-size:10px;color:#8b949e;'>📄 {file_short}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style='font-size:12px;color:#8b949e;font-family:JetBrains Mono;
                        padding:20px 0;text-align:center;'>No findings yet</div>
            """, unsafe_allow_html=True)

        # LLM Explanations panel
        st.markdown("""
        <div style='font-family:JetBrains Mono;font-size:11px;color:#8b949e;
                    text-transform:uppercase;letter-spacing:2px;
                    margin:16px 0 8px 0;border-top:1px solid #1e2d40;padding-top:12px;'>
            AI Explanations
        </div>
    
        """, unsafe_allow_html=True)

        ollama_up = check_ollama_health()
        if not ollama_up:
            st.markdown("""
            <div style='background:#1a1a0d;border:1px solid #3d3000;border-radius:6px;
                        padding:10px 12px;font-size:11px;color:#ffd700;
                        font-family:JetBrains Mono;line-height:1.8;'>
                ⚠️ Ollama not running<br>
                <span style='color:#8b949e;'>Start with: ollama serve</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style='background:#0a1f0a;border:1px solid #1a3d1a;border-radius:6px;
                        padding:8px 12px;font-size:11px;color:#00ff88;
                        font-family:JetBrains Mono;margin-bottom:10px;'>
                ✓ Ollama connected
            </div>
            """, unsafe_allow_html=True)

            if st.button("🤖 Explain Findings", use_container_width=True):
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
                                color:#00ff88;line-height:1.8;margin-top:8px;'>
                        ✓ {results['success']} explained<br>
                        <span style='color:#ff8c00;'>✗ {results['failed']} failed</span>
                    </div>
                    """, unsafe_allow_html=True)
                    time.sleep(1)
                    st.rerun()
            
        # Show sample of existing explanations
        explained = get_explained_findings()
        if explained:
            st.markdown("""
            <div style='font-family:JetBrains Mono;font-size:10px;color:#8b949e;
                        text-transform:uppercase;letter-spacing:1px;margin:12px 0 6px 0;'>
                Latest Explanations
            </div>
            """, unsafe_allow_html=True)
            for item in explained[:3]:
                sev = (item.get("severity") or "").upper()
                SEV_COLORS = {"CRITICAL":"#ff4444","HIGH":"#ff8c00","MEDIUM":"#ffd700","LOW":"#00ff88"}
                color = SEV_COLORS.get(sev, "#8b949e")
                with st.expander(f"{item.get('id', item.get('rule', '?'))} — {sev}"):
                    st.markdown(f"""
                    <div style='font-family:JetBrains Mono;font-size:11px;line-height:1.8;'>
                        <span style='color:#8b949e;'>WHAT</span><br>
                        <span style='color:#c9d1d9;'>{item.get('explanation','—')}</span><br><br>
                        <span style='color:#8b949e;'>RISK</span><br>
                        <span style='color:{color};'>{item.get('why_dangerous','—')}</span><br><br>
                        <span style='color:#8b949e;'>FIX</span><br>
                        <span style='color:#00ff88;'>{item.get('fix','—')}</span><br><br>
                        <span style='color:#8b949e;'>CWE: {item.get('cwe','N/A')}</span>
                    </div>
                    """, unsafe_allow_html=True)

#Main Fn
def main():
    stats= get_stats()
    render_sidebar(stats, get_severity_breakdown())
    render_main(stats, get_recent_findings())

main()

        