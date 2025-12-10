import streamlit as st
from neo4j import GraphDatabase
from pyvis.network import Network
import os
from dotenv import load_dotenv
from scanner import scan_all

#Neo4j connection setup
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j" ,"vulngraph123"))

def get_graph_data():
    with driver.session() as session:
        result = session.run("""
            MATCH (n)
            OPTIONAL MATCH (n)-[r]->(m)
            RETURN n, r, m
            LIMIT 500
        """)
        nodes = []
        edges = []
        node_ids = set()

        for record in result:
            for node in [record["n"], record["m"]]:
                if node and node.id not in node_ids:
                    node_ids.add(node.id)
                    nodes.append({
                        "id": node.id,
                        "label": list(node.labels)[0],
                        "title": node.get("path", "No path info")
                    })
            if record["r"]:
                edges.append({
                    "from": record["r"].start_node.id,
                    "to": record["r"].end_node.id,
                    "label": type(record["r"]).__name__
                })
        return nodes, edges
    
st.set_page_config(page_title="VulnGraph", layout="wide")
st.title("VulnGraph: Open Source ASPM Platform")
st.markdown("*LLM-Powered Application Security Posture Management** · 100 % Open Source")

if st.button("Refresh Graph"):
    with st.spinner("Fetching data..."):
        nodes, edges = get_graph_data()
        net = Network(height = "700px", width = "100%", bgcolor= "#0e1117", font_color= "white")
        net.toggle_physics(True)
    
if st.button("Run Security Scan"):
    with st.spinner("Scanning for vulns..."):
        findings = scan_all()
        st.json(findings)  # Shows raw JSON — we'll visualize tomorrow
        st.success(f"Found {len(findings['gitleaks'])} secrets, {len(findings['bandit'])} code issues!")

        for node in nodes:
            net.add_node(node["id"], label=node["label"], title=node["title"])
            for edge in edges:
                net.add_edge(edge["from"], edge["to"], label=edge["label"])

            net.save_graph("graph.html")
            HtmlFile = open("graph.html", 'r', encoding='utf-8')
            st.components.v1.html(HtmlFile.read(), height=750)

        st.sidebar.success("Graph refreshed successfully!")
        
