from neo4j import GraphDatabase
import json, os
from dotenv import load_dotenv
load_dotenv()

driver = GraphDatabase.driver(
    os.getenv("NEO4J_URI"),
    auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD"))
)

with driver.session() as session:
    findings = [dict(r) for r in session.run("""
        MATCH (f:File)-[]->(n)
        WHERE n:Vulnerability OR n:Secret
        RETURN f.path AS file,
               labels(n)[0] AS type,
               CASE WHEN n:Vulnerability THEN n.id ELSE n.rule END AS id,
               CASE WHEN n:Vulnerability THEN coalesce(n.severity,'UNKNOWN') ELSE 'SECRET' END AS severity,
               coalesce(n.source,'unknown') AS source,
               n.explanation AS explanation,
               n.why_dangerous AS why_dangerous,
               n.fix AS fix,
               n.cwe AS cwe
    """)]

    stats = dict(session.run("""
        MATCH (f:File) WITH count(f) AS files
        OPTIONAL MATCH (v:Vulnerability) WITH files, count(v) AS vulns
        OPTIONAL MATCH (s:Secret) WITH files, vulns, count(s) AS secrets
        OPTIONAL MATCH (v2:Vulnerability) WHERE toUpper(v2.severity) IN ['CRITICAL','HIGH']
        RETURN files, vulns, secrets, count(v2) AS high_critical
    """).single())

driver.close()

demo = {
    "findings": findings,
    "stats": stats,
    "source": "static_demo"
}

os.makedirs("../data", exist_ok=True)
with open("../data/demo_data.json", "w") as f:
    json.dump(demo, f, indent=2, default=str)

print(f"Exported {len(findings)} findings")
print(f"Stats: {stats}")