---
title: VulnGraph
emoji: 🛡️
colorFrom: green
colorTo: blue
sdk: docker
app_file: app/main.py
pinned: false
---
# VulnGraph

**AI-powered Application Security Posture Management (ASPM) platform.** Scans codebases for vulnerabilities and secrets, models attack paths as a graph, and generates LLM-powered explanations and code patches.

> ⚠️ **For full functionality, run locally.** The deployed demo runs in static mode — scans, LLM explanations, and agent patches require a local environment with Neo4j and Ollama.

**Live Demo**
- Dashboard: https://vulngraph-dashboard.onrender.com
- API: https://vulngraph-api.onrender.com
- API Docs: https://vulngraph-api.onrender.com/docs

---

## What It Does

- **Scans** codebases using Gitleaks (secrets), Trivy (CVEs), and Bandit (SAST)
- **Models** findings as a Neo4j attack graph — files connected to vulnerabilities and secrets
- **Explains** each finding using a local LLM (llama3.2:3b via Ollama) augmented with RAG retrieval from a CWE/OWASP/Bandit knowledge base
- **Patches** vulnerabilities using a deterministic 5-step agentic pipeline
- **Exposes** tools over MCP so Claude Desktop and other AI clients can query your attack graph
- **Evaluates** LLM explanation quality using a custom RAGAS harness (relevancy, faithfulness, CWE accuracy)
- **Generates** SBOMs in CycloneDX and SPDX formats

---

## Architecture

```
Scanners                 Graph DB            AI Layer
─────────────────        ──────────          ──────────────────────────
Gitleaks (secrets)  ──►  Neo4j          ──►  LLM explanations (Ollama)
Trivy (CVEs)        ──►  Attack graph   ──►  RAG pipeline (ChromaDB)
Bandit (SAST)       ──►  File nodes     ──►  Agent + patch generation
                                             MCP server
                         FastAPI ──► Streamlit Dashboard
```

---

## Real Findings

Tested against four codebases:

| Target | Gitleaks | Trivy | Bandit | Notable |
|--------|----------|-------|--------|---------|
| VulnGraph itself | HF token, AWS key | 2 CVEs | 11 findings | Own codebase |
| dvpwa (vulnerable Python app) | 0 | 48 CVEs | 2 findings | SQL injection (B608), MD5 (B324), PyYAML CRITICAL (CVE-2017-18342) |
| secretsandstuff | AWS key, GitHub token | 2 findings | 0 | Secret detection demo |
| Juice Shop | 11 secrets | 9 findings | 0 | JWT tokens, private keys, Docker misconfigs |

---

## Local Setup

### Prerequisites

- Python 3.12
- Docker
- [Ollama](https://ollama.ai)
- Gitleaks and Trivy executables in `tools/`

### 1. Clone and install

```bash
git clone https://github.com/your-username/VulnGraph
cd VulnGraph
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

### 2. Start Neo4j

```bash
docker run -d \
  --name vulngraph-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/vulngraph123 \
  neo4j:5.25-community
```

### 3. Start Ollama and pull model

```bash
ollama serve
ollama pull llama3.2:3b
```

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env with your values
```

`.env`:
```
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=PLACEHOLDER
NEO4J_PASSWORD=PLACEHOLDER
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2:3b
```

### 5. Seed knowledge base

```bash
cd app
python rag.py
```

### 6. Run

```bash
# Dashboard
streamlit run app/main.py

# API (separate terminal)
uvicorn app.api:app --reload --port 8000
```

---

## Scanning

### Scan your own codebase

Click **Run Full Scan** in the dashboard, or:

```bash
cd app
python scanner.py
```

### Scan an external repo (local)

```python
from scanner import scan_all
results = scan_all(target_dir="/path/to/repo")
```

### Scan via API (Git URL)

```bash
curl -X POST https://vulngraph-api.onrender.com/scan/repo \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/anxolerd/dvpwa"}'
```

> Note: The `/scan/repo` endpoint clones and scans the repo but does not store results in Neo4j on the deployed version. For full pipeline including LLM explanations and graph visualization, run locally.

### Generate LLM explanations

```bash
python app/llm.py
```

### Generate patch for a finding

```bash
python app/agent.py --finding B404
```

---

## MCP Server (Claude Desktop)

Exposes VulnGraph tools over the Model Context Protocol so Claude Desktop can query your attack graph, retrieve security context, and generate patches.

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vulngraph": {
      "command": "C:\\path\\to\\VulnGraph\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\VulnGraph\\app\\mcp_server.py"]
    }
  }
}
```

Available tools: `query_attack_graph`, `search_knowledge_base`, `get_file_context`, `generate_patch`, `get_finding_explanation`

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service health check |
| GET | `/stats` | Scan metrics |
| GET | `/findings` | All findings (filterable by severity, source) |
| GET | `/findings/{id}` | Single finding with LLM explanation |
| GET | `/graph` | Attack path graph as JSON |
| GET | `/sbom` | SBOM in CycloneDX or SPDX format |
| POST | `/scan` | Trigger full scan |
| POST | `/scan/repo` | Scan a public GitHub repo by URL |
| POST | `/explain` | Generate LLM explanations |
| POST | `/agent/fix` | Run agent to generate code patch |

---
## CI/CD

[![Security Scan](https://github.com/MKR-24/VulnGraph/actions/workflows/scan.yml/badge.svg)](https://github.com/MKR-24/VulnGraph/actions/workflows/scan.yml)

**`scan.yml`** — triggers on every push and PR
- Runs Bandit (SAST) and Trivy (SCA)
- Posts findings summary as PR comment
- Fails workflow if CRITICAL CVEs are found
- Uploads scan reports as artifacts (30-day retention)

**`eval.yml`** — runs every Monday
- Evaluates LLM explanation quality against ground truth dataset
- Fails if pass rate drops below 50%
- Tracks score trends via GitHub Actions artifacts
## LLM Evaluation

Measures explanation quality against a ground truth dataset using three metrics:

- **Relevancy (50%)** — does the explanation address the actual vulnerability?
- **Faithfulness (30%)** — does it align with RAG-retrieved context?
- **CWE Accuracy (20%)** — was the correct CWE identified?

```bash
python app/eval.py
```

Model comparison results:

| Model | Pass Rate | Avg Overall |
|-------|-----------|-------------|
| llama3.2:3b | 66.7% | 0.600 |
| phi3 | 33.3% | 0.547 |
| gemma2:2b | 33.3% | 0.563 |
| qwen2.5:1.5b | 16.7% | 0.538 |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Scanners | Gitleaks, Trivy, Bandit |
| Graph DB | Neo4j 5.25 |
| LLM | llama3.2:3b via Ollama |
| RAG | ChromaDB + sentence-transformers + BM25 hybrid |
| Backend | FastAPI |
| Frontend | Streamlit |
| Agent | Deterministic 5-step pipeline |
| MCP | Model Context Protocol (Anthropic) |
| CI/CD | GitHub Actions |
| Deployment | Render |

---

## Project Structure

```
VulnGraph/
├── app/
│   ├── main.py          # Streamlit dashboard
│   ├── api.py           # FastAPI backend
│   ├── scanner.py       # Gitleaks + Trivy + Bandit pipeline
│   ├── llm.py           # LLM explanation generation
│   ├── rag.py           # ChromaDB RAG + BM25 hybrid retrieval
│   ├── schemas.py       # Pydantic validation models
│   ├── eval.py          # LLM evaluation harness
│   ├── agent.py         # Deterministic agentic pipeline
│   ├── tools.py         # Agent tool implementations
│   ├── mcp_server.py    # MCP server
│   └── pages/
│       └── 2_📊_Eval_Dashboard.py
├── .github/workflows/
│   ├── scan.yml         # Security scan CI
│   └── eval.yml         # LLM eval CI
├── data/
│   └── chroma/          # ChromaDB vector store
├── tools/               # Gitleaks and Trivy executables
└── gitleaks.toml        # Custom secret detection rules
```
## RAG Pipeline

VulnGraph uses a hybrid retrieval system combining vector search and BM25 keyword search for accurate security context retrieval.

### How it works

1. **Query expansion** — finding IDs are expanded with domain-specific terms (e.g. `B404` → `B404 subprocess import command injection OS command CWE-78`)
2. **Metadata filtering** — Bandit findings only search Bandit + OWASP docs, CVE findings only search CWE + OWASP docs, preventing cross-source contamination
3. **Vector search** — ChromaDB with `all-MiniLM-L6-v2` embeddings retrieves semantically similar documents
4. **BM25 search** — keyword search finds exact rule ID matches that vector search misses
5. **Fusion scoring** — results combined with weighted score: Vector (60%) + BM25 (40%)

### Impact

Before hybrid RAG, B404 retrieval returned unrelated crypto documents (B304 at 34.6%). After:

| Finding | Before | After |
|---------|--------|-------|
| B404 | B304 weak cipher (34.6%) | B404 subprocess (74.0%) |
| B105 | Unknown | B105 hardcoded password (80.0%) |

Knowledge base: 120 documents — 26 CWE definitions, 10 OWASP Top 10 (2025), 84 Bandit rules
