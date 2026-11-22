# MCP-Secure Gateway: Dynamic Security Gateway for LLM Agents

A dynamic security gateway for LLM agents interacting with MCP (Model Context Protocol) tools. Built as a final-year research project extending the *MCP-Secure* base paper.

---

## 🏛️ Architecture Overview

The base paper provides tool-level enforcement:
- **L1 (Scope):** Restricts calls to allowed tools.
- **L2 (Read-Only):** Mutating calls become no-ops.
- **L3 (Approval with Elevation):** Human confirmation with time-boxed elevation TTL.

Our contribution adds three content-aware and dynamic analysis layers:
1. **Layer A — Semantic Parameter & AST Validation ("Identify"):** Path traversal filtering, protected branch enforcement, credential exfiltration regex scanning, outbound email recipient allowlisting, and Python AST call/import analysis.
2. **Layer B — Dynamic Taint Engine ("Finding"):** Ingests observations from untrusted sources (`web.fetch_url`, `mail.read_inbox`), detects prompt injection payloads, tracks tainted entity/n-gram propagation, and enforces sink policies on sensitive operations.
3. **Layer C — Risk Scoring Engine ("Conclusion"):** Calculates a 5D risk vector (`tool_sensitivity`, `param_risk`, `taint`, `privilege_level`, `chain_risk`), produces a weighted risk score ($0..1$), maps to decisions (`ALLOW`, `DOWNGRADE`, `APPROVAL`, `BLOCK`), and allows hard rule overrides.

Pipeline flow:
```
User Task -> LLM / Simulated Agent -> Action JSON {"server", "tool", "args"}
     -> Gateway (Session/Scope -> L1 -> L2 -> L3 -> Layer A -> Layer B -> Layer C)
     -> Decision (ALLOW / DOWNGRADE / APPROVAL / BLOCK)
     -> MCP Server -> Observation returned (tagged with taint if untrusted)
     -> Every call logged to logs/calls.jsonl -> Visualized on Streamlit Dashboard
```

---

## 🚀 Quickstart & Commands

### 1. Requirements & Setup
- Python 3.10+
- Install dependencies:
```bash
pip install -r requirements.txt
```

### 2. Run the Gateway Demo
Demonstrates benign tasks, prompt injection defense, and scripted elevation:
```bash
python main.py demo
```

### 3. Interactive Chat with Agent
Run an interactive session against Ollama (`llama3.1:8b`) or simulated agent:
```bash
python main.py chat --agent simulated --mode P123
# Or with Ollama:
python main.py chat --agent ollama --model llama3.1:8b --mode P123
```

### 4. Run Empirical Evaluation & Ablation Study
Compare all configurations (`L0`, `L2`, `L3`, `P1`, `P12`, `P123`) across 40 standardized benchmark tasks (15 benign, 25 attack):
```bash
python eval/run_experiments.py --agent simulated --configs L0 L2 L3 P1 P12 P123 --repeats 1
```
Results and ablation metrics are automatically written to:
- `results/summary.txt`
- `results/ablation_summary.csv`
- `results/results.csv`

### 5. Launch the Streamlit Dashboard
Launch the interactive research dashboard to inspect live calls, taint flows, risk breakdowns, and run live agent tests:
```bash
streamlit run dashboard/app.py
```
Dashboard features:
- **🤖 Live Agent Playground:** Interactive prompt execution, injection planting, and step-by-step trace inspection.
- **📋 Live Decision Table:** Color-coded table (`ALLOW`, `DOWNGRADE`, `APPROVAL`, `BLOCK`) with server, tool, latency, and full filters.
- **🌊 Taint Flow View:** Provenance store table, source $\to$ sink flow tracking, and detailed attack vectors.
- **📊 Risk Score Breakdown:** 5D risk vector charts (`tool_sensitivity`, `param_risk`, `taint`, `privilege_level`, `chain_risk`) and component explanations.
- **📈 Benchmark & Ablation Charts:** Empirical Attack Block Rate, Benign Completion, False Positive Rate, and Latency comparisons.

### 6. Run Full Unit Test Suite
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📁 Repository Structure

```text
├── SPEC.md                  # Project specification and decisions log
├── README.md                # Project overview and run guide
├── requirements.txt         # Dependencies (streamlit, pandas, ollama)
├── main.py                  # CLI entry point (demo, chat, run)
├── servers/                 # In-memory mock MCP servers
│   ├── git_server.py        # list_branches, create_branch, commit_file, delete_branch, force_push, merge_pr
│   ├── file_server.py       # read_file, write_file (with sandboxed fake .env)
│   ├── mail_server.py       # read_inbox, send_mail (with fake inbox)
│   ├── web_server.py        # fetch_url (with fake web and prompt injection)
│   ├── code_server.py       # run_python (simulated AST analysis)
│   └── __init__.py          # Server registry
├── gateway/                 # Core Security Gateway (stdlib-only)
│   ├── session.py           # SessionState, Elevation, SessionRegistry
│   ├── layer1_params.py     # Layer A: Parameter & AST validation
│   ├── layer2_taint.py      # Layer B: Dynamic taint tracking & sink policies
│   ├── layer3_risk.py       # Layer C: 5D risk vector & scoring engine
│   ├── pipeline.py          # Unified pipeline & ablation modes (L0..P123)
│   ├── approval.py          # Interactive and scripted approval mechanisms
│   ├── logger.py            # JSONL structured event logger
│   └── config.json          # Weights, thresholds, and sensitivity config
├── agent/                   # Agent implementations
│   ├── react_agent.py       # Ollama ReAct agent with JSON repair heuristics
│   └── simulated_agent.py   # Deterministic offline agent for reproducible eval
├── eval/                    # Benchmark & evaluation harness
│   ├── tasks.py             # 40 standardized benchmark tasks (benign & attack)
│   └── run_experiments.py   # Ablation runner, metrics calculation, and CSV output
├── dashboard/               # Research dashboard
│   └── app.py               # 5-tab Streamlit visualizer & live playground
├── tests/                   # Comprehensive unit test suites (320+ tests)
├── logs/                    # Structured call logs (calls.jsonl)
└── results/                 # Experiment summaries and ablation CSV files
```
