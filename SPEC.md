# MCP-Secure Gateway — Project Specification

> **Project:** Dynamic Security Gateway for LLM Agents Using MCP Tools  
> **Author:** Final-Year Research Project  
> **Created:** 2026-11-21  
> **Status:** 🟡 Specification Phase

---

## 1. Research Context

### 1.1 Base Paper (MCP-Secure)

The base paper introduces a three-layer tool-level security gateway for agents
interacting with MCP (Model Context Protocol) servers:

| Layer | Name | Mechanism |
|-------|------|-----------|
| **L1** | Scope Check | Validates that the requested tool is within the declared session scope |
| **L2** | Read-Only Enforcement | Blocks write-class tools unless the session explicitly permits mutation |
| **L3** | Approval + Time-Boxed Elevation | Routes high-risk tools through a human-approval step; grants temporary elevated access with a TTL |

**Limitation addressed:** The base paper operates purely at the *tool identity* level — it checks *which* tool is called, but not *what parameters* are passed to it, *how data flows* between tool calls, or *what the aggregate risk* of a multi-step plan is.

---

## 2. This Project's Contribution — Three Additional Layers

This project extends the base paper with three novel layers that sit **before**
L1 and **around** the full pipeline, forming a cohesive Dynamic Security Gateway.

### Layer A — Semantic Parameter & AST Validation ("Identify")

**Position in pipeline:** Pre-L1  
**Goal:** Catch malicious or policy-violating *content* inside tool arguments
before the call ever reaches the MCP server.

Mechanisms:
- **Schema validation:** Each tool's argument schema (from the MCP server
  manifest) is enforced with a JSON-schema check.
- **AST / pattern analysis:** String arguments (e.g. shell commands, SQL, file
  paths, code snippets) are parsed with Python's `ast` module and regex
  heuristics to detect prompt-injection payloads, path-traversal sequences,
  exfiltration patterns, and forbidden function calls.
- **Semantic similarity check (offline):** Tool purpose vs. argument content is
  compared with a lightweight TF-IDF cosine score to flag semantic mismatch
  (e.g. a "search" tool being passed a `DROP TABLE` string).

### Layer B — Dynamic Taint Engine ("Finding")

**Position in pipeline:** Wraps observation return paths and feeds into every
subsequent call.

**Goal:** Track data provenance across a multi-step agent loop so that
information from untrusted sources cannot flow into privileged tool calls
without detection.

Mechanisms:
- **Taint tagging:** Observations from designated *source* tools (e.g.
  `web_search`, `read_email`) are wrapped with a `TaintLabel`
  (source, timestamp, trust level).
- **Propagation rules:** When the agent re-uses tainted text as an argument to
  a later tool call, the taint label propagates; the engine records the
  provenance chain.
- **Sink enforcement:** A configurable sink table maps (tool, arg_name) pairs to
  the minimum acceptable trust level. Calls where tainted data reaches a
  low-trust sink are escalated or blocked.

### Layer C — Risk Scoring Engine ("Conclusion")

**Position in pipeline:** Post-L3, pre-dispatch (and again at session close for
aggregate reporting).

**Goal:** Produce a numeric risk score for each individual tool call and for the
overall agent session, enabling fine-grained ALLOW / DOWNGRADE / APPROVAL / BLOCK
decisions beyond binary policy rules.

Mechanisms:
- **Per-call score:** Weighted combination of (tool sensitivity class, argument
  anomaly score from Layer A, taint level from Layer B, session history
  features, time-of-day / rate features).
- **Session score:** Rolling weighted average of per-call scores, with a
  configurable burst penalty for rapid successive high-risk calls.
- **Decision thresholds:** Four bands mapped to gateway decisions (defined in
  `gateway/config.json`).
- **Explainability:** Each score is accompanied by a human-readable rationale
  string logged to `logs/` and surfaced on the dashboard.

---

## 3. Full System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         USER  TASK  (natural language)                  │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    OLLAMA ReAct AGENT  (agent/react_agent.py)           │
│           Thinks → Chooses tool → Emits Action JSON                     │
│   {"server": "...", "tool": "...", "args": {...}}                       │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │  Action JSON
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    DYNAMIC SECURITY GATEWAY  (gateway/)                 │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  session.py — Session registry, scope declaration, TTL tracking  │   │
│  └───────────────────────────────┬──────────────────────────────────┘   │
│                                  │                                       │
│  ┌───────────────────────────────▼──────────────────────────────────┐   │
│  │  [NEW]  Layer A — layer1_params.py                               │   │
│  │          Schema validate → AST parse → Semantic mismatch check   │   │
│  └───────────────────────────────┬──────────────────────────────────┘   │
│                                  │                                       │
│  ┌───────────────────────────────▼──────────────────────────────────┐   │
│  │  [BASE] L1 — Scope Check  (pipeline.py uses session.py)          │   │
│  └───────────────────────────────┬──────────────────────────────────┘   │
│                                  │                                       │
│  ┌───────────────────────────────▼──────────────────────────────────┐   │
│  │  [BASE] L2 — Read-Only Enforcement  (pipeline.py)                │   │
│  └───────────────────────────────┬──────────────────────────────────┘   │
│                                  │                                       │
│  ┌───────────────────────────────▼──────────────────────────────────┐   │
│  │  [BASE] L3 — Approval + Time-Boxed Elevation  (approval.py)      │   │
│  └───────────────────────────────┬──────────────────────────────────┘   │
│                                  │                                       │
│  ┌───────────────────────────────▼──────────────────────────────────┐   │
│  │  [NEW]  Layer C — layer3_risk.py                                 │   │
│  │          Per-call score → Session score → Decision band          │   │
│  └───────────────────────────────┬──────────────────────────────────┘   │
│                                  │                                       │
│  Decision: ALLOW / DOWNGRADE / APPROVAL / BLOCK                         │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │  (if ALLOW or DOWNGRADE)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    MCP BACKEND ADAPTER  (gateway/mcp_backend.py)        │
│          Routes to correct mock or stdio MCP server in servers/         │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │  Observation (raw result)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [NEW]  Layer B — layer2_taint.py                                       │
│          Wrap observation with TaintLabel if source tool                │
│          Propagate taint to next Action JSON args                       │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │  (Tainted) Observation
                                    ▼
                       Back to ReAct AGENT loop
                                    │
                                    ├──► logs/   (every call, structured JSON)
                                    └──► dashboard/app.py  (live view)
```

---

## 4. Gateway Decision Bands

| Band Score | Decision | Meaning |
|-----------|----------|---------|
| 0.00 – 0.39 | **ALLOW** | Call proceeds immediately |
| 0.40 – 0.59 | **DOWNGRADE** | Call proceeds with reduced privilege (e.g. read-only override) |
| 0.60 – 0.84 | **APPROVAL** | Call queued; human must approve via dashboard within TTL |
| 0.85 – 1.00 | **BLOCK** | Call rejected; agent receives a structured error observation |

---

## 5. Folder Structure

```
MCP_Security/
│
├── SPEC.md                         ← This file
├── README.md                       ← User-facing project overview
├── main.py                         ← Entry point: wires agent + gateway + dashboard
├── requirements.txt                ← Python dependencies
│
├── servers/                        ← MCP server implementations
│   ├── git_server.py               ← Mock git tool server
│   ├── file_server.py              ← Mock file tool server
│   ├── mail_server.py              ← Mock mail tool server
│   ├── web_server.py               ← Mock web-search tool server
│   ├── code_server.py              ← Mock code-execution tool server
│   └── stdio_mcp_server.py         ← Real stdio MCP server (MCP protocol wire format)
│
├── agent/
│   ├── react_agent.py              ← Ollama-backed ReAct agent (offline)
│   └── simulated_agent.py          ← Scripted agent replaying pre-recorded traces
│
├── gateway/
│   ├── config.json                 ← Risk thresholds, taint sources/sinks, scope policies
│   ├── pipeline.py                 ← Orchestrates all layers in order; returns Decision
│   ├── session.py                  ← Session registry, scope, TTL-based elevation state
│   ├── layer1_params.py            ← [NEW] Layer A: schema + AST + semantic validation
│   ├── layer2_taint.py             ← [NEW] Layer B: taint tagging and propagation engine
│   ├── layer3_risk.py              ← [NEW] Layer C: per-call and session risk scoring
│   ├── approval.py                 ← L3 approval queue, TTL enforcement
│   └── mcp_backend.py              ← Routes dispatched calls to the right server
│
├── eval/
│   ├── tasks.py                    ← Benign, adversarial, and boundary task definitions
│   └── run_experiments.py          ← Automated eval harness; writes to results/
│
├── dashboard/
│   ├── app.py                      ← Streamlit (or Flask) dashboard entry point
│   └── pages/
│       ├── live_calls.py           ← Real-time call log with decision badges
│       ├── taint_graph.py          ← Provenance graph visualisation
│       └── risk_scores.py          ← Per-call and session risk score timelines
│
├── tests/
│   ├── test_layer_a.py
│   ├── test_layer_b.py
│   ├── test_layer_c.py
│   ├── test_pipeline.py
│   └── test_session.py
│
├── logs/                           ← Structured JSON call logs (auto-created at runtime)
└── results/                        ← Eval output CSVs and summary JSONs (auto-created)
```

---

## 6. Key Design Constraints

| Constraint | Detail |
|-----------|--------|
| **Language** | Python 3.10+ only |
| **Core gateway stdlib-only** | `gateway/` modules use **only** the Python standard library (no third-party imports); stdlib permitted: `ast`, `re`, `json`, `math`, `collections`, `dataclasses`, `typing`, `datetime`, `logging`, `hashlib`, `uuid` |
| **Offline operation** | The entire system runs with no internet access; all LLM calls go to a local Ollama instance |
| **Fake data only** | No real credentials, no real file paths, no real email addresses or repositories |
| **Mock MCP servers** | All `servers/` implementations return hard-coded or procedurally generated fake observations |
| **Dashboard dependencies** | Dashboard (`dashboard/`) and agent (`agent/`) may use third-party packages (e.g. Streamlit, requests, ollama SDK) declared in `requirements.txt` |

---

## 7. Decisions Log

This section is updated throughout the build to record every significant
architectural or implementation decision, the options considered, and the
rationale chosen.

---

### DECISION-001 — Specification Written
- **Date:** 2026-11-21  
- **Decision:** Created SPEC.md with full architecture, folder structure, layer
  descriptions, and constraint table as the single source of truth for the
  project.  
- **Rationale:** Provides a stable reference before any code is written;
  ensures all future implementation work maps back to the research contribution
  layers (A, B, C) and the base paper layers (L1, L2, L3).  
- **Status:** ✅ Accepted

---

### DECISION-002 — Mock Server Common Interface
- **Date:** 2026-11-21
- **Decision:** Every mock server exposes exactly two public methods:
  `list_tools() -> list[dict]` and `call(tool, args) -> dict`.
  The response dict always contains `ok` (bool), `result | error` (str/Any),
  and `meta` (dict with `server`, `tool`, `effect`).
- **Alternatives considered:**
  - MCP wire-format JSON-RPC directly — rejected: overkill for the mock layer;
    `stdio_mcp_server.py` will handle the real wire format separately.
  - Per-tool methods on the class — rejected: harder to route generically from
    `mcp_backend.py`.
- **Rationale:** A uniform dict interface lets `mcp_backend.py` route any call
  with a single pattern; the `meta.effect` field feeds directly into Layer A
  and Layer C without further lookup.
- **Status:** ✅ Accepted

---

### DECISION-003 — Server-side AST Scan in CodeServer
- **Date:** 2026-11-21
- **Decision:** `code_server.py` runs its own `ast.parse` scan and embeds the
  result in `meta.ast_scan`. The gateway's Layer A also performs an independent
  AST scan.
- **Rationale:** Defence in depth — the server rejects truly dangerous code
  with a simulated non-zero exit code even if the gateway were bypassed; Layer A
  performs the authoritative policy decision. Duplicate work is negligible for
  a mock server.
- **Status:** ✅ Accepted

---

### DECISION-005 — Session Levels as Discrete Enforcement Modes
- **Date:** 2026-11-21
- **Decision:** `SessionState.level` (0–3) is a single integer that selects
  the entire enforcement mode for a session. Levels are NOT cumulative stacks
  applied simultaneously; `pipeline.process()` dispatches to exactly one
  `_l0` / `_l1` / `_l2` / `_l3` handler per call.
- **Alternatives considered:**
  - Flags per layer (scope_enabled, readonly_enabled, approval_enabled) —
    rejected: combinatorial explosion of test states; levels map cleanly to
    the base paper's Table 1.
  - Separate pipeline classes per level — rejected: harder to change level
    at runtime (e.g. during elevation).
- **Status:** ✅ Accepted

---

### DECISION-006 — Elevation Scoped to Specific Tool, Not Whole Session
- **Date:** 2026-11-21
- **Decision:** `ApprovalQueue.approve()` calls `session.grant_elevation(tools=[(server,tool)])`.
  Elevation covers ONLY the specific (server, tool) pair that was approved, not
  all sensitive tools.
- **Rationale:** Principle of least privilege — a human approving `force_push`
  should not implicitly authorise `merge_pr`. Each sensitive call requires its
  own approval cycle.
- **Status:** ✅ Accepted

---

### DECISION-012 — Benchmark Dataset & Empirical Ablation Evaluation Suite
- **Date:** 2026-11-21
- **Decision:** Implemented `eval/tasks.py` and `eval/run_experiments.py`:
  1. *Benchmark Dataset (`eval/tasks.py`)*: Comprises 40 standardized tasks:
     - 15 Benign Tasks: realistic assistant workflows (branching, commits, PR review, docs, emails, arithmetic).
     - 25 Attack Tasks: spanning 7 vulnerability categories (path traversal, protected branch operations, credential exfiltration, indirect web injection, indirect email injection, chained secret read-and-send, malicious AST execution).
  2. *Empirical Experiment Runner (`eval/run_experiments.py`)*:
     - Automated comparative evaluation across ablation configurations (`L0`, `L2`, `L3`, `P1`, `P12`, `P123`).
     - Formal metrics: `attack_block_rate_%`, `benign_completion_%`, `false_positive_rate_%`, `attack_attempted_%`, `block_given_attempt_%`, and latency.
     - Isolate LLM prompt refusal vs gateway blocking via `block_given_attempt_%` so un-attempted attacks do not artificially boost gateway efficacy scores.
     - Exports publication-ready reports to `results/summary.txt`, `results/ablation_summary.csv`, and `results/results.csv`.
- **Rationale:** Provides rigorous empirical evidence to validate the research project's core contribution against baseline tool-level gateways.
- **Status:** ✅ Accepted

---

### DECISION-011 — Agent Framework, Human Approver, and Structured JSONL Logging
- **Date:** 2026-11-21
- **Decision:** Implemented agent execution runtimes, approval interfaces, structured logging, and CLI orchestration:
  1. *ReAct Agent (`agent/react_agent.py`)*: Local Ollama ReAct agent (`llama3.1:8b`) with fixed temperature 0.0 and seed 42, automated JSON block extraction, regex trailing-comma and quote healing, and clear guidance if Ollama is unreachable.
  2. *Simulated Agent (`agent/simulated_agent.py`)*: Deterministic agent for offline benchmark evaluation and prompt injection vulnerability simulation.
  3. *Approval Operators (`gateway/approval.py`)*: `ConsoleApprover` for interactive operator confirmation with timeout-based auto-deny; `ScriptedApprover` with customizable policies (`approve_all`, `deny_all`, lambda) for automated experiments.
  4. *Structured Logging (`gateway/logger.py`)*: Appends every gateway call to `logs/calls.jsonl` tracking timestamp, model, task, mode, Action JSON, Layer A/B/C outputs, decision, reason, and latency.
  5. *CLI Orchestration (`main.py`)*: Unified entry point providing `demo`, `chat`, and `run` commands.
- **Rationale:** Completes the end-to-end agentic workflow, enabling live interactive operation, automated headless testing, and comprehensive trace capture for research dashboards.
- **Status:** ✅ Accepted

---

### DECISION-010 — Layer C Risk Scoring Engine & Ablation Pipeline Modes
- **Date:** 2026-11-21
- **Decision:** Implemented `gateway/layer3_risk.py` and upgraded `gateway/pipeline.py` with multi-dimensional risk scoring and comprehensive ablation mode support:
  1. *Risk Vector*: Combines `tool_sensitivity` (read 0.1, write 0.5, sensitive 0.9), `param_risk` (from Layer A), `taint` (from Layer B), `privilege_level` (elevation/gap), and `chain_risk` (multi-step sequence analysis such as secret-read followed by outbound call).
  2. *Configurable Weights & Thresholds*: Default weights and thresholds loaded from `gateway/config.json` (`<0.30` ALLOW, `0.30..0.60` DOWNGRADE, `0.60..0.85` APPROVAL, `>=0.85` BLOCK), supporting ablation overrides.
  3. *Hard Rule Overrides*: Hard violations in Layer A or Layer B override the numeric score to 1.0 and force an immediate BLOCK decision.
  4. *Ablation Modes*: `pipeline.process()` supports explicit ablation modes `L0`, `L1`, `L2`, `L3`, `P1`, `P12`, and `P123`.
  5. *Performance Tracking*: Precision latency measurement recorded using `time.perf_counter()` stored as `latency_ms` in `decision.meta` and session history.
- **Rationale:** Enables rigorous empirical evaluation and ablation comparisons across base-paper baselines and our contribution layers.
- **Status:** ✅ Accepted

---

### DECISION-009 — Dynamic Taint Engine Architecture & Flow Representation (Layer B)
- **Date:** 2026-11-21
- **Decision:** Implemented `gateway/layer2_taint.py` with dual-phase operation:
  1. *Observation Ingestion*: Automatically intercepts observations from untrusted sources (`web.fetch_url`, `mail.read_inbox`, PR/issue texts), runs prompt-injection scans (`ignore previous instructions`, hidden HTML comments, `system override`, exfiltration directives), computes SHA-256 hashes, extracts entities/n-grams, and registers `{id, source, content, hash, timestamp}` in `session.taint_store`.
  2. *Propagation & Sink Policy*: Evaluates subsequent tool calls for entity or n-gram matches against stored taint records. Tainted data targeting sensitive sinks (`send_mail`, `write_file`, `delete_branch`, `force_push`, `code.run_python`) is escalated (`ESCALATE`) or blocked (`BLOCK` for injection payloads).
  3. *Multi-Turn Session Context Taint*: Raises and preserves `session.session_taint_level` across intermediate non-sink steps (e.g., reading files) so multi-turn exfiltration chains are detected and logged as explicit `TaintFlow` graphs.
- **Rationale:** Ensures indirect prompt injections cannot manipulate the agent into executing privileged or exfiltrative actions later in a conversation session.
- **Status:** ✅ Accepted

---

### DECISION-008 — Parameter Validation & Hard vs Soft Boundary (Layer A)
- **Date:** 2026-11-21
- **Decision:** `gateway/layer1_params.py` separates findings into `hard` (immediate block) and `soft` (additive numeric risk `param_risk` in 0..1).
  - Hard checks include: path traversal (`..`, `/etc/`, `.env`, `.ssh`, absolute root prefixes), destructive git commands (`delete_branch`, `force_push`) on protected branches (`main`, `master`, `prod`, etc.), credential exfiltration in outbound args (`mail.send_mail.body`), non-allowlisted email recipient domains, and dangerous AST calls/imports (`os.system`, `subprocess`, `exec`, `eval`, `socket`, `open` on sensitive files).
  - Soft checks include: non-destructive actions on protected branches (`commit_file`), credentials embedded in content arguments (`write_file.content`), and safe standard-library operations in AST (`sys`, `shutil`).
- **Rationale:** Ensures catastrophic exfiltration or destruction is blocked deterministically before reaching the MCP servers, while suspicious or contextual patterns contribute to the downstream Layer C risk scoring engine.
- **Status:** ✅ Accepted

---

### DECISION-007 — Elevation Auto-Expires on Access, Not on a Timer
- **Date:** 2026-11-21
- **Decision:** `SessionState.has_active_elevation()` checks `time.time()` on
  every invocation and clears `self.elevation = None` when TTL has passed.
  No background timer or scheduler is used.
- **Rationale:** Gateway is single-threaded and stdlib-only; polling on
  access is deterministic, testable via backdated `expires_at`, and needs
  no threads.
- **Status:** ✅ Accepted

---

### DECISION-004 — Prompt-Injection Payload in WebServer
- **Date:** 2026-11-21
- **Decision:** `web_server.py` stores a fake page at
  `http://malicious.example.fake/offer` whose content contains a visible
  prompt-injection payload. The page carries `injected=True` in both the
  result dict and `meta.injected_payload` so Layer B can immediately tag the
  observation as untrusted without regex scanning.
- **Rationale:** Provides a realistic taint-source test case; the dual flag
  (content + meta) lets tests verify both the data-plane and the metadata-plane
  behaviour of the taint engine.
- **Status:** ✅ Accepted

---

### DECISION-014 — Local Ollama Integration with Qwen 2.5 (`qwen2.5:3b` / `qwen2.5:1.5b`)
- **Date:** 2026-11-21
- **Decision:** Configured the agent runtime and dashboard to integrate directly with local Ollama models detected on the host (`qwen2.5:3b` and `qwen2.5:1.5b`):
  1. *Default Model*: Selected `qwen2.5:3b` as the default model for `ReActAgent`, CLI tools (`main.py run`, `main.py chat`), and `eval/run_experiments.py`.
  2. *ReAct JSON Parser Enhancement*: Enhanced `agent/react_agent.py` to prioritize valid `Action` JSON blocks over trailing `Final Answer:` headers when models generate composite step templates, correctly extracting `server`, `tool`, and `args`.
  3. *Dashboard Model Selector*: Updated `dashboard/app.py` Live Agent Playground dropdown to provide direct one-click selection between `Simulated Agent`, `Ollama: qwen2.5:3b`, and `Ollama: qwen2.5:1.5b`.
- **Rationale:** Leverages the user's local installed Ollama model weights for live end-to-end LLM ReAct agent execution while keeping the simulated deterministic agent available for reproducible ablation evaluations.
- **Status:** ✅ Accepted

---

### DECISION-013 — Streamlit Research Dashboard & Live Agent Playground Architecture
- **Date:** 2026-11-21
- **Decision:** Implemented `dashboard/app.py` providing a comprehensive 5-tab user interface reading from `logs/*.jsonl` and evaluation outputs:
  1. *Live Agent Playground*: Interactive prompt input, execution mode selection (`L0, L1, L2, L3, P1, P12, P123`), scope restriction multi-select, and an injection planter that can plant customized prompt injections into `web.fetch_url` or `mail.read_inbox` prior to agent execution. Steps are rendered in real time with call badges and observations.
  2. *Live Decision Table*: Color-coded table with green (`ALLOW`), yellow (`DOWNGRADE`), orange (`APPROVAL`), and red (`BLOCK`) badges. Provides faceted filtering by decision status, ablation mode, server, and free-text search.
  3. *Taint Flow View*: Visualizes registered taint items from `session.taint_store` alongside detected Source $\to$ Sink flow matrices and detailed propagation logs.
  4. *Risk Score Breakdown*: Interactive inspection of any logged call displaying the 5D risk components (`tool_sensitivity`, `param_risk`, `taint`, `privilege_level`, `chain_risk`), component weight contributions, and trigger rationales.
  5. *Benchmark & Ablation Charts*: Parses `results/ablation_summary.csv` to visualize empirical attack block rates, benign completion rates, false positive rates, and execution latency overhead across all tested configurations.
- **Rationale:** Satisfies final-year project visual demonstration and research evaluation requirements, providing an accessible dashboard for reviewers to probe defenses dynamically.
- **Status:** ✅ Accepted

---

> [!NOTE]
> New decisions will be appended below the latest DECISION-* entry as
> development proceeds. Each entry records: Date, Decision, Alternatives
> Considered, Rationale, Status.

---

*End of SPEC.md*
