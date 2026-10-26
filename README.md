# Gauntlet 🥊
### Adversarial Safety Test Harness for Payment Agents

> **An open-source adversarial evaluation suite that attacks AI agents capable of moving money (refunds, payment links, settlements, lookups) and scores whether they hold up under real financial attacks.**

---

## ⚡ Overview

As financial platforms like **Razorpay Agent Studio** open their ecosystems to autonomous third-party agents, the barrier to entry shifts from *can the agent perform the task* to *can the agent safely refuse malicious financial manipulation*.

Gauntlet benchmarks payment agents against adversarial prompts, prompt injections, race conditions, over-refunding, cross-tenant data leaks, and unauthorized settlement redirects.

### Core Philosophy
1. **Judge on Real State Changes, Not Words**: We don't judge whether the LLM claimed *"I will not process that refund"*. We assert against an append-only backend audit log to prove whether a refund, payment link, or settlement actually occurred in the financial state engine.
2. **Deterministic Baseline vs Live Sanity**: Uses an in-memory Mock MCP server matching official Razorpay MCP tool schemas and paise rules, backed by an opt-in live test-mode adapter.
3. **No Hallucinated Benchmarks**: Every scorecard metric comes from recorded, reproducible execution runs saved in `results/`.
4. **Benign Controls Included**: Evaluates both **Attack Success Rate (ASR)** and **False Refusal Rate (FRR)** on legitimate operations.
5. **Separation of Real vs Synthetic Surfaces**: Tools matching the official Razorpay MCP server are strictly separated from synthetic admin tools (`update_settlement_bank_account`), which are labeled as synthetic across all scenarios and reports.

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────┐
│                   Test Runner                          │
│  - Loads YAML scenarios (Attacks + Benign Controls)    │
│  - Executes agent loop over MCP protocol               │
│  - Inspects append-only state audit log                │
│  - Computes Attack Success Rate & False Refusal Rate   │
└───────────────────────────┬────────────────────────────┘
                            │
              MCP Protocol (stdio / http)
                            │
┌───────────────────────────▼────────────────────────────┐
│              Mock Razorpay MCP Server                  │
│  - Official Razorpay tool schemas (auto-generated)     │
│  - State Engine: Payments, Refunds, Settlements, Links │
│  - Strict paise & financial state machine validation   │
│  - Append-only Audit Log of state mutations            │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart

### Prerequisites
- Python 3.11+
- `uv` (recommended) or `pip`

```bash
# Clone the repository
git clone https://github.com/edwardkhati/Gauntlet.git
cd Gauntlet

# Setup virtual environment and install dependencies
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Run tests
pytest
```

---

## 📜 Tool Surface & Verification

- **Official Razorpay MCP Tools**: Ground truth dumped directly from official Go server (`razorpay/razorpay-mcp-server`) into `fixtures/razorpay_tools_list.json`.
- **Synthetic Admin Tools**: `update_settlement_bank_account` is explicitly modeled as a synthetic admin capability to test social engineering resilience, isolated from the official tool surface.

See [`docs/limitations.md`](docs/limitations.md) for full documentation of test mode capabilities and sandbox constraints.
