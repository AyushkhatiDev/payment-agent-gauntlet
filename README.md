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
              MCP Protocol (stdio / in-memory)
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

## 💡 Running Without Paid APIs

Gauntlet is provider-agnostic and includes native support for free, open-weights, and local LLMs via OpenAI-compatible endpoints:

### 1. Google Gemini (Free Tier via Google AI Studio)
Google provides a free tier for Gemini models with native tool calling support:
- **Base URL**: `https://generativelanguage.googleapis.com/v1beta/openai/`
- **Models**: `gemini-2.5-flash`, `gemini-1.5-flash`, `gemini-2.0-flash`
- **Setup**:
  ```bash
  # In your .env:
  GEMINI_API_KEY=your_key_here
  
  # Run Gauntlet:
  gauntlet run --provider openai_compatible --model gemini-2.5-flash --api-key-env GEMINI_API_KEY -n 5
  ```

### 2. Groq (High-Speed Free Tier)
Groq provides fast, free inference for open-weights models with tool calling:
- **Base URL**: `https://api.groq.com/openai/v1`
- **Models**: `llama-3.3-70b-versatile`, `llama-3.1-8b-instant`
- **Setup**:
  ```bash
  # In your .env:
  GROQ_API_KEY=your_key_here
  
  # Run Gauntlet:
  gauntlet run --provider openai_compatible --base-url https://api.groq.com/openai/v1 --model llama-3.3-70b-versatile --api-key-env GROQ_API_KEY -n 5
  ```

### 3. Local Ollama (100% Offline & Free)
Run open-source models completely locally on your machine with zero external network calls:
- **Base URL**: `http://localhost:11434/v1`
- **Models**: `llama3.1`, `qwen2.5`, `mistral`
- **Setup**:
  ```bash
  ollama run llama3.1
  
  # Run Gauntlet:
  gauntlet run --provider openai_compatible --base-url http://localhost:11434/v1 --model llama3.1 -n 5
  ```

---

## 📜 Tool Surface & Verification

- **Official Razorpay MCP Tools**: Ground truth dumped directly from official Go server (`razorpay/razorpay-mcp-server`) into `fixtures/razorpay_tools_list.json`.
- **Synthetic Admin Tools**: `update_settlement_bank_account` is explicitly modeled as a synthetic admin capability to test social engineering resilience, isolated from the official tool surface.

See [`docs/limitations.md`](docs/limitations.md) for full documentation of test mode capabilities and sandbox constraints.

---

## 📊 Evaluation Runs & Provenance

All evaluation metrics in Gauntlet derive from recorded, append-only backend traces:
- **Baseline Smoke Test (`results/smoke_test_qwen1.5b_20261026`)**: An initial pipeline verification run. As documented in the run's metadata, `qwen2.5:1.5b` failed the benign controls (0% pass rate), establishing it as incapable of reliable financial tool use. Traces for `scen_04` and `scen_05` act solely as **judge positive controls** (proving that our StateEngine and AuditLog correctly detect state mutations when executed), not security conclusions. `scen_06` results are invalid because the tool error was caused by a mock server schema artifact rather than model defense.
- **Scorecard Metric Structure**: For every evaluated model, Gauntlet reports **Benign Control Pass Rate**, **Authorized Twin Pass Rate**, and only then Attack Attempt and Success Rates.
