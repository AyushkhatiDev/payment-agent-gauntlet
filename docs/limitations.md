# Razorpay Test Mode: Capabilities & Sandbox Limitations

This document records the exact operational boundaries discovered during Phase 0 and Phase 1 research into the official **Razorpay MCP Server** and **Razorpay Test Mode APIs**.

---

## 1. What Razorpay Test Mode Supports
- **Test Credentials**: API keys prefixed with `rzp_test_` provide an isolated environment where zero real money moves.
- **Order & Link Generation**: Orders (`POST /v1/orders`) and Payment Links (`POST /v1/payment_links`) can be generated via REST API and Python SDK without browser interaction.
- **Refunds on Existing Captured Payments**: Any test payment that was successfully created and captured can be refunded (`POST /v1/payments/:id/refund`) or partially refunded.
- **Read APIs**: `GET /v1/payments/:id`, `GET /v1/refunds`, etc. work as expected.

---

## 2. Technical Limitations of Razorpay Test Mode for Automated Harnesses

### A. No Server-Side Payment Seeding API
In Razorpay's API design, **there is no server-side endpoint to generate a captured payment entity (`pay_...`) directly**. 
- Payments are exclusively created when a customer checks out via the frontend SDK (`checkout.js`), hosted payment page, or UPI intent.
- Consequently, an automated CI/CD test runner cannot programmatically seed a fresh `pay_...` fixture via pure REST API before every test scenario without automating a headless browser checkout flow.

### B. Lack of State Reset / Snapshotting
The Razorpay cloud test sandbox does not provide an endpoint to wipe data or revert state.
- Once a test payment ID `pay_test_xyz` is refunded in a scenario, its refundable balance is permanently consumed in Razorpay's database.
- A subsequent test scenario attempting to refund `pay_test_xyz` will fail with:
  ```json
  {
    "error": {
      "code": "BAD_REQUEST_ERROR",
      "description": "The payment has already been refunded"
    }
  }
  ```
- Because adversarial safety testing requires deterministic, repeatable setup states across multiple runs, relying solely on cloud sandbox state leads to flakiness.

### C. Merchant Settlement Bank Accounts Require 2FA (No API)
In Razorpay's real architecture, the merchant's primary settlement bank account cannot be changed via merchant API or MCP tools.
- It is strictly an administrative dashboard action requiring mandatory 2-Factor Authentication (SMS OTP to the business owner) and verification document uploads.
- To test the critical threat category *"social engineering an agent into changing the settlement bank account"*, Gauntlet introduces a **`update_settlement_bank_account`** tool. This tool is **strictly labeled as a synthetic/hypothetical admin tool** across all code, scenario definitions, and scorecards.

---

## 3. Engineering Decision: Why Mock MCP Server is Primary

Because of limitations (A) and (B), **`MockRazorpay` (the in-memory Mock MCP server) is the primary deterministic test engine**.
- It boots instantly with zero external network dependencies.
- It executes full resets (`state_engine.reset()`) between scenarios in microseconds.
- It validates exact paise subunit arithmetic and Razorpay error formats (`BAD_REQUEST_ERROR`).
- It maintains an append-only audit log of state mutations so the test runner can evaluate agents on real state changes rather than LLM text output.

The Live Test Mode adapter is reserved for a verified subset of scenarios (e.g. creating test payment links, verifying payment status).
