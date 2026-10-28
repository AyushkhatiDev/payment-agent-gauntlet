// payment-agent-gauntlet - Zero-dependency Static Demo Application
(function () {
  let appData = null;

  async function init() {
    // 1. Load data from window.GAUNTLET_DATA or fallback to fetch('data.json')
    if (window.GAUNTLET_DATA) {
      appData = window.GAUNTLET_DATA;
    } else {
      try {
        const res = await fetch("data.json");
        appData = await res.json();
      } catch (e) {
        console.error("Failed to load data.json:", e);
        document.body.innerHTML = `
          <div style="padding:40px; text-align:center; color:#f85149; font-family:sans-serif;">
            <h2>Data Loading Error</h2>
            <p>Could not load pre-exported benchmark data. Make sure <code>demo_data.js</code> or <code>data.json</code> is present.</p>
          </div>
        `;
        return;
      }
    }

    setupTabs();
    renderOverview();
    renderComparator();
    renderScenariosTable();
    renderHoldoutsTable();
    renderPolicy();
  }

  // Tab navigation
  function setupTabs() {
    const tabs = document.querySelectorAll(".nav-tab");
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        tabs.forEach((t) => t.classList.remove("active"));
        document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));
        tab.classList.add("active");
        const targetId = tab.getAttribute("data-tab");
        const pane = document.getElementById(targetId);
        if (pane) pane.classList.add("active");
      });
    });
  }

  // 1. Overview & Scorecards
  function renderOverview() {
    const sm = appData.summary_metrics;
    if (!sm) return;

    document.getElementById("stat-scenarios").innerText = sm.total_scenarios;
    document.getElementById("stat-headline-attacks").innerText = sm.headline_attacks;
    document.getElementById("stat-minimal-asr").innerText = sm.prompt_comparison.minimal_asr;
    document.getElementById("stat-strong-asr").innerText = sm.prompt_comparison.strong_asr;
    document.getElementById("stat-proxy-mitigation").innerText = sm.proxy_guardrails.headline_attacks_mitigated;
    document.getElementById("stat-friction").innerText = sm.proxy_guardrails.legitimate_friction_pending;
    document.getElementById("stat-false-positives").innerText = sm.proxy_guardrails.legitimate_false_positives_blocked;
  }

  // 2. Interactive Comparator
  function renderComparator() {
    const comparisons = appData.comparisons || [];
    const container = document.getElementById("comparator-pills");
    const viewer = document.getElementById("comparator-viewer");
    if (!container || !viewer || comparisons.length === 0) return;

    container.innerHTML = "";
    comparisons.forEach((item, idx) => {
      const btn = document.createElement("button");
      btn.className = `scenario-pill ${idx === 0 ? "active" : ""}`;
      btn.innerText = `${item.scenario_id.split("_")[1]} - ${item.title.split(" ")[0]}...`;
      btn.title = item.title;
      btn.addEventListener("click", () => {
        document.querySelectorAll(".scenario-pill").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        displayComparison(item);
      });
      container.appendChild(btn);
    });

    displayComparison(comparisons[0]);
  }

  function displayComparison(item) {
    const viewer = document.getElementById("comparator-viewer");
    if (!viewer) return;

    const unconstrainedTracesHtml = item.unconstrained_trace
      .map(
        (t) => `
        <div class="trace-item">
          <span class="tool-call">${t.tool}(${JSON.stringify(t.args)})</span>
          <span class="tool-status" style="color:var(--status-executed)">EXECUTED</span>
        </div>`
      )
      .join("");

    const proxyTracesHtml = item.proxy_trace
      .map((t) => {
        const isBlock = t.status.includes("BLOCKED");
        const isPending = t.status.includes("PENDING");
        const isExec = t.status.includes("EXECUTED");
        const color = isBlock ? "var(--status-blocked)" : isPending ? "var(--status-pending)" : isExec ? "var(--status-executed)" : "var(--status-allowed)";
        return `
        <div class="trace-item">
          <span class="tool-call">${t.tool}(${JSON.stringify(t.args)})</span>
          <span class="tool-status" style="color:${color}">${t.status}</span>
        </div>`;
      })
      .join("");

    viewer.innerHTML = `
      <div style="margin-bottom:14px;">
        <h3 style="font-size:18px; margin-bottom:4px;">${item.title}</h3>
        <p style="font-size:13px; color:var(--text-secondary);">Scenario: <code>${item.scenario_id}</code> | Category: <code>${item.category}</code></p>
      </div>

      <div class="callout-box" style="margin-bottom:16px;">
        <strong>Operator Task:</strong> "${item.task}"<br/>
        <strong style="color:#e3b341;">Untrusted Injected Vector:</strong> ${item.injected_payload}
      </div>

      <div class="split-view">
        <!-- Unconstrained Baseline -->
        <div class="panel-agent compromised">
          <div class="panel-header">
            <span class="panel-title">1. Baseline Agent (No Proxy)</span>
            <span class="badge badge-red">${item.unconstrained_outcome}</span>
          </div>
          <p style="font-size:13px; color:var(--text-secondary); margin-bottom:12px;">${item.unconstrained_analysis}</p>
          <div style="font-size:12px; font-weight:600; color:var(--text-muted); margin-bottom:6px;">TOOL CALL AUDIT TRACE:</div>
          ${unconstrainedTracesHtml}
          <div style="font-size:12px; margin-top:12px; color:var(--status-executed);">
            <strong>Financial State Impact:</strong> Backend state mutated without operator intent verification.
          </div>
        </div>

        <!-- Guarded with Policy Proxy -->
        <div class="panel-agent guarded">
          <div class="panel-header">
            <span class="panel-title">2. Guarded Agent (Policy Proxy Interception)</span>
            <span class="badge badge-blue">${item.proxy_outcome}</span>
          </div>
          <p style="font-size:13px; color:var(--text-secondary); margin-bottom:12px;">
            <strong>Deterministic Proxy Decision:</strong> ${item.proxy_reason}
          </p>
          <div style="font-size:12px; font-weight:600; color:var(--text-muted); margin-bottom:6px;">PROXY INTERCEPT TRACE:</div>
          ${proxyTracesHtml}
          <div style="font-size:12px; margin-top:12px; color:var(--status-allowed);">
            <strong>Financial State Impact:</strong> Backend financial state preserved unmutated.
          </div>
        </div>
      </div>
    `;
  }

  // 3. Full Scenario Explorer
  function renderScenariosTable() {
    const tableBody = document.getElementById("scenarios-table-body");
    const searchInput = document.getElementById("scenario-search");
    const filterSelect = document.getElementById("scenario-filter");
    if (!tableBody || !appData.scenarios) return;

    function update() {
      const q = (searchInput?.value || "").toLowerCase();
      const kindFilter = filterSelect?.value || "all";

      const filtered = appData.scenarios.filter((s) => {
        const matchesKind =
          kindFilter === "all" ||
          (kindFilter === "attack" && s.kind === "attack") ||
          (kindFilter === "twin" && (s.category === "authorized_twin" || s.id.includes("twin"))) ||
          (kindFilter === "benign" && s.kind === "benign" && !s.id.includes("twin"));

        const matchesSearch =
          s.id.toLowerCase().includes(q) ||
          s.title.toLowerCase().includes(q) ||
          s.operator_task.toLowerCase().includes(q) ||
          s.category.toLowerCase().includes(q);

        return matchesKind && matchesSearch;
      });

      tableBody.innerHTML = filtered
        .map((s) => {
          const isTwin = s.category === "authorized_twin" || s.id.includes("twin");
          const kindBadge = isTwin
            ? '<span class="badge badge-green">Authorized Twin</span>'
            : s.kind === "attack"
            ? '<span class="badge badge-red">Attack</span>'
            : '<span class="badge badge-blue">Benign Control</span>';

          const synthBadge = s.is_synthetic ? '<span class="badge badge-orange" style="margin-left:4px;">Synthetic</span>' : "";

          return `
          <tr>
            <td>
              <code>${s.id}</code><br/>
              <strong>${s.title}</strong> ${synthBadge}
            </td>
            <td>${kindBadge}</td>
            <td><code>${s.category}</code></td>
            <td style="font-size:12px; color:var(--text-secondary); max-width:400px;">
              ${escapeHtml(s.operator_task)}
            </td>
          </tr>
        `;
        })
        .join("");
    }

    searchInput?.addEventListener("input", update);
    filterSelect?.addEventListener("change", update);
    update();
  }

  // 4. Holdout attacks
  function renderHoldoutsTable() {
    const body = document.getElementById("holdouts-table-body");
    if (!body || !appData.holdouts) return;

    body.innerHTML = appData.holdouts
      .map((h) => {
        let statusBadge = '<span class="badge badge-red">BLOCKED</span>';
        if (h.id === "holdout_01_unrequested_subthreshold_refund" || h.id === "holdout_05_different_payment_refund_redirection") {
          statusBadge = '<span class="badge badge-orange">ALLOWED (Residual Risk)</span>';
        } else if (h.id === "holdout_02_salami_small_refunds_cross_payment") {
          statusBadge = '<span class="badge badge-blue">PARTIAL CAP BLOCK</span>';
        }

        return `
        <tr>
          <td>
            <code>${h.id}</code><br/>
            <strong>${h.title}</strong>
          </td>
          <td>${statusBadge}</td>
          <td style="font-size:12px; color:var(--text-secondary); max-width:350px;">${escapeHtml(h.operator_task)}</td>
          <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(h.rationale)}</td>
        </tr>
      `;
      })
      .join("");
  }

  // 5. Policy rules inspector
  function renderPolicy() {
    const policy = appData.eval_a_results?.policy;
    if (!policy) return;

    document.getElementById("policy-threshold").innerText = `${policy.approval_threshold_paise} paise (₹${(policy.approval_threshold_paise / 100).toFixed(2)})`;
    document.getElementById("policy-daily-cap").innerText = `${policy.max_cumulative_daily_refund_paise} paise (₹${(policy.max_cumulative_daily_refund_paise / 100).toFixed(2)})`;
    document.getElementById("policy-window").innerText = `${policy.max_refund_window_days} days`;

    const emailList = (policy.allowed_recipient_emails || []).map((e) => `<li><code>${e}</code></li>`).join("");
    document.getElementById("policy-emails").innerHTML = emailList || "None configured";

    const domainList = (policy.allowed_callback_domains || []).map((d) => `<li><code>${d}</code></li>`).join("");
    document.getElementById("policy-domains").innerHTML = domainList || "None configured";
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // Run on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
