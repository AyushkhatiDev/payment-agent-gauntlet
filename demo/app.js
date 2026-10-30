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

    const elScen = document.getElementById("stat-scenarios");
    if (elScen) elScen.textContent = sm.total_scenarios;

    const elAtk = document.getElementById("stat-headline-attacks");
    if (elAtk) elAtk.textContent = sm.headline_attacks;

    const elFric = document.getElementById("stat-friction");
    if (elFric) elFric.textContent = sm.proxy_guardrails.legitimate_friction_pending;

    const elFp = document.getElementById("stat-false-positives");
    if (elFp) elFp.textContent = sm.proxy_guardrails.legitimate_false_positives_blocked;

    // Render Attack Mitigation dynamic table
    const tableBody = document.getElementById("attack-mitigation-table-body");
    if (tableBody && appData.attack_mitigation_table) {
      tableBody.innerHTML = appData.attack_mitigation_table
        .map((row) => {
          return `
          <tr>
            <td>
              <strong>${escapeHtml(row.family)}</strong><br/>
              <span style="font-size:11px; color:var(--text-muted);">${escapeHtml(row.description)}</span>
            </td>
            <td><code>${row.scenario_count}</code></td>
            <td style="color:var(--status-allowed); font-size:12px;">
              <strong>${escapeHtml(row.strong_cell)}</strong>
            </td>
            <td style="color:${row.minimal_executed_k > 0 ? 'var(--status-executed)' : 'var(--text-secondary)'}; font-size:12px;">
              <strong>${escapeHtml(row.minimal_cell)}</strong>
            </td>
            <td style="font-size:12px; color:var(--text-secondary);">
              ${escapeHtml(row.difference_cell)}
            </td>
            <td>
              <span class="badge ${escapeHtml(row.proxy_badge)}">${escapeHtml(row.proxy_desc)}</span>
            </td>
          </tr>
        `;
        })
        .join("");
    }
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
      btn.textContent = `${item.scenario_id.split("_")[1]} - ${item.title.split(" ")[0]}...`;
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
          <span class="tool-call">${escapeHtml(t.tool)}(${escapeHtml(JSON.stringify(t.args))})</span>
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
          <span class="tool-call">${escapeHtml(t.tool)}(${escapeHtml(JSON.stringify(t.args))})</span>
          <span class="tool-status" style="color:${color}">${escapeHtml(t.status)}</span>
        </div>`;
      })
      .join("");

    viewer.innerHTML = `
      <div style="margin-bottom:14px;">
        <h3 style="font-size:18px; margin-bottom:4px;">${escapeHtml(item.title)}</h3>
        <p style="font-size:13px; color:var(--text-secondary);">Scenario: <code>${escapeHtml(item.scenario_id)}</code> | Category: <code>${escapeHtml(item.category)}</code></p>
      </div>

      <div class="callout-box" style="margin-bottom:16px;">
        <strong>Operator Task:</strong> "${escapeHtml(item.task)}"<br/>
        <strong style="color:#e3b341;">Untrusted Injected Vector:</strong> ${escapeHtml(item.injected_payload)}
      </div>

      <div class="split-view">
        <!-- Unconstrained Baseline -->
        <div class="panel-agent compromised">
          <div class="panel-header">
            <span class="panel-title">1. Baseline Agent (No Proxy)</span>
            <div>
              <span class="badge" style="background:rgba(139,148,158,0.2); color:var(--text-secondary); border:1px solid var(--border-color); margin-right:6px;">recorded run</span>
              <span class="badge badge-red">${escapeHtml(item.unconstrained_outcome)}</span>
            </div>
          </div>
          <p style="font-size:13px; color:var(--text-secondary); margin-bottom:12px;">${escapeHtml(item.unconstrained_analysis)}</p>
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
            <div>
              <span class="badge" style="background:rgba(139,148,158,0.2); color:var(--text-secondary); border:1px solid var(--border-color); margin-right:6px;">deterministic simulation, no LLM</span>
              <span class="badge badge-blue">${escapeHtml(item.proxy_outcome)}</span>
            </div>
          </div>
          <p style="font-size:13px; color:var(--text-secondary); margin-bottom:12px;">
            <strong>Deterministic Proxy Decision:</strong> ${escapeHtml(item.proxy_reason)}
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
              <code>${escapeHtml(s.id)}</code><br/>
              <strong>${escapeHtml(s.title)}</strong> ${synthBadge}
            </td>
            <td>${kindBadge}</td>
            <td><code>${escapeHtml(s.category)}</code></td>
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
        } else if (h.id === "holdout_06_replay_idempotency_attack") {
          statusBadge = '<span class="badge badge-red">BLOCKED</span> <span class="badge" style="background:rgba(139,148,158,0.2); color:var(--text-secondary); border:1px solid var(--border-color); font-size:10px;">mock-only convenience; not counted as a defense</span>';
        }

        return `
        <tr>
          <td>
            <code>${escapeHtml(h.id)}</code><br/>
            <strong>${escapeHtml(h.title)}</strong>
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

    const elThresh = document.getElementById("policy-threshold");
    if (elThresh) elThresh.textContent = `${policy.approval_threshold_paise} paise (₹${(policy.approval_threshold_paise / 100).toFixed(2)})`;

    const elCap = document.getElementById("policy-daily-cap");
    if (elCap) elCap.textContent = `${policy.max_cumulative_daily_refund_paise} paise (₹${(policy.max_cumulative_daily_refund_paise / 100).toFixed(2)})`;

    const elWin = document.getElementById("policy-window");
    if (elWin) elWin.textContent = `${policy.max_refund_window_days} days`;

    const emailList = (policy.allowed_recipient_emails || []).map((e) => `<li><code>${escapeHtml(e)}</code></li>`).join("");
    const elEmails = document.getElementById("policy-emails");
    if (elEmails) elEmails.innerHTML = emailList || "None configured";

    const domainList = (policy.allowed_callback_domains || []).map((d) => `<li><code>${escapeHtml(d)}</code></li>`).join("");
    const elDomains = document.getElementById("policy-domains");
    if (elDomains) elDomains.innerHTML = domainList || "None configured";
  }

  function escapeHtml(val) {
    if (val === null || val === undefined) return "";
    const str = typeof val === "string" ? val : String(val);
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Run on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

