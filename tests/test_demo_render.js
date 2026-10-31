const { JSDOM } = require("jsdom");
const fs = require("fs");
const path = require("path");
const assert = require("assert");

function runSmokeTest() {
  console.log("=== Running Demo Rendering Smoke Test with jsdom ===");

  const html = fs.readFileSync(path.join(__dirname, "../demo/index.html"), "utf8");
  const demoDataJs = fs.readFileSync(path.join(__dirname, "../demo/demo_data.js"), "utf8");
  const appJs = fs.readFileSync(path.join(__dirname, "../demo/app.js"), "utf8");

  const errors = [];

  const virtualConsole = new (require("jsdom").VirtualConsole)();
  virtualConsole.on("error", (err) => {
    errors.push(err);
  });

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    url: "http://localhost/",
    virtualConsole
  });

  const { window } = dom;

  window.addEventListener("error", (e) => {
    errors.push(e.error || e.message);
  });

  // Evaluate pre-exported benchmark data and application bundle
  window.eval(demoDataJs);
  window.eval(appJs);

  // Dispatch DOMContentLoaded if readyState was loading
  if (window.document.readyState === "loading") {
    window.document.dispatchEvent(new window.Event("DOMContentLoaded"));
  }

  // 1. Assert Overview Elements
  const statScenarios = window.document.getElementById("stat-scenarios");
  if (statScenarios) assert.strictEqual(statScenarios.textContent, "52");

  const statStrong = window.document.getElementById("stat-strong-asr");
  assert(statStrong.textContent.includes("0 of 110 runs"));

  const statMinimal = window.document.getElementById("stat-minimal-asr");
  assert(statMinimal.textContent.includes("15 of 75 runs"));
  assert(statMinimal.textContent.includes("scen_04, scen_06b, scen_23"));

  const statProxy = window.document.getElementById("stat-proxy-mitigation");
  assert(statProxy.textContent.includes("8 blocked, 11 held for approval"));

  const statFriction = window.document.getElementById("stat-friction");
  assert.strictEqual(statFriction.textContent, "12 / 24 (50.0%)");

  const statFp = window.document.getElementById("stat-false-positives");
  assert.strictEqual(statFp.textContent, "4 / 24 (16.7%)");

  // Assert Attack Mitigation Table
  const mitigationRows = window.document.querySelectorAll("#attack-mitigation-table-body tr");
  console.log(`✓ Attack Mitigation Table: ${mitigationRows.length} families rendered`);
  assert(mitigationRows.length >= 5, "Attack mitigation table must have at least 5 rows");

  // Assert Comparator Tab
  const compPills = window.document.querySelectorAll("#comparator-pills button");
  console.log(`✓ Comparator Pills: ${compPills.length} scenarios available`);
  assert(compPills.length >= 4, "Comparator must have pills");

  // 1b. Test Comparator Interactions & Financial State Impact
  const compViewer = window.document.getElementById("comparator-viewer");
  assert(compViewer, "Comparator viewer must exist");

  // Check initial scen_01 (default)
  const scen01Baseline = compViewer.querySelector(".panel-agent.compromised");
  assert(scen01Baseline, "scen_01 baseline panel must exist");
  assert(
    !scen01Baseline.textContent.toLowerCase().includes("state mutated"),
    "scen_01 baseline panel must NOT contain 'state mutated'"
  );

  // Find and click pill for scen_23
  const pill23 = Array.from(compPills).find((p) => p.textContent.includes("23"));
  assert(pill23, "scen_23 pill must exist");
  pill23.click();

  const scen23SubPanels = compViewer.querySelectorAll(".sub-panel");
  assert(
    scen23SubPanels.length >= 2,
    `scen_23 inspector must display both minimal-prompt and strong-prompt sub-panels; found ${scen23SubPanels.length}`
  );
  const subPanelTexts = Array.from(scen23SubPanels).map((p) => p.textContent);
  assert(
    subPanelTexts.some((t) => t.includes("minimal prompt")),
    "scen_23 inspector must display minimal prompt sub-panel"
  );
  assert(
    subPanelTexts.some((t) => t.includes("strong prompt")),
    "scen_23 inspector must display strong prompt sub-panel"
  );

  // Find and click pill for scen_12
  const pill12 = Array.from(compPills).find((p) => p.textContent.includes("12"));
  assert(pill12, "scen_12 pill must exist");
  pill12.click();

  const scen12Guarded = compViewer.querySelector(".panel-agent.guarded");
  assert(scen12Guarded, "scen_12 guarded panel must exist");
  assert(
    scen12Guarded.textContent.includes("mutated"),
    "scen_12 guarded panel must contain 'mutated'"
  );
  assert(
    !scen12Guarded.textContent.includes("preserved unmutated"),
    "scen_12 guarded panel must NOT contain 'preserved unmutated'"
  );

  // Assert NO tab shows the text "INTERCEPTED"
  const allTabs = window.document.querySelectorAll(".tab-pane");
  allTabs.forEach((tab) => {
    const text = tab.textContent;
    assert(
      !text.includes("INTERCEPTED"),
      `Tab ${tab.id} must not show the text 'INTERCEPTED'`
    );
  });

  // 2. Test Tab Navigation
  const tabButtons = window.document.querySelectorAll(".nav-tab");
  assert(tabButtons.length === 6, `Expected 6 tabs, found ${tabButtons.length}`);

  tabButtons.forEach((tab) => {
    tab.click();
    const targetId = tab.getAttribute("data-tab");
    const pane = window.document.getElementById(targetId);
    assert(pane.classList.contains("active"), `Tab pane ${targetId} must be active after click`);
  });
  console.log("✓ All 6 tabs visited and activated successfully");

  // 3. Test Scenario Explorer Filter Options
  const scenariosBody = window.document.getElementById("scenarios-table-body");
  const filterSelect = window.document.getElementById("scenario-filter");
  assert(filterSelect, "Scenario filter select element must exist");

  const expectedOptions = ["all", "attack", "twin", "benign"];
  const actualOptions = Array.from(filterSelect.options).map((o) => o.value);
  assert.deepStrictEqual(actualOptions, expectedOptions);

  expectedOptions.forEach((opt) => {
    filterSelect.value = opt;
    filterSelect.dispatchEvent(new window.Event("change"));
    const rowCount = scenariosBody.querySelectorAll("tr").length;
    console.log(`✓ Filter '${opt}': ${rowCount} rows rendered`);
    assert(rowCount > 0, `Filter '${opt}' returned 0 rows! Every filter option must return rows.`);
  });

  // 4. Test Pre-Registered Holdouts Tab
  const holdoutRows = window.document.querySelectorAll("#holdouts-table-body tr");
  console.log(`✓ Pre-Registered Holdouts Table: ${holdoutRows.length} rows rendered`);
  assert.strictEqual(holdoutRows.length, 6, "Expected exactly 6 holdout rows");

  // Assert holdout_06 badge matches and renders mock-only convenience label
  const holdout06Row = Array.from(holdoutRows).find((r) => r.innerHTML.includes("holdout_06_replay_altered_amount"));
  assert(holdout06Row, "holdout_06_replay_altered_amount row must exist in holdouts table");
  assert(
    holdout06Row.textContent.includes("mock-only convenience; not counted as a defense"),
    "holdout_06 row must contain 'mock-only convenience; not counted as a defense' badge"
  );

  // 5. Test Policy Guardrails Tab
  const emailItems = window.document.querySelectorAll("#policy-emails li");
  const domainItems = window.document.querySelectorAll("#policy-domains li");
  console.log(`✓ Policy Guardrails: ${emailItems.length} allowed emails, ${domainItems.length} allowed domains`);
  assert.strictEqual(emailItems.length, 7, "Expected 7 allowed emails");
  assert.strictEqual(domainItems.length, 6, "Expected 6 allowed domains");

  // 6. Assert No JavaScript Errors
  if (errors.length > 0) {
    console.error("JavaScript errors captured during render:", errors);
    process.exit(1);
  }

  console.log("=== All Demo Rendering Smoke Tests Passed Cleanly with Zero Errors ===");
}

runSmokeTest();
