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
  const statProxy = window.document.getElementById("stat-proxy-mitigation");
  assert.strictEqual(statProxy.textContent, "21 / 22 (95.5%)");

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
