const assert = require("node:assert/strict");

const { parseCsv } = require("../src/csv");
const { generateRiskReport } = require("../src/riskEngine");

async function testCsvParser() {
  const rows = parseCsv(
    'name,notes\nalpha,"one, two"\nbeta,"line one\nline two"\n'
  );

  assert.equal(rows.length, 2);
  assert.equal(rows[0].notes, "one, two");
  assert.equal(rows[1].notes, "line one\nline two");
}

async function testRiskReport() {
  const report = await generateRiskReport();

  // Basic report structure
  assert.equal(report.topRisks.length, 5);

  // Dataset counts
  assert.equal(report.dataSummary.assets, 60);
  assert.equal(report.dataSummary.vulnerabilities, 114);

  // Scores must be sorted from highest to lowest
  for (let i = 1; i < report.topRisks.length; i += 1) {
    assert.ok(
      report.topRisks[i - 1].score >= report.topRisks[i].score,
      "Top risks must be sorted by descending score"
    );
  }

  // Risk scores must be numeric and normalized to 0–100
  for (const risk of report.topRisks) {
    assert.ok(
      Number.isFinite(risk.score),
      `Risk score must be numeric: ${risk.vulnerability?.cve}`
    );

    assert.ok(
      risk.score >= 0 && risk.score <= 100,
      `Risk score must be between 0 and 100: ${risk.score}`
    );
  }

  // Raw score should be available for transparency
  for (const risk of report.topRisks) {
    assert.ok(
      Number.isFinite(risk.rawScore),
      `Raw score must be numeric: ${risk.vulnerability?.cve}`
    );
  }

  // At least one Top-5 risk should have ransomware evidence
  assert.ok(
    report.topRisks.some(
      (risk) => risk.threatIntel?.ransomware === "Yes"
    ),
    "At least one Top-5 risk should have ransomware evidence"
  );

  // Every Top-5 risk must have NIST remediation
  assert.ok(
    report.topRisks.every(
      (risk) => risk.remediation?.nistControl?.id
    ),
    "Every Top-5 risk should have a NIST control"
  );

  // NIST provenance must point to NIST
  assert.ok(
    report.referenceProvenance?.nistUrl?.includes("nist.gov"),
    "NIST provenance URL must point to nist.gov"
  );
}

async function run() {
  await testCsvParser();
  await testRiskReport();

  console.log("All tests passed");
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});