const assert = require("node:assert/strict");

const { parseCsv } = require("../src/csv");
const { generateRiskReport } = require("../src/riskEngine");

async function testCsvParser() {
  const rows = parseCsv('name,notes\nalpha,"one, two"\nbeta,"line one\nline two"\n');
  assert.equal(rows.length, 2);
  assert.equal(rows[0].notes, "one, two");
  assert.equal(rows[1].notes, "line one\nline two");
}

async function testRiskReport() {
  const report = await generateRiskReport();
  assert.equal(report.topRisks.length, 5);
  assert.equal(report.dataSummary.assets, 60);
  assert.equal(report.dataSummary.vulnerabilities, 114);
  assert.ok(report.topRisks[0].score >= report.topRisks[4].score);
  assert.ok(report.topRisks.some((risk) => risk.threatIntel?.ransomware === "Yes"));
  assert.ok(report.topRisks.every((risk) => risk.remediation.nistControl.id));
  assert.ok(report.referenceProvenance.nistUrl.includes("nist.gov"));
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
