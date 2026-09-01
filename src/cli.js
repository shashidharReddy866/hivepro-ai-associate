const { generateRiskReport } = require("./riskEngine");

generateRiskReport({ refresh: process.argv.includes("--refresh") })
  .then((report) => {
    for (const risk of report.topRisks) {
      console.log(`#${risk.rank} ${risk.asset.name} - ${risk.vulnerability.name}`);
      console.log(`Score: ${risk.score} | CVE: ${risk.vulnerability.cve} | Service: ${risk.businessService.name}`);
      console.log(`Threat: ${risk.threatIntel ? `${risk.threatIntel.actor} / ${risk.threatIntel.campaign}` : "No direct match"}`);
      console.log(`Why: ${risk.why}`);
      console.log(`NIST: ${risk.remediation.nistControl.id} ${risk.remediation.nistControl.name}`);
      console.log("");
    }
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
