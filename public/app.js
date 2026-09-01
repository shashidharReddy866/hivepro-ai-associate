let report = null;

const riskList = document.querySelector("#riskList");
const summary = document.querySelector("#summary");
const provenance = document.querySelector("#provenance");
const searchInput = document.querySelector("#searchInput");
const scoreInput = document.querySelector("#scoreInput");
const scoreValue = document.querySelector("#scoreValue");
const refreshButton = document.querySelector("#refreshButton");

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function tag(text, kind = "") {
  return `<span class="tag ${kind}">${escapeHtml(text)}</span>`;
}

function renderSummary() {
  const values = [
    ["Assets", report.dataSummary.assets],
    ["Vulnerabilities", report.dataSummary.vulnerabilities],
    ["Threat Intel", report.dataSummary.threatIntel],
    ["Services", report.dataSummary.businessServices]
  ];
  summary.innerHTML = values
    .map(([label, value]) => `<div class="metric"><span>${label}</span><strong>${value}</strong></div>`)
    .join("");
}

function searchableText(risk) {
  return [
    risk.asset.name,
    risk.asset.type,
    risk.vulnerability.name,
    risk.vulnerability.cve,
    risk.businessService.name,
    risk.threatIntel?.actor,
    risk.threatIntel?.campaign,
    risk.remediation.nistControl.id,
    risk.remediation.nistControl.name
  ]
    .join(" ")
    .toLowerCase();
}

function renderRisk(risk) {
  const factors = Object.entries(risk.evidence.scoringFactors)
    .map(([name, value]) => `<span class="factor">${escapeHtml(name)}: ${escapeHtml(value)}</span>`)
    .join("");

  const threatText = risk.threatIntel
    ? `${risk.threatIntel.actor} / ${risk.threatIntel.campaign}: ${risk.threatIntel.summary}`
    : "No direct threat intelligence match. Ranking is driven by exposure, business impact, exploitability, and control gaps.";

  return `
    <article class="risk-card">
      <div class="risk-header">
        <div class="rank">#${risk.rank}</div>
        <div>
          <h2>${escapeHtml(risk.asset.name)} - ${escapeHtml(risk.vulnerability.name)}</h2>
          <p class="subtitle">${escapeHtml(risk.vulnerability.cve)} on ${escapeHtml(risk.vulnerability.affectedComponent)} affecting ${escapeHtml(risk.businessService.name)}</p>
        </div>
        <div class="score"><span>Score</span>${escapeHtml(risk.score)}</div>
      </div>

      <div class="tags">
        ${tag(risk.asset.internetExposed === "Yes" ? "Internet exposed" : "Internal")}
        ${tag(`${risk.asset.criticality} asset`, risk.asset.criticality === "Critical" ? "danger" : "")}
        ${tag(`CVSS ${risk.vulnerability.cvss}`)}
        ${tag(risk.vulnerability.exploitAvailable === "Yes" ? "Exploit available" : "No exploit", risk.vulnerability.exploitAvailable === "Yes" ? "warn" : "")}
        ${tag(risk.threatIntel?.ransomware === "Yes" ? "Ransomware campaign" : "No ransomware match", risk.threatIntel?.ransomware === "Yes" ? "danger" : "")}
        ${tag(risk.asset.edrInstalled === "Yes" ? "EDR present" : "No EDR", risk.asset.edrInstalled === "Yes" ? "" : "danger")}
      </div>

      <p class="why">${escapeHtml(risk.why)}</p>

      <div class="detail-grid">
        <div class="detail">
          <span class="meta-label">Business Service</span>
          <p>${escapeHtml(risk.businessService.impact)}</p>
        </div>
        <div class="detail">
          <span class="meta-label">Threat Evidence</span>
          <p>${escapeHtml(threatText)}</p>
        </div>
        <div class="detail">
          <span class="meta-label">Remediation Guidance</span>
          <p><strong>${escapeHtml(risk.remediation.nistControl.id)} ${escapeHtml(risk.remediation.nistControl.name)}:</strong> ${escapeHtml(risk.remediation.nistControl.summary)}</p>
        </div>
      </div>

      <div class="factor-list">${factors}</div>
    </article>
  `;
}

function renderRisks() {
  const query = searchInput.value.trim().toLowerCase();
  const minScore = Number(scoreInput.value);
  scoreValue.textContent = String(minScore);

  const risks = report.topRisks.filter((risk) => {
    return risk.score >= minScore && (!query || searchableText(risk).includes(query));
  });

  riskList.innerHTML = risks.length ? risks.map(renderRisk).join("") : '<p class="empty">No top-5 risks match the current filters.</p>';
}

function renderProvenance() {
  const ref = report.referenceProvenance;
  provenance.innerHTML = `
    <strong>Reference retrieval:</strong>
    NIST controls from <code>${escapeHtml(ref.nistUrl)}</code>.
    CISA KEV from <code>${escapeHtml(ref.kevUrl)}</code>
    ${ref.kevCatalogVersion ? `(catalog ${escapeHtml(ref.kevCatalogVersion)}, ${escapeHtml(ref.kevCount)} records).` : "."}
  `;
}

async function loadReport(refresh = false) {
  riskList.innerHTML = '<p class="loading">Loading risk analysis...</p>';
  const response = await fetch(`/api/risks${refresh ? "?refresh=1" : ""}`);
  if (!response.ok) throw new Error(await response.text());
  report = await response.json();
  renderSummary();
  renderRisks();
  renderProvenance();
}

searchInput.addEventListener("input", renderRisks);
scoreInput.addEventListener("input", renderRisks);
refreshButton.addEventListener("click", async () => {
  refreshButton.disabled = true;
  refreshButton.textContent = "Refreshing...";
  try {
    await loadReport(true);
  } finally {
    refreshButton.disabled = false;
    refreshButton.textContent = "Refresh References";
  }
});

loadReport().catch((error) => {
  riskList.innerHTML = `<p class="empty">${escapeHtml(error.message)}</p>`;
});
