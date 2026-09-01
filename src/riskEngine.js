const fs = require("node:fs/promises");
const path = require("node:path");

const { parseCsv } = require("./csv");

const ROOT = path.join(__dirname, "..");
const DATA_DIR = path.join(ROOT, "data");
const REFERENCE_DIR = path.join(ROOT, "references");
const NIST_CACHE = path.join(REFERENCE_DIR, "nist_sp800_53_controls.csv");
const KEV_CACHE = path.join(REFERENCE_DIR, "cisa_kev.json");

const NIST_URL =
  "https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/NIST_SP-800-53_rev5_catalog_load.csv";
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const CONTROL_HINTS = {
  default: ["SI-2", "RA-5"],
  vpn: ["SI-2", "AC-2", "IR-4"],
  authentication: ["AC-2", "SI-2"],
  api: ["SI-2", "AC-2", "RA-5"],
  ransomware: ["IR-4", "SI-2"],
  "project management": ["SI-2", "AC-2", "RA-5"],
  confluence: ["SI-2", "AC-2", "RA-5"],
  jenkins: ["SA-22", "SI-2", "RA-5"],
  teamcity: ["SA-22", "SI-2", "RA-5"],
  citrix: ["SI-2", "IR-4", "AC-2"],
  unsupported: ["SA-22", "SI-2"]
};

async function readCsv(fileName) {
  return parseCsv(await fs.readFile(path.join(DATA_DIR, fileName), "utf8"));
}

async function readDataPack() {
  const [assets, vulnerabilities, threatIntel, businessServices, remediationHints, threatReport] =
    await Promise.all([
      readCsv("assets.csv"),
      readCsv("vulnerabilities.csv"),
      readCsv("threat_intelligence.csv"),
      readCsv("business_services.csv"),
      readCsv("remediation_guidance.csv"),
      fs.readFile(path.join(DATA_DIR, "synthetic_threat_report.md"), "utf8")
    ]);

  return { assets, vulnerabilities, threatIntel, businessServices, remediationHints, threatReport };
}

async function fetchText(url) {
  const response = await fetch(url, { headers: { "user-agent": "hivepro-assignment-risk-assistant/1.0" } });
  if (!response.ok) throw new Error(`Failed to retrieve ${url}: HTTP ${response.status}`);
  return response.text();
}

async function refreshReferences() {
  await fs.mkdir(REFERENCE_DIR, { recursive: true });
  const [nistCsv, kevJson] = await Promise.all([fetchText(NIST_URL), fetchText(KEV_URL)]);
  await Promise.all([fs.writeFile(NIST_CACHE, nistCsv), fs.writeFile(KEV_CACHE, kevJson)]);
  return {
    nist: { source: NIST_URL, bytes: Buffer.byteLength(nistCsv) },
    cisaKev: { source: KEV_URL, bytes: Buffer.byteLength(kevJson) }
  };
}

async function ensureReferences(refresh = false) {
  try {
    if (refresh) throw new Error("refresh requested");
    const [nistCsv, kevJson] = await Promise.all([
      fs.readFile(NIST_CACHE, "utf8"),
      fs.readFile(KEV_CACHE, "utf8")
    ]);
    return parseReferences(nistCsv, kevJson, false);
  } catch (_) {
    const result = await refreshReferences();
    const [nistCsv, kevJson] = await Promise.all([
      fs.readFile(NIST_CACHE, "utf8"),
      fs.readFile(KEV_CACHE, "utf8")
    ]);
    return { ...parseReferences(nistCsv, kevJson, true), refreshResult: result };
  }
}

function parseReferences(nistCsv, kevJson, refreshed) {
  const controls = parseCsv(nistCsv).map((control) => ({
    id: control.identifier,
    name: control.name,
    text: control.control_text || "",
    discussion: control.discussion || "",
    related: control.related || ""
  }));

  const kev = JSON.parse(kevJson);
  const kevByCve = new Map((kev.vulnerabilities || []).map((item) => [item.cveID, item]));
  return {
    controls,
    kevByCve,
    provenance: {
      nistUrl: NIST_URL,
      kevUrl: KEV_URL,
      refreshed,
      kevCatalogVersion: kev.catalogVersion,
      kevDateReleased: kev.dateReleased,
      kevCount: kev.count
    }
  };
}

function normalize(value) {
  return String(value || "").trim().toLowerCase();
}

function boolYes(value) {
  return normalize(value) === "yes";
}

function serviceScore(service) {
  let score = 0;
  if (!service) return score;
  if (service.risk_appetite === "Very Low") score += 12;
  if (service.risk_appetite === "Low") score += 7;
  if (service.revenue_impact === "Critical") score += 12;
  if (service.revenue_impact === "High") score += 8;
  if (boolYes(service.customer_facing)) score += 6;
  if (Number(service.rto_hours) <= 1) score += 6;
  if (service.compliance_scope) score += service.compliance_scope.includes("PCI") ? 8 : 4;
  return score;
}

function criticalityScore(asset) {
  if (asset.criticality === "Critical") return 12;
  if (asset.criticality === "High") return 8;
  if (asset.criticality === "Medium") return 4;
  return 1;
}

function exploitScore(vulnerability, intel, kevEntry) {
  let score = 0;
  if (boolYes(vulnerability.exploit_available)) score += 16;
  if (normalize(vulnerability.auth_required) === "no") score += 6;
  if (intel?.exploit_maturity === "Weaponized") score += 16;
  if (intel?.ransomware_association === "Yes") score += 14;
  if (kevEntry) score += 10;
  if (kevEntry?.knownRansomwareCampaignUse === "Known") score += 12;
  return score;
}

function missingControlScore(asset, vulnerability) {
  let score = 0;
  if (!boolYes(asset.edr_installed)) score += 12;
  if (Number(asset.last_seen_days) > 14) score += 4;
  if (!boolYes(vulnerability.patch_available)) score += 4;
  if (Number(vulnerability.days_open) > 30) score += 4;
  if (Number(vulnerability.days_open) > 90) score += 3;
  return score;
}

function findRemediationHint(remediationHints, vulnerability) {
  const haystack = normalize(`${vulnerability.vulnerability_name} ${vulnerability.affected_component}`);
  let best = null;
  let bestScore = 0;
  for (const hint of remediationHints) {
    const words = normalize(hint.finding_type).split(/\s+/).filter((word) => word.length > 3);
    const score = words.reduce((total, word) => total + (haystack.includes(word) ? 1 : 0), 0);
    if (score > bestScore) {
      best = hint;
      bestScore = score;
    }
  }
  return best;
}

function tokenSet(text) {
  return new Set(
    normalize(text)
      .replace(/[^a-z0-9-\s]/g, " ")
      .split(/\s+/)
      .filter((token) => token.length > 2)
  );
}

function retrieveNistControl(controls, risk, hint) {
  const query = [
    risk.vulnerability.vulnerability_name,
    risk.vulnerability.affected_component,
    risk.asset.asset_type,
    risk.threatIntel?.summary,
    hint?.recommended_action
  ].join(" ");

  const lowerQuery = normalize(query);
  const candidateIds = new Set(CONTROL_HINTS.default);
  for (const [keyword, ids] of Object.entries(CONTROL_HINTS)) {
    if (keyword !== "default" && lowerQuery.includes(keyword)) ids.forEach((id) => candidateIds.add(id));
  }

  const queryTokens = tokenSet(query);
  const candidates = controls.filter((control) => candidateIds.has(control.id));
  const scored = candidates.map((control) => {
    const controlTokens = tokenSet(`${control.id} ${control.name} ${control.text} ${control.discussion}`);
    let score = candidateIds.has(control.id) ? 4 : 0;
    for (const token of queryTokens) if (controlTokens.has(token)) score += 1;
    if (risk.threatIntel?.ransomware_association === "Yes" && control.id === "IR-4") score += 6;
    if (!boolYes(risk.asset.edr_installed) && control.id === "RA-5") score += 3;
    if (/auth|account|credential|token|mfa/.test(lowerQuery) && control.id === "AC-2") score += 5;
    if (/patch|rce|cve|vulnerability|flaw/.test(lowerQuery) && control.id === "SI-2") score += 5;
    if (/jenkins|teamcity|unsupported|build/.test(lowerQuery) && control.id === "SA-22") score += 5;
    return { control, score };
  });

  scored.sort((a, b) => b.score - a.score || a.control.id.localeCompare(b.control.id));
  const best = scored[0]?.control || controls.find((control) => control.id === "SI-2");
  return {
    id: best.id,
    name: best.name,
    summary: summarizeControl(best),
    source: NIST_URL
  };
}

function summarizeControl(control) {
  const text = `${control.text} ${control.discussion}`.replace(/\s+/g, " ").trim();
  const firstSentence = text.split(/(?<=[.!?])\s+/).find((sentence) => sentence.length > 40) || text;
  return firstSentence.slice(0, 360).replace(/\s+\S*$/, "") + (firstSentence.length > 360 ? "..." : "");
}

function buildRiskSentence(risk) {
  const factors = [];
  if (boolYes(risk.asset.internet_exposed)) factors.push("internet-exposed");
  if (risk.asset.criticality === "Critical") factors.push("critical business asset");
  if (boolYes(risk.vulnerability.exploit_available)) factors.push("exploit available");
  if (risk.threatIntel) factors.push(`${risk.threatIntel.threat_actor} campaign match`);
  if (risk.threatIntel?.ransomware_association === "Yes") factors.push("ransomware-associated");
  if (!boolYes(risk.asset.edr_installed)) factors.push("no EDR");
  if (risk.kevEntry) factors.push("CISA KEV listed");

  return `Ranks here because ${factors.join(", ")} combine with ${risk.asset.business_service} business impact, making this more urgent than CVSS alone would show.`;
}

async function generateRiskReport({ refresh = false } = {}) {
  const data = await readDataPack();
  const references = await ensureReferences(refresh);
  const assetById = new Map(data.assets.map((asset) => [asset.asset_id, asset]));
  const serviceByName = new Map(data.businessServices.map((service) => [service.business_service, service]));
  const intelByCve = new Map(data.threatIntel.map((intel) => [intel.matched_cve_or_control, intel]));

  const risks = data.vulnerabilities
    .filter((vulnerability) => vulnerability.status === "Open")
    .map((vulnerability) => {
      const asset = assetById.get(vulnerability.asset_id) || {};
      const service = serviceByName.get(asset.business_service) || {};
      const threatIntel = intelByCve.get(vulnerability.cve);
      const kevEntry = references.kevByCve.get(vulnerability.cve);
      const cvss = Number(vulnerability.cvss);
      const score =
        cvss * 4 +
        (boolYes(asset.internet_exposed) || vulnerability.asset_exposure === "Internet" ? 18 : 0) +
        criticalityScore(asset) +
        serviceScore(service) +
        exploitScore(vulnerability, threatIntel, kevEntry) +
        missingControlScore(asset, vulnerability);

      return { vulnerability, asset, service, threatIntel, kevEntry, score: Number(score.toFixed(1)) };
    })
    .sort((a, b) => b.score - a.score);

  const topRisks = risks.slice(0, 5).map((risk, index) => {
    const hint = findRemediationHint(data.remediationHints, risk.vulnerability);
    const nistControl = retrieveNistControl(references.controls, risk, hint);
    return {
      rank: index + 1,
      score: risk.score,
      asset: {
        id: risk.asset.asset_id,
        name: risk.asset.asset_name,
        type: risk.asset.asset_type,
        owner: risk.asset.owner_team || "Unassigned",
        internetExposed: risk.asset.internet_exposed,
        criticality: risk.asset.criticality,
        edrInstalled: risk.asset.edr_installed,
        location: risk.asset.location
      },
      vulnerability: {
        id: risk.vulnerability.vuln_id,
        name: risk.vulnerability.vulnerability_name,
        cve: risk.vulnerability.cve,
        cvss: risk.vulnerability.cvss,
        exploitAvailable: risk.vulnerability.exploit_available,
        patchAvailable: risk.vulnerability.patch_available,
        daysOpen: risk.vulnerability.days_open,
        affectedComponent: risk.vulnerability.affected_component
      },
      threatIntel: risk.threatIntel
        ? {
            id: risk.threatIntel.intel_id,
            actor: risk.threatIntel.threat_actor,
            campaign: risk.threatIntel.campaign_name,
            ransomware: risk.threatIntel.ransomware_association,
            confidence: risk.threatIntel.confidence,
            summary: risk.threatIntel.summary
          }
        : null,
      cisaKev: risk.kevEntry
        ? {
            dateAdded: risk.kevEntry.dateAdded,
            ransomwareUse: risk.kevEntry.knownRansomwareCampaignUse,
            requiredAction: risk.kevEntry.requiredAction
          }
        : null,
      businessService: {
        name: risk.asset.business_service,
        owner: risk.service.business_owner,
        impact: risk.service.business_impact,
        complianceScope: risk.service.compliance_scope,
        revenueImpact: risk.service.revenue_impact,
        rtoHours: risk.service.rto_hours
      },
      why: buildRiskSentence(risk),
      remediation: {
        nistControl,
        operationalHint: hint
          ? {
              action: hint.recommended_action,
              validationEvidence: hint.validation_evidence
            }
          : null
      },
      evidence: {
        scoringFactors: {
          cvssWeighted: Number(risk.vulnerability.cvss) * 4,
          internetExposure: boolYes(risk.asset.internet_exposed) ? 18 : 0,
          assetCriticality: criticalityScore(risk.asset),
          businessService: serviceScore(risk.service),
          exploitAndThreat: exploitScore(risk.vulnerability, risk.threatIntel, risk.kevEntry),
          missingControlsAndAge: missingControlScore(risk.asset, risk.vulnerability)
        }
      }
    };
  });

  return {
    generatedAt: new Date().toISOString(),
    scenario: "TawasolPay cyber risk prioritization",
    topRisks,
    dataSummary: {
      assets: data.assets.length,
      vulnerabilities: data.vulnerabilities.length,
      threatIntel: data.threatIntel.length,
      businessServices: data.businessServices.length
    },
    referenceProvenance: references.provenance
  };
}

module.exports = { generateRiskReport, refreshReferences, NIST_URL, KEV_URL };
