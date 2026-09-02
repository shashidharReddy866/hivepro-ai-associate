const fs = require("node:fs/promises");
const path = require("node:path");

const { parseCsv } = require("./csv");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const ROOT = path.join(__dirname, "..");
const DATA_DIR = path.join(ROOT, "data");
const REFERENCE_DIR = path.join(ROOT, "references");

const NIST_CACHE = path.join(
  REFERENCE_DIR,
  "nist_sp800_53_controls.csv"
);

const KEV_CACHE = path.join(
  REFERENCE_DIR,
  "cisa_kev.json"
);

const NIST_URL =
  "https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/NIST_SP-800-53_rev5_catalog_load.csv";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/*
 * Semantic RAG can be disabled for constrained environments such as
 * Render Free while keeping the full semantic retrieval implementation
 * available in the codebase.
 *
 * Default: true
 *
 * Render:
 * SEMANTIC_RAG=false
 */
const SEMANTIC_RAG =
  String(process.env.SEMANTIC_RAG ?? "true").toLowerCase() !== "false";

// -----------------------------------------------------------------------------
// Gemini
// -----------------------------------------------------------------------------

let geminiModel = null;

async function getGeminiModel() {
  if (!geminiModel) {
    try {
      const apiKey = process.env.GEMINI_API_KEY;

      if (!apiKey) {
        console.warn(
          "GEMINI_API_KEY not set, falling back to template-based explanations"
        );

        return null;
      }

      const genAI = new GoogleGenerativeAI(apiKey);

      geminiModel = genAI.getGenerativeModel({
        model: "gemini-pro"
      });
    } catch (err) {
      console.error(
        "Failed to initialize Gemini model, falling back to templates:",
        err.message
      );

      geminiModel = false;
    }
  }

  return geminiModel || null;
}

// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------

function normalize(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function boolYes(value) {
  return normalize(value) === "yes";
}

function tokenSet(text) {
  return new Set(
    normalize(text)
      .replace(/[^a-z0-9-\s]/g, " ")
      .split(/\s+/)
      .filter((token) => token.length > 2)
  );
}

// -----------------------------------------------------------------------------
// Risk explanations
// -----------------------------------------------------------------------------

function buildRiskFactors(risk) {
  const factors = [];

  if (boolYes(risk.asset.internet_exposed)) {
    factors.push("internet-exposed");
  }

  if (risk.asset.criticality === "Critical") {
    factors.push("critical business asset");
  }

  if (boolYes(risk.vulnerability.exploit_available)) {
    factors.push("exploit available");
  }

  if (risk.threatIntel) {
    factors.push(
      `${risk.threatIntel.threat_actor} campaign match`
    );
  }

  if (
    risk.threatIntel?.ransomware_association === "Yes"
  ) {
    factors.push("ransomware-associated");
  }

  if (!boolYes(risk.asset.edr_installed)) {
    factors.push("no EDR");
  }

  if (risk.kevEntry) {
    factors.push("CISA KEV listed");
  }

  return factors;
}

async function generateRiskExplanation(risk, hint) {
  const model = await getGeminiModel();

  if (!model) {
    const factors = buildRiskFactors(risk);

    return `Ranks here because ${factors.join(
      ", "
    )} combine with ${risk.asset.business_service} business impact, making this more urgent than CVSS alone would show.`;
  }

  try {
    const prompt = `
You are a cybersecurity risk analyst.

Generate a concise 1-2 sentence explanation for why this cyber risk ranks high in priority.

Use ONLY the evidence provided below.

Do not invent CVEs, threat actors, campaigns, controls, or other facts.

Risk Details:
- Vulnerability: ${risk.vulnerability.vulnerability_name} (${risk.vulnerability.cve}, CVSS ${risk.vulnerability.cvss})
- Asset: ${risk.asset.asset_name} (${risk.asset.asset_type}, criticality: ${risk.asset.criticality})
- Business Service: ${risk.asset.business_service}
- Internet Exposed: ${risk.asset.internet_exposed}
- EDR Installed: ${risk.asset.edr_installed}
- Exploit Available: ${risk.vulnerability.exploit_available}
- Patch Available: ${risk.vulnerability.patch_available}
- Days Open: ${risk.vulnerability.days_open}
${
  risk.threatIntel
    ? `- Threat Actor: ${risk.threatIntel.threat_actor} (Campaign: ${risk.threatIntel.campaign_name}, Ransomware: ${risk.threatIntel.ransomware_association})`
    : ""
}
${
  risk.kevEntry
    ? "- This CVE is in CISA's KEV (Known Exploited Vulnerabilities) catalog"
    : ""
}
${
  hint
    ? `- Recommended Action: ${hint.recommended_action}`
    : ""
}

Provide only the explanation, no preamble.
`.trim();

    const result = await model.generateContent(prompt);
    const explanation = result.response.text().trim();

    return (
      explanation.slice(0, 360) +
      (explanation.length > 360 ? "..." : "")
    );
  } catch (err) {
    console.error(
      "Gemini risk explanation generation failed, using fallback:",
      err.message
    );

    const factors = buildRiskFactors(risk);

    return `Ranks here because ${factors.join(
      ", "
    )} combine with ${risk.asset.business_service} business impact, making this more urgent than CVSS alone would show.`;
  }
}

// -----------------------------------------------------------------------------
// NIST control summaries
// -----------------------------------------------------------------------------

async function generateNistControlSummary(control) {
  if (!control) {
    return "NIST SP 800-53 remediation control could not be determined.";
  }

  const model = await getGeminiModel();

  const basicSummary = () => {
    const text = `${control.text} ${control.discussion}`
      .replace(/\s+/g, " ")
      .trim();

    const firstSentence =
      text
        .split(/(?<=[.!?])\s+/)
        .find((sentence) => sentence.length > 40) || text;

    const trimmed = firstSentence
      .slice(0, 360)
      .replace(/\s+\S*$/, "");

    return (
      trimmed +
      (firstSentence.length > 360 ? "..." : "")
    );
  };

  if (!model) {
    return basicSummary();
  }

  try {
    const prompt = `
You are a NIST SP 800-53 cybersecurity controls expert.

Summarize this control in 1-2 sentences focusing on what it does and why it matters.

Control: ${control.id} - ${control.name}
Text: ${control.text}
Discussion: ${control.discussion}

Provide only the summary, no preamble.
`.trim();

    const result = await model.generateContent(prompt);
    const summary = result.response.text().trim();

    return (
      summary.slice(0, 360) +
      (summary.length > 360 ? "..." : "")
    );
  } catch (err) {
    console.error(
      "Gemini control summary generation failed, using fallback:",
      err.message
    );

    return basicSummary();
  }
}

// -----------------------------------------------------------------------------
// Embedding model
// -----------------------------------------------------------------------------

let embeddingModel = null;

async function getEmbeddingModel() {
  if (!SEMANTIC_RAG) {
    return null;
  }

  if (!embeddingModel) {
    try {
      const { pipeline } = await import(
        "@xenova/transformers"
      );

      embeddingModel = await pipeline(
        "feature-extraction",
        "Xenova/all-MiniLM-L6-v2"
      );
    } catch (err) {
      console.error(
        "Failed to load embedding model, falling back to lexical retrieval:",
        err.message
      );

      embeddingModel = null;
    }
  }

  return embeddingModel;
}

async function getEmbedding(text) {
  if (!SEMANTIC_RAG) {
    return null;
  }

  const model = await getEmbeddingModel();

  if (!model) {
    return null;
  }

  try {
    const output = await model(text, {
      pooling: "mean",
      normalize: true
    });

    return Array.from(output.data);
  } catch (err) {
    console.error(
      "Embedding generation failed:",
      err.message
    );

    return null;
  }
}

function cosineSimilarity(vecA, vecB) {
  if (
    !vecA ||
    !vecB ||
    vecA.length !== vecB.length
  ) {
    return 0;
  }

  let dotProduct = 0;

  for (let i = 0; i < vecA.length; i += 1) {
    dotProduct += vecA[i] * vecB[i];
  }

  return dotProduct;
}

// -----------------------------------------------------------------------------
// Data loading
// -----------------------------------------------------------------------------

async function readCsv(fileName) {
  return parseCsv(
    await fs.readFile(
      path.join(DATA_DIR, fileName),
      "utf8"
    )
  );
}

async function readDataPack() {
  const [
    assets,
    vulnerabilities,
    threatIntel,
    businessServices,
    remediationHints,
    threatReport
  ] = await Promise.all([
    readCsv("assets.csv"),
    readCsv("vulnerabilities.csv"),
    readCsv("threat_intelligence.csv"),
    readCsv("business_services.csv"),
    readCsv("remediation_guidance.csv"),
    fs.readFile(
      path.join(
        DATA_DIR,
        "synthetic_threat_report.md"
      ),
      "utf8"
    )
  ]);

  return {
    assets,
    vulnerabilities,
    threatIntel,
    businessServices,
    remediationHints,
    threatReport
  };
}

// -----------------------------------------------------------------------------
// External reference data
// -----------------------------------------------------------------------------

async function fetchText(url) {
  const response = await fetch(url, {
    headers: {
      "user-agent":
        "hivepro-assignment-risk-assistant/1.0"
    }
  });

  if (!response.ok) {
    throw new Error(
      `Failed to retrieve ${url}: HTTP ${response.status}`
    );
  }

  return response.text();
}

async function refreshReferences() {
  await fs.mkdir(REFERENCE_DIR, {
    recursive: true
  });

  const [nistCsv, kevJson] = await Promise.all([
    fetchText(NIST_URL),
    fetchText(KEV_URL)
  ]);

  await Promise.all([
    fs.writeFile(NIST_CACHE, nistCsv),
    fs.writeFile(KEV_CACHE, kevJson)
  ]);

  return {
    nist: {
      source: NIST_URL,
      bytes: Buffer.byteLength(nistCsv)
    },

    cisaKev: {
      source: KEV_URL,
      bytes: Buffer.byteLength(kevJson)
    }
  };
}

let cachedReferences = null;
let cachedNistCsv = null;
let cachedKevJson = null;

async function ensureReferences(refresh = false) {
  try {
    if (refresh) {
      throw new Error("refresh requested");
    }

    const [nistCsv, kevJson] = await Promise.all([
      fs.readFile(NIST_CACHE, "utf8"),
      fs.readFile(KEV_CACHE, "utf8")
    ]);

    if (
      cachedReferences &&
      cachedNistCsv === nistCsv &&
      cachedKevJson === kevJson
    ) {
      return cachedReferences;
    }

    const references = await parseReferences(
      nistCsv,
      kevJson,
      false
    );

    cachedReferences = references;
    cachedNistCsv = nistCsv;
    cachedKevJson = kevJson;

    return references;
  } catch (_) {
    const result = await refreshReferences();

    const [nistCsv, kevJson] = await Promise.all([
      fs.readFile(NIST_CACHE, "utf8"),
      fs.readFile(KEV_CACHE, "utf8")
    ]);

    const references = {
      ...(await parseReferences(
        nistCsv,
        kevJson,
        true
      )),
      refreshResult: result
    };

    cachedReferences = references;
    cachedNistCsv = nistCsv;
    cachedKevJson = kevJson;

    return references;
  }
}

async function parseReferences(
  nistCsv,
  kevJson,
  refreshed
) {
  const controls = parseCsv(nistCsv).map(
    (control) => ({
      id: control.identifier,
      name: control.name,
      text: control.control_text || "",
      discussion: control.discussion || "",
      related: control.related || "",
      embedding: null
    })
  );

  let model = null;

  /*
   * Only compute all NIST embeddings when semantic
   * RAG is explicitly enabled.
   *
   * This is the key Render Free optimization.
   */
  if (SEMANTIC_RAG) {
    model = await getEmbeddingModel();

    if (model) {
      /*
       * Avoid starting an embedding model when it is
       * not available. Each control keeps a cached
       * embedding in memory for semantic retrieval.
       */
      await Promise.all(
        controls.map(async (control) => {
          const controlText = [
            control.id,
            control.name,
            control.text,
            control.discussion
          ]
            .filter(Boolean)
            .join(" ");

          control.embedding =
            await getEmbedding(controlText);
        })
      );
    }
  }

  const kev = JSON.parse(kevJson);

  const kevByCve = new Map(
    (kev.vulnerabilities || []).map(
      (item) => [
        item.cveID,
        item
      ]
    )
  );

  return {
    controls,
    kevByCve,

    provenance: {
      nistUrl: NIST_URL,
      kevUrl: KEV_URL,
      refreshed,

      retrievalMethod:
        model && SEMANTIC_RAG
          ? "embeddings"
          : "lexical",

      kevCatalogVersion:
        kev.catalogVersion,

      kevDateReleased:
        kev.dateReleased,

      kevCount: kev.count
    }
  };
}

// -----------------------------------------------------------------------------
// Risk scoring
// -----------------------------------------------------------------------------

function serviceScore(service) {
  let score = 0;

  if (!service) {
    return score;
  }

  if (service.risk_appetite === "Very Low") {
    score += 12;
  }

  if (service.risk_appetite === "Low") {
    score += 7;
  }

  if (service.revenue_impact === "Critical") {
    score += 12;
  }

  if (service.revenue_impact === "High") {
    score += 8;
  }

  if (boolYes(service.customer_facing)) {
    score += 6;
  }

  if (Number(service.rto_hours) <= 1) {
    score += 6;
  }

  if (service.compliance_scope) {
    score += service.compliance_scope.includes(
      "PCI"
    )
      ? 8
      : 4;
  }

  return score;
}

function criticalityScore(asset) {
  if (asset.criticality === "Critical") {
    return 12;
  }

  if (asset.criticality === "High") {
    return 8;
  }

  if (asset.criticality === "Medium") {
    return 4;
  }

  return 1;
}

function exploitScore(
  vulnerability,
  intel,
  kevEntry
) {
  let score = 0;

  if (
    boolYes(
      vulnerability.exploit_available
    )
  ) {
    score += 16;
  }

  if (
    normalize(vulnerability.auth_required) ===
    "no"
  ) {
    score += 6;
  }

  if (
    intel?.exploit_maturity === "Weaponized"
  ) {
    score += 16;
  }

  if (
    intel?.ransomware_association === "Yes"
  ) {
    score += 14;
  }

  if (kevEntry) {
    score += 10;
  }

  if (
    kevEntry?.knownRansomwareCampaignUse ===
    "Known"
  ) {
    score += 12;
  }

  return score;
}

function missingControlScore(
  asset,
  vulnerability
) {
  let score = 0;

  if (!boolYes(asset.edr_installed)) {
    score += 12;
  }

  if (Number(asset.last_seen_days) > 14) {
    score += 4;
  }

  if (
    !boolYes(vulnerability.patch_available)
  ) {
    score += 4;
  }

  if (Number(vulnerability.days_open) > 30) {
    score += 4;
  }

  if (Number(vulnerability.days_open) > 90) {
    score += 3;
  }

  return score;
}

// -----------------------------------------------------------------------------
// Remediation hint lookup
// -----------------------------------------------------------------------------

function findRemediationHint(
  remediationHints,
  vulnerability
) {
  const haystack = normalize(
    `${vulnerability.vulnerability_name} ${vulnerability.affected_component}`
  );

  let best = null;
  let bestScore = 0;

  for (const hint of remediationHints) {
    const words = normalize(
      hint.finding_type
    )
      .split(/\s+/)
      .filter(
        (word) => word.length > 3
      );

    const score = words.reduce(
      (total, word) =>
        total +
        (haystack.includes(word) ? 1 : 0),
      0
    );

    if (score > bestScore) {
      best = hint;
      bestScore = score;
    }
  }

  return best;
}

// -----------------------------------------------------------------------------
// NIST retrieval
// -----------------------------------------------------------------------------

async function retrieveNistControl(
  controls,
  risk,
  hint
) {
  const query = [
    risk.vulnerability.vulnerability_name,
    risk.vulnerability.affected_component,
    risk.asset.asset_type,
    risk.threatIntel?.summary,
    hint?.recommended_action
  ]
    .filter(Boolean)
    .join(" ");

  let queryEmbedding = null;

  /*
   * Semantic retrieval is enabled only when requested.
   * On Render Free this is disabled through:
   *
   * SEMANTIC_RAG=false
   */
  if (SEMANTIC_RAG) {
    queryEmbedding =
      await getEmbedding(query);
  }

  let best = null;
  let bestScore = -Infinity;

  // ---------------------------------------------------------------------------
  // Semantic retrieval
  // ---------------------------------------------------------------------------

  if (queryEmbedding) {
    for (const control of controls) {
      if (!control.embedding) {
        continue;
      }

      const similarity =
        cosineSimilarity(
          queryEmbedding,
          control.embedding
        );

      if (similarity > bestScore) {
        bestScore = similarity;
        best = control;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Lexical/context-aware fallback
  // ---------------------------------------------------------------------------

  if (!best || bestScore < 0.3) {
    const lowerQuery = normalize(query);
    const queryTokens = tokenSet(query);

    let lexicalBest = null;
    let lexicalBestScore = 0;

    for (const control of controls) {
      const controlTokens = tokenSet(
        `${control.id} ${control.name} ${control.text} ${control.discussion}`
      );

      let score = 0;

      for (const token of queryTokens) {
        if (controlTokens.has(token)) {
          score += 1;
        }
      }

      // Ransomware response
      if (
        risk.threatIntel
          ?.ransomware_association ===
          "Yes" &&
        control.id === "IR-4"
      ) {
        score += 6;
      }

      // Missing EDR / assessment
      if (
        !boolYes(
          risk.asset.edr_installed
        ) &&
        control.id === "RA-5"
      ) {
        score += 3;
      }

      // Identity/authentication
      if (
        /auth|account|credential|token|mfa/.test(
          lowerQuery
        ) &&
        control.id === "AC-2"
      ) {
        score += 5;
      }

      // Vulnerability/patching
      if (
        /patch|rce|cve|vulnerability|flaw/.test(
          lowerQuery
        ) &&
        control.id === "SI-2"
      ) {
        score += 5;
      }

      // Unsupported/build components
      if (
        /jenkins|teamcity|unsupported|build/.test(
          lowerQuery
        ) &&
        control.id === "SA-22"
      ) {
        score += 5;
      }

      if (score > lexicalBestScore) {
        lexicalBestScore = score;
        lexicalBest = control;
      }
    }

    best =
      lexicalBest ||
      controls.find(
        (control) =>
          control.id === "SI-2"
      );
  }

  /*
   * Defensive fallback in case the source catalog
   * cannot provide a matching control.
   */
  if (!best) {
    throw new Error(
      "No NIST SP 800-53 controls available for retrieval."
    );
  }

  const summary =
    await generateNistControlSummary(
      best
    );

  return {
    id: best.id,
    name: best.name,
    summary,
    source: NIST_URL,

    retrievalMethod:
      queryEmbedding &&
      bestScore >= 0.3
        ? "embeddings"
        : "lexical"
  };
}

// -----------------------------------------------------------------------------
// Human-readable risk sentence
// -----------------------------------------------------------------------------

function buildRiskSentence(risk) {
  const factors = buildRiskFactors(risk);

  return `Ranks here because ${factors.join(
    ", "
  )} combine with ${risk.asset.business_service} business impact, making this more urgent than CVSS alone would show.`;
}

// -----------------------------------------------------------------------------
// Risk report
// -----------------------------------------------------------------------------

async function generateRiskReport(
  { refresh = false } = {}
) {
  const data = await readDataPack();

  const references =
    await ensureReferences(refresh);

  const assetById = new Map(
    data.assets.map((asset) => [
      asset.asset_id,
      asset
    ])
  );

  const serviceByName = new Map(
    data.businessServices.map(
      (service) => [
        service.business_service,
        service
      ]
    )
  );

  const intelByCve = new Map(
    data.threatIntel.map(
      (intel) => [
        intel.matched_cve_or_control,
        intel
      ]
    )
  );

  const risks = data.vulnerabilities
    .filter(
      (vulnerability) =>
        vulnerability.status === "Open"
    )
    .map((vulnerability) => {
      const asset =
        assetById.get(
          vulnerability.asset_id
        ) || {};

      const service =
        serviceByName.get(
          asset.business_service
        ) || {};

      const threatIntel =
        intelByCve.get(
          vulnerability.cve
        );

      const kevEntry =
        references.kevByCve.get(
          vulnerability.cve
        );

      const cvss =
        Number(vulnerability.cvss);

      /*
       * Contextual risk scoring:
       * CVSS + internet exposure + asset criticality
       * + business service impact + exploit/threat intel
       * + compensating control gaps + age.
       */
      const rawScore =
        cvss * 4 +
        (
          boolYes(
            asset.internet_exposed
          ) ||
          vulnerability.asset_exposure ===
            "Internet"
            ? 18
            : 0
        ) +
        criticalityScore(asset) +
        serviceScore(service) +
        exploitScore(
          vulnerability,
          threatIntel,
          kevEntry
        ) +
        missingControlScore(
          asset,
          vulnerability
        );

      /*
       * Normalize to 0-100 for the dashboard.
       *
       * Keeping rawScore as evidence makes the scoring
       * calculation auditable.
       */
      const MAX_RISK_SCORE = 215;

      const score = Math.min(
        100,
        (rawScore / MAX_RISK_SCORE) * 100
      );

      return {
        vulnerability,
        asset,
        service,
        threatIntel,
        kevEntry,

        rawScore: Number(
          rawScore.toFixed(1)
        ),

        score: Number(
          score.toFixed(1)
        )
      };
    })
    .sort(
      (a, b) =>
        b.score - a.score
    );

  // ---------------------------------------------------------------------------
  // Build Top 5
  // ---------------------------------------------------------------------------

  const topRisks =
    await Promise.all(
      risks.slice(0, 5).map(
        async (risk, index) => {
          const hint =
            findRemediationHint(
              data.remediationHints,
              risk.vulnerability
            );

          const nistControl =
            await retrieveNistControl(
              references.controls,
              risk,
              hint
            );

          return {
            rank: index + 1,

            score: risk.score,

            rawScore: risk.rawScore,

            // -----------------------------------------------------------------
            // Asset evidence
            // -----------------------------------------------------------------

            asset: {
              id: risk.asset.asset_id,

              name:
                risk.asset.asset_name,

              type:
                risk.asset.asset_type,

              owner:
                risk.asset.owner_team ||
                "Unassigned",

              internetExposed:
                risk.asset.internet_exposed,

              criticality:
                risk.asset.criticality,

              edrInstalled:
                risk.asset.edr_installed,

              location:
                risk.asset.location
            },

            // -----------------------------------------------------------------
            // Vulnerability evidence
            // -----------------------------------------------------------------

            vulnerability: {
              id:
                risk.vulnerability.vuln_id,

              name:
                risk.vulnerability
                  .vulnerability_name,

              cve:
                risk.vulnerability.cve,

              cvss:
                risk.vulnerability.cvss,

              exploitAvailable:
                risk.vulnerability
                  .exploit_available,

              patchAvailable:
                risk.vulnerability
                  .patch_available,

              daysOpen:
                risk.vulnerability
                  .days_open,

              affectedComponent:
                risk.vulnerability
                  .affected_component
            },

            // -----------------------------------------------------------------
            // Threat intelligence evidence
            // -----------------------------------------------------------------

            threatIntel:
              risk.threatIntel
                ? {
                    id:
                      risk.threatIntel
                        .intel_id,

                    actor:
                      risk.threatIntel
                        .threat_actor,

                    campaign:
                      risk.threatIntel
                        .campaign_name,

                    ransomware:
                      risk.threatIntel
                        .ransomware_association,

                    confidence:
                      risk.threatIntel
                        .confidence,

                    summary:
                      risk.threatIntel
                        .summary
                  }
                : null,

            // -----------------------------------------------------------------
            // CISA KEV evidence
            // -----------------------------------------------------------------

            cisaKev:
              risk.kevEntry
                ? {
                    dateAdded:
                      risk.kevEntry
                        .dateAdded,

                    ransomwareUse:
                      risk.kevEntry
                        .knownRansomwareCampaignUse,

                    requiredAction:
                      risk.kevEntry
                        .requiredAction
                  }
                : null,

            // -----------------------------------------------------------------
            // Business impact evidence
            // -----------------------------------------------------------------

            businessService: {
              name:
                risk.asset
                  .business_service,

              owner:
                risk.service
                  .business_owner,

              impact:
                risk.service
                  .business_impact,

              complianceScope:
                risk.service
                  .compliance_scope,

              revenueImpact:
                risk.service
                  .revenue_impact,

              rtoHours:
                risk.service
                  .rto_hours
            },

            // -----------------------------------------------------------------
            // Human-readable explanation
            // -----------------------------------------------------------------

            why:
              await generateRiskExplanation(
                risk,
                hint
              ),

            // -----------------------------------------------------------------
            // Remediation
            // -----------------------------------------------------------------

            remediation: {
              nistControl,

              operationalHint:
                hint
                  ? {
                      action:
                        hint.recommended_action,

                      validationEvidence:
                        hint.validation_evidence
                    }
                  : null
            },

            // -----------------------------------------------------------------
            // Transparent scoring evidence
            // -----------------------------------------------------------------

            evidence: {
              rawRiskScore:
                risk.rawScore,

              normalizedRiskScore:
                risk.score,

              scoringFactors: {
                cvssWeighted:
                  Number(
                    risk.vulnerability
                      .cvss
                  ) * 4,

                internetExposure:
                  boolYes(
                    risk.asset
                      .internet_exposed
                  )
                    ? 18
                    : 0,

                assetCriticality:
                  criticalityScore(
                    risk.asset
                  ),

                businessService:
                  serviceScore(
                    risk.service
                  ),

                exploitAndThreat:
                  exploitScore(
                    risk.vulnerability,
                    risk.threatIntel,
                    risk.kevEntry
                  ),

                missingControlsAndAge:
                  missingControlScore(
                    risk.asset,
                    risk.vulnerability
                  )
              }
            }
          };
        }
      )
    );

  // ---------------------------------------------------------------------------
  // Final report
  // ---------------------------------------------------------------------------

  return {
    generatedAt:
      new Date().toISOString(),

    scenario:
      "TawasolPay cyber risk prioritization",

    topRisks,

    dataSummary: {
      assets:
        data.assets.length,

      vulnerabilities:
        data.vulnerabilities.length,

      threatIntel:
        data.threatIntel.length,

      businessServices:
        data.businessServices.length
    },

    referenceProvenance:
      {
        ...references.provenance,

        semanticRagEnabled:
          SEMANTIC_RAG
      }
  };
}

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

module.exports = {
  generateRiskReport,
  refreshReferences,
  getEmbeddingModel,
  NIST_URL,
  KEV_URL
};