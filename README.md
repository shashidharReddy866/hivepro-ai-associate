# TawasolPay Cyber Risk Assistant

Working system for the HivePro AI Associate take-home assignment. It ingests the provided asset, vulnerability, threat intelligence, remediation hint, business service, and MDR advisory data, then produces a ranked top-5 cyber risk list with evidence and NIST SP 800-53 Rev. 5 remediation guidance.

## 🚀 Deploy to Public URL (2 Minutes)

Click the button below to deploy to Railway with a public URL:

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template/jREfnB?referralCode=shashidhar)

Or deploy manually in 2 clicks:
1. Go to https://railway.app/new
2. Click **Deploy from GitHub**
3. Authorize Railway and select `hivepro-ai-associate` repository
4. Railway automatically assigns a public URL (check the Railway dashboard once deployment completes)

**Result**: App accessible at `https://<your-app-name>.up.railway.app` with live embeddings-based NIST retrieval.

---

## Run Locally

```bash
npm start
```

Open `http://localhost:3000`.

Optional CLI output:

```bash
npm.cmd run analyze
```

Refresh official reference data:

```bash
npm.cmd run refresh:references
```

## What It Does

The system joins vulnerabilities from `data/` to assets, business service context, local threat intelligence, and CISA KEV data. It scores each open vulnerability using CVSS plus internet exposure, exploit availability, direct campaign match, ransomware association, business criticality, compliance/revenue impact, EDR coverage, patch availability, and age. The dashboard shows the top five risks as readable entries with the asset, vulnerability, threat match, business service, explanation, evidence factors, and the retrieved NIST control.

Reference data is retrieved from:

- NIST SP 800-53 Rev. 5 controls CSV: `https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/NIST_SP-800-53_rev5_catalog_load.csv`
- CISA KEV JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

## Data Split

I query the CSV data as structured records because assets, vulnerabilities, services, and threat intel have stable keys and fields: `asset_id`, `business_service`, `cve`, exposure, CVSS, campaign name, and ransomware flags. Exact joins and weighted scoring are more reliable than embedding rows and hoping semantic retrieval preserves the relationships.

I retrieve NIST SP 800-53 as reference text using **sentence-transformer embeddings** (`Xenova/all-MiniLM-L6-v2`). At startup, the system computes embeddings for all NIST control descriptions and caches them. For each risk, it generates a query embedding from the vulnerability name, affected component, asset type, threat summary, and remediation hints, then ranks controls by cosine similarity to the query embedding. This semantic retrieval is what the assignment brief evaluates: controls are chosen based on semantic relevance to the risk context, not keyword matching.

The system maintains provenance and traceability: each NIST control includes the control ID, name, and a summary of its guidance text. If the embedding model is unavailable, it gracefully falls back to lightweight lexical token-overlap scoring with context-aware boosts for common patterns (ransomware → IR-4, missing EDR → RA-5, auth issues → AC-2, patching → SI-2).


## Where It Can Go Wrong

1. If a CVE in `vulnerabilities.csv` is synthetic or absent from CISA KEV, the system will not flag it as CISA-known exploited even if the local threat report says it is active. I partially catch this by using local threat intelligence as a separate scoring signal and by showing whether the CISA match exists.

2. If the asset inventory has stale exposure or EDR fields, the ranking may understate or overstate urgency. I add a small stale-asset penalty through `last_seen_days`, but a production version should validate inventory freshness against scanner and EDR telemetry.

3. NIST control retrieval can select a broad control when several controls are relevant, such as choosing `SI-2` flaw remediation where `IR-4` incident handling also matters. I make the selected control visible with source provenance and keep scoring factors transparent so reviewers can spot weak guidance.

## One Thing I Would Improve

The biggest gap is an evaluation harness with expected top-risk fixtures and control-selection checks. The ranking is deliberately explainable, but without regression tests it is too easy for a scoring tweak or embedding model change to silently alter the board-facing output. Cross-validating the top-5 list against known historical risks and expected NIST control selections would catch silent regressions.

## Architecture Decisions

**Semantic retrieval for NIST controls**: The brief specifically mentions that control retrieval is evaluated on the RAG architecture — distinguishing between structured CSV retrieval (assets, vulnerabilities, threat intel) and semantic document retrieval (NIST). This implementation uses sentence-transformer embeddings for NIST to capture semantic similarity between the risk context and control guidance. The fallback lexical mode is preserved for environments without model support, maintaining flexibility without sacrificing capability on well-resourced deployments.


## Deployment

**Repository**: https://github.com/shashidharReddy866/hivepro-ai-associate

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed step-by-step instructions for Railway, Render, or Fly.io.

**Quick Summary**:
- **Railway** (recommended): Go to https://railway.app/new → "Deploy from GitHub" → Select repo → Done (2 min)
- **Render**: Similar process, go to https://dashboard.render.com/
- **Fly.io**: Use CLI (`flyctl login` → `flyctl deploy`)

All platforms provide free tiers and automatic public URLs.

