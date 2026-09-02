# TawasolPay Cyber Risk Assistant

Working system for the HivePro AI Associate take-home assignment. It ingests the provided asset, vulnerability, threat intelligence, remediation hint, business service, and MDR advisory data, then produces a ranked top-5 cyber risk list with evidence and NIST SP 800-53 Rev. 5 remediation guidance.

## Run Locally

```bash
npm.cmd start
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

### Deploy to Railway (Recommended - Free, 1 Click)

1. Go to https://railway.app/new
2. Click "Deploy from GitHub"
3. Authorize Railway to access your GitHub account
4. Select the `hivepro-ai-associate` repository
5. Click "Deploy Now"
6. Wait ~2 minutes for the app to build and start
7. Railway will assign a public URL automatically (visible in the Railway dashboard)

Railway provides 500 free compute hours/month, which is more than enough for this deployment.

### Deploy to Render (Free Tier)

1. Go to https://dashboard.render.com/
2. Click "New +" → "Web Service"
3. Connect your GitHub account and select `hivepro-ai-associate`
4. Configure:
   - **Name**: `hivepro-ai-risk-assistant`
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
5. Click "Create Web Service"
6. Render will build and deploy automatically (watch the logs)

### Deploy to Fly.io

Requires Fly CLI (`brew install flyctl` or https://fly.io/docs/hands-on/install-flyctl/):

```bash
flyctl auth login
flyctl launch
flyctl deploy
```

### Local Development

For local development, `npm start` runs the server on port 3000. The dashboard fetches data from `/api/risks` which computes embeddings on startup (30-60 seconds first load), then serves subsequent requests in <2 seconds.

