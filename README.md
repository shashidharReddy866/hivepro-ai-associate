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

I retrieve NIST SP 800-53 as reference text because remediation controls are prose-heavy and the task asks for the applicable guidance, not a database join. The implementation downloads the official NIST CSV, narrows to relevant control candidates, and performs lightweight local retrieval over control names, text, and discussion fields; in a larger build I would swap this lexical retrieval for sentence-transformer embeddings while keeping the same provenance and traceability.

## Where It Can Go Wrong

1. If a CVE in `vulnerabilities.csv` is synthetic or absent from CISA KEV, the system will not flag it as CISA-known exploited even if the local threat report says it is active. I partially catch this by using local threat intelligence as a separate scoring signal and by showing whether the CISA match exists.

2. If the asset inventory has stale exposure or EDR fields, the ranking may understate or overstate urgency. I add a small stale-asset penalty through `last_seen_days`, but a production version should validate inventory freshness against scanner and EDR telemetry.

3. NIST control retrieval can select a broad control when several controls are relevant, such as choosing `SI-2` flaw remediation where `IR-4` incident handling also matters. I make the selected control visible with source provenance and keep scoring factors transparent so reviewers can spot weak guidance.

## One Thing I Would Improve

With another day, I would add an evaluation harness with expected top-risk fixtures and control-selection checks. That is the biggest gap because the ranking is deliberately explainable, but without regression tests it is too easy for a scoring tweak or retrieval change to silently alter the board-facing output.

## Deployment

The app is dependency-light and works on free Node hosts such as Render, Railway, Fly.io, or a small VM. Use `npm start` as the start command and expose port `3000` or the platform-provided `PORT`.
