# TawasolPay Cyber Risk Assistant

A contextual cyber-risk prioritization system that identifies the **Top 5 vulnerabilities requiring the most urgent attention** by combining technical severity, threat intelligence, asset exposure, business criticality, compensating controls, exploit activity, and authoritative security references.

**Live Demo:** https://hivepro-ai-associate.onrender.com  
**Repository:** https://github.com/shashidharReddy866/hivepro-ai-associate

---

## Overview

Traditional vulnerability prioritization often over-relies on CVSS severity. This project takes a broader approach: a vulnerability becomes more urgent when it is combined with factors such as:

- Internet exposure
- Confirmed exploit availability
- Weaponization and active threat campaigns
- Ransomware association
- CISA Known Exploited Vulnerabilities (KEV) coverage
- Asset criticality
- Business-service impact
- Compliance scope and revenue impact
- Missing endpoint protection / compensating controls
- Vulnerability age and patch availability

The result is a transparent, evidence-driven Top 5 risk view intended to help a security team decide **what to remediate first and why**.

---

## What the Application Provides

### 1. Contextual Top 5 Risk Prioritization

The application evaluates open vulnerabilities and produces a ranked Top 5 list.

Each result includes:

- Risk rank
- Normalized score (0–100)
- Raw score
- Affected asset
- CVE and CVSS
- Exploit and patch status
- Threat actor and campaign evidence
- Ransomware association
- CISA KEV evidence
- Business-service impact
- NIST SP 800-53 remediation guidance
- Operational remediation guidance
- Transparent scoring factors

### 2. Evidence-Based Explanations

The application explains why a risk ranks highly using the evidence available in the data rather than treating CVSS as the only signal.

Example factors include:

> Internet exposed + exploit available + ransomware campaign + no EDR + CISA KEV + critical business impact

### 3. NIST SP 800-53 Remediation Mapping

Each prioritized risk is mapped to a NIST SP 800-53 Rev. 5 control.

The system supports:

- Semantic retrieval using sentence-transformer embeddings
- Lexical/context-aware fallback retrieval
- Context-specific boosts for scenarios such as ransomware response, vulnerability remediation, identity risks, and unsupported software
- Source provenance back to the NIST catalog

### 4. CISA KEV Enrichment

CVE records are cross-referenced against the CISA Known Exploited Vulnerabilities catalog.

When a match exists, the dashboard surfaces:

- Date added
- Known ransomware campaign use
- Required action

### 5. Optional Generative AI

Google Gemini can be enabled for concise, human-readable risk explanations and NIST control summaries.

The application also works without an API key by using deterministic fallback explanations.

---

# Architecture

```text
                   ┌─────────────────────────────┐
                   │       Input Data Pack        │
                   │                             │
                   │ assets.csv                   │
                   │ vulnerabilities.csv         │
                   │ threat_intelligence.csv     │
                   │ business_services.csv       │
                   │ remediation_guidance.csv    │
                   │ synthetic_threat_report.md  │
                   └──────────────┬──────────────┘
                                  │
                                  ▼
                   ┌─────────────────────────────┐
                   │       Risk Engine            │
                   │                             │
                   │ Asset / vulnerability joins │
                   │ Contextual scoring           │
                   │ Threat intelligence          │
                   │ Business impact              │
                   │ Control-gap analysis         │
                   └──────────────┬──────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
          ┌───────────────────┐       ┌────────────────────┐
          │ CISA KEV          │       │ NIST SP 800-53     │
          │ CVE enrichment    │       │ control retrieval  │
          └─────────┬─────────┘       └─────────┬──────────┘
                    │                           │
                    └─────────────┬─────────────┘
                                  ▼
                   ┌─────────────────────────────┐
                   │       Top 5 Risk Report      │
                   │                             │
                   │ Score + evidence + rationale │
                   │ Threat context               │
                   │ Business impact              │
                   │ NIST remediation             │
                   └──────────────┬──────────────┘
                                  │
                                  ▼
                   ┌─────────────────────────────┐
                   │       Web Dashboard          │
                   │        Node.js + HTTP        │
                   └─────────────────────────────┘
```

---

# Data Sources

The application ingests the complete assignment data pack:

| Source | Purpose |
|---|---|
| `assets.csv` | Asset identity, type, ownership, exposure, criticality, EDR status, location |
| `vulnerabilities.csv` | CVE, CVSS, exploitability, patch status, affected component, age |
| `threat_intelligence.csv` | Threat actors, campaigns, exploit maturity, ransomware association, confidence |
| `business_services.csv` | Business criticality, revenue impact, customer-facing status, RTO, compliance scope |
| `remediation_guidance.csv` | Operational remediation actions and validation evidence |
| `synthetic_threat_report.md` | Scenario-level threat context |

The application also uses authoritative external references:

- **NIST SP 800-53 Rev. 5 catalog**
- **CISA Known Exploited Vulnerabilities (KEV) catalog**

Reference data is cached under `/references` and can be refreshed from their official sources.

---

# Risk Scoring Methodology

The scoring model is intentionally transparent and deterministic.

For each open vulnerability:

```text
Raw Risk Score =
    CVSS weighted severity
  + Internet exposure
  + Asset criticality
  + Business-service impact
  + Exploit / threat intelligence
  + Missing controls / vulnerability age
```

The resulting raw score is normalized to a **0–100 dashboard score**.

## Contextual Signals

### Technical severity

CVSS contributes to the baseline severity but does not determine the final ranking by itself.

### Exposure

Internet-facing assets receive additional risk weighting because exploitable weaknesses are more directly reachable.

### Asset criticality

Critical and high-value assets receive additional weight.

### Business impact

Business-service attributes such as:

- Revenue impact
- Customer-facing status
- Recovery time objective
- Compliance scope
- Risk appetite

increase the priority of vulnerabilities that could materially affect the organization.

### Exploit and threat signals

The model increases priority for:

- Confirmed exploit availability
- Weaponized exploitation
- Threat-actor campaign matches
- Ransomware association
- CISA KEV inclusion
- Known ransomware campaign use in CISA KEV

### Compensating-control gaps and age

Risk increases when:

- EDR is absent
- Assets have not been recently observed
- A patch is unavailable
- Vulnerabilities have remained open for extended periods

The dashboard exposes these scoring components so the ranking remains auditable.

---

# NIST Retrieval / RAG Design

The repository contains a semantic retrieval implementation using:

**`Xenova/all-MiniLM-L6-v2`**

The retrieval query is constructed from risk context such as:

- Vulnerability name
- Affected component
- Asset type
- Threat-intelligence summary
- Operational remediation hint

The system then compares the query representation with NIST control representations using cosine similarity.

When semantic retrieval is unavailable or deliberately disabled, the application falls back to a **lexical/context-aware retrieval strategy** with explicit contextual boosts.

### Production deployment note

The public Render Free deployment uses:

```text
SEMANTIC_RAG=false
```

This prevents the resource-intensive transformer model from consuming the constrained free runtime during live requests.

The semantic RAG implementation remains part of the application and can be enabled with:

```text
SEMANTIC_RAG=true
```

This deployment decision is intentional: it preserves the RAG capability in the codebase while keeping the public demonstration responsive and reliable on the constrained hosting tier.

---

# AI / Gemini Integration

Gemini is optional.

Without `GEMINI_API_KEY`, the application uses deterministic, template-based explanations.

With the API key configured, Gemini can generate:

- Concise risk-priority narratives
- NIST control summaries

Prompts instruct the model to use **only the evidence supplied by the risk engine**, reducing the likelihood of unsupported claims.

Example environment variable:

```text
GEMINI_API_KEY=your_api_key
```

---

# Quick Start

## Requirements

- Node.js
- npm

## Install

```bash
npm install
```

## Run

```bash
npm start
```

Then open:

```text
http://localhost:3000
```

## Run the analysis from the CLI

```bash
npm run analyze
```

## Run tests

```bash
npm test
```

## Refresh reference data

```bash
npm run refresh:references
```

---

# Public Deployment — Render

The current public deployment uses **Render**.

## Render Configuration

Typical settings:

```text
Service Type: Web Service
Runtime: Node
Branch: main
Start Command: npm start
```

The application listens on the environment-provided `PORT` and binds to `0.0.0.0`.

### Required production setting for the free deployment

```text
SEMANTIC_RAG=false
```

### Optional

```text
GEMINI_API_KEY=your_api_key
```

### Health endpoint

```text
GET /health
```

Expected response:

```json
{
  "status": "ok",
  "service": "tawasolpay-cyber-risk-assistant"
}
```

### Risk API

```text
GET /api/risks
```

The endpoint returns the complete prioritized risk report consumed by the dashboard.

### Reference refresh endpoint

```text
POST /api/references/refresh
```

This refreshes the NIST and CISA KEV reference caches.

---

# Project Structure

```text
hivepro-ai-associate/
├── data/
│   ├── assets.csv
│   ├── vulnerabilities.csv
│   ├── threat_intelligence.csv
│   ├── business_services.csv
│   ├── remediation_guidance.csv
│   └── synthetic_threat_report.md
│
├── references/
│   ├── nist_sp800_53_controls.csv
│   └── cisa_kev.json
│
├── public/
│   ├── index.html
│   ├── app.js
│   └── styles.css
│
├── src/
│   ├── csv.js
│   ├── cli.js
│   └── riskEngine.js
│
├── tests/
│   └── riskEngine.test.js
│
├── server.js
├── DEPLOYMENT.md
├── package.json
└── README.md
```

---

# Technology Stack

| Area | Technology |
|---|---|
| Runtime | Node.js |
| HTTP server | Node.js built-in `http` module |
| Frontend | HTML, CSS, vanilla JavaScript |
| Risk engine | JavaScript |
| Semantic retrieval | `@xenova/transformers` / `Xenova/all-MiniLM-L6-v2` |
| Generative AI | Google Gemini API (optional) |
| Reference data | NIST SP 800-53 + CISA KEV |
| Data format | CSV + JSON + Markdown |
| Testing | Node.js test runner / assertions |
| Deployment | Render Web Service |

The implementation intentionally avoids an unnecessary frontend framework or heavyweight backend framework for this assignment.

---

# API Endpoints

## Health

```text
GET /health
```

Used for service health monitoring.

## Risk Report

```text
GET /api/risks
```

Returns:

- Top 5 risks
- Asset context
- Vulnerability context
- Threat intelligence
- CISA KEV evidence
- Business-service context
- NIST remediation
- Scoring evidence
- Reference provenance

## Refresh References

```text
POST /api/references/refresh
```

Refreshes the cached NIST and CISA KEV reference data.

---

# Testing and Validation

The project includes automated tests covering core behavior such as:

- CSV parsing
- Data ingestion counts
- Top 5 generation
- Risk ordering
- Score normalization
- Ransomware-related prioritization
- NIST control presence
- NIST source provenance

Run:

```bash
npm test
```

Expected result:

```text
All tests passed
```

---

# README Questions from the Assignment

## 1. What data would you keep structured vs embedded, and why?

### Structured data

I would keep the following structured:

- Asset inventory
- Vulnerability/CVE records
- CVSS and exploitability attributes
- Business-service metadata
- Threat-intelligence indicators
- CISA KEV matches
- Remediation actions
- Risk scores and scoring factors

These fields are well suited to deterministic joins, filtering, aggregation, validation, reporting, and auditing.

### Embedded data

I would embed:

- Long-form threat reports
- Security advisories
- NIST control descriptions and discussions
- Analyst narratives
- Other unstructured security documents

Embeddings are useful when the system needs semantic similarity rather than exact keyword matches.

The implementation follows this principle by keeping the core risk facts structured while supporting semantic retrieval for NIST control relevance.

---

## 2. Failure cases and how would you mitigate them?

### External reference download failure

If NIST or CISA data cannot be downloaded, the application can continue using the locally cached reference files when available.

**Mitigation:** cache reference data and expose provenance so the operator can see where the information originated.

### Missing or incomplete data

An asset may not map cleanly to a business service or a vulnerability may not have matching threat intelligence.

**Mitigation:** use safe defaults, preserve the available evidence, and avoid fabricating missing information.

### Semantic model unavailable

The embedding model may fail to load or may be unsuitable for a constrained deployment environment.

**Mitigation:** fall back to lexical/context-aware retrieval. The dashboard also reports the retrieval method used.

### Gemini unavailable

The API key may be missing, invalid, unavailable, or the model call may fail.

**Mitigation:** use deterministic template-based explanations instead of blocking the risk report.

### Incorrect or misleading semantic retrieval

A semantically similar NIST control is not automatically the correct operational control.

**Mitigation:** combine semantic retrieval with lexical/contextual signals, preserve source provenance, expose the selected control, and keep the final recommendation reviewable by a human analyst.

### Model or prompt manipulation

Untrusted threat-report content could contain instructions intended to manipulate an AI model.

**Mitigation:** treat ingested content as data rather than instructions, constrain prompts to supplied evidence, and keep risk scoring deterministic rather than allowing an LLM to directly control prioritization.

### Resource constraints

Embedding thousands of NIST control representations can be expensive on small hosting instances.

**Mitigation:** cache reference data, avoid repeated model loading, provide a lightweight retrieval fallback, and use deployment-specific configuration such as `SEMANTIC_RAG=false` on constrained environments.

---

## 3. What is one thing you would change or improve?

The next improvement would be to **persist precomputed NIST embeddings and cache the generated risk report**.

This would reduce cold-start latency, avoid repeated embedding computation, make the API more resilient on constrained infrastructure, and allow semantic retrieval to remain enabled without recalculating the full reference representation for every service lifecycle.

A second-stage improvement would be adding a stronger evaluation suite with labeled scenarios to measure retrieval precision, ranking quality, and false-positive behavior.

---

# Security and Reliability Considerations

The project deliberately separates deterministic security logic from optional generative AI.

### Deterministic components

The following remain rule-based and auditable:

- Risk scoring
- Top 5 ranking
- CVE-to-asset joins
- Threat-intelligence matching
- CISA KEV matching
- Business-impact weighting
- Evidence generation

### AI-assisted components

Gemini is used only for natural-language explanation and summaries.

This prevents a generative model from becoming the single point of truth for security prioritization.

---

# Current Demo Dataset

The current public deployment demonstrates the assignment against:

- **60 assets**
- **114 vulnerabilities**
- **40 threat-intelligence records**
- **20 business services**

The dashboard presents the five highest-priority open vulnerabilities produced by the contextual scoring model.

---

# Submission

## Live application

https://hivepro-ai-associate.onrender.com

## GitHub repository

https://github.com/shashidharReddy866/hivepro-ai-associate

The repository contains the application source, test suite, assignment data, reference-handling logic, deployment documentation, and README.

---

# License

MIT
