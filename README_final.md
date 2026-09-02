# TawasolPay Cyber Risk Assistant

> Context-aware vulnerability prioritization for identifying the **Top 5 cyber risks** that require the most urgent attention.

**Live Demo:** https://hivepro-ai-associate.onrender.com  
**GitHub:** https://github.com/shashidharReddy866/hivepro-ai-associate

---

## Overview

Traditional vulnerability management often prioritizes issues primarily by CVSS severity. This project takes a broader approach by combining **technical severity, exploitability, threat intelligence, asset exposure, business criticality, compensating controls, and authoritative security references**.

The system processes the complete assignment data pack and produces a ranked Top 5 risk view with the evidence behind each decision.

### Key signals considered

- CVSS severity
- Internet exposure
- Exploit availability
- Weaponized exploitation
- Threat actor and campaign matches
- Ransomware association
- CISA Known Exploited Vulnerabilities (KEV)
- Asset criticality
- Business-service impact
- Revenue impact
- Compliance scope
- EDR / compensating-control gaps
- Vulnerability age
- Patch availability

The goal is not simply to identify the most technically severe vulnerability, but to answer:

> **Which vulnerabilities create the greatest real-world business risk, and why should they be remediated first?**

---

# Key Capabilities

## 1. Contextual Top 5 Risk Prioritization

The application evaluates open vulnerabilities and produces a ranked Top 5 list.

Each prioritized risk includes:

- Rank
- Normalized risk score (0–100)
- Raw risk score
- Affected asset
- CVE and CVSS
- Exploit status
- Patch status
- Threat actor and campaign
- Ransomware association
- CISA KEV evidence
- Business-service impact
- NIST SP 800-53 remediation
- Operational remediation guidance
- Transparent scoring breakdown

---

## 2. Evidence-Based Risk Explanations

The system explains why a vulnerability ranks highly using available evidence instead of relying on CVSS alone.

Example:

```text
Internet exposed
+ Exploit available
+ Active threat campaign
+ Ransomware association
+ No EDR
+ CISA KEV
+ Critical business impact
```

This makes the prioritization easier for a security analyst or business stakeholder to understand and audit.

---

## 3. CISA KEV Enrichment

Open vulnerabilities are cross-referenced against the **CISA Known Exploited Vulnerabilities catalog**.

When a CVE is present in KEV, the application surfaces:

- Date added
- Known ransomware campaign use
- Required action

---

## 4. NIST SP 800-53 Remediation

The application maps prioritized vulnerabilities to relevant **NIST SP 800-53 Rev. 5** controls.

The retrieval pipeline supports:

- Semantic retrieval using sentence-transformer embeddings
- Lexical/context-aware fallback
- Risk-intent-aware control reranking
- Source provenance to the NIST catalog
- Human-readable control summaries

Examples:

```text
Vulnerability / patch / RCE
→ SI-2 Flaw Remediation

Active exploitation / ransomware
→ IR-4 Incident Handling

Vulnerability assessment / monitoring
→ RA-5 Vulnerability Monitoring

Authentication / account risks
→ AC-2 Account Management

Unsupported components
→ SA-22 Unsupported System Components
```

---

## 5. Optional Generative AI

Google Gemini can be enabled for:

- Risk-priority explanations
- NIST control summaries

The application remains functional without Gemini by using deterministic fallback explanations.

The LLM is **not responsible for determining the Top 5 ranking**. Core prioritization remains deterministic and auditable.

---

# Architecture

```text
                    ┌───────────────────────────┐
                    │       Assignment Data     │
                    │                           │
                    │ assets.csv                │
                    │ vulnerabilities.csv       │
                    │ threat_intelligence.csv   │
                    │ business_services.csv     │
                    │ remediation_guidance.csv  │
                    │ threat_report.md          │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │        Risk Engine         │
                    │                           │
                    │ Structured joins          │
                    │ Contextual scoring        │
                    │ Threat intelligence       │
                    │ Business impact            │
                    │ Control-gap analysis       │
                    │ Threat-report context      │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
          ┌──────────────────┐        ┌────────────────────┐
          │ CISA KEV         │        │ NIST SP 800-53     │
          │ CVE enrichment   │        │ Retrieval + Rerank │
          └────────┬─────────┘        └─────────┬──────────┘
                   │                            │
                   └──────────────┬─────────────┘
                                  ▼
                    ┌───────────────────────────┐
                    │      Top 5 Risk Report     │
                    │                           │
                    │ Rank + score              │
                    │ Evidence + rationale      │
                    │ Business impact            │
                    │ Remediation                │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │       Web Dashboard        │
                    │       Node.js + HTTP       │
                    └───────────────────────────┘
```

---

# Data Sources

The application ingests the complete assignment data pack:

| Source | Purpose |
|---|---|
| `assets.csv` | Asset identity, type, ownership, exposure, criticality, EDR status, location |
| `vulnerabilities.csv` | CVE, CVSS, exploitability, patch status, affected component, age |
| `threat_intelligence.csv` | Threat actors, campaigns, exploit maturity, ransomware association, confidence |
| `business_services.csv` | Business impact, revenue impact, customer-facing status, RTO, compliance scope |
| `remediation_guidance.csv` | Operational remediation actions and validation evidence |
| `synthetic_threat_report.md` | Unstructured scenario-level threat context |

The system also uses authoritative external references:

- **NIST SP 800-53 Rev. 5**
- **CISA Known Exploited Vulnerabilities (KEV)**

Reference data is cached under `/references`.

---

# Risk Scoring Methodology

The scoring model is deterministic, transparent, and designed to prioritize business risk rather than CVSS severity alone.

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

The raw score is normalized to a **0–100 dashboard score**.

### Contextual scoring signals

#### Technical severity
CVSS provides the technical severity baseline.

#### Internet exposure
Internet-facing assets receive additional risk weighting.

#### Asset criticality
Critical and high-value assets receive additional weighting.

#### Business impact

The model considers:

- Revenue impact
- Customer-facing status
- Risk appetite
- Recovery time objective
- Compliance scope

#### Threat and exploit signals

Higher priority is given to:

- Exploit availability
- Weaponized exploitation
- Threat actor campaign matches
- Ransomware association
- CISA KEV inclusion
- Known ransomware campaign use in KEV

#### Control gaps and age

Risk increases when:

- EDR is absent
- Assets are stale
- Patches are unavailable
- Vulnerabilities remain open for long periods

The dashboard exposes the individual scoring factors for auditability.

---

# NIST Retrieval / RAG Design

NIST remediation is treated as a retrieval problem rather than a hardcoded CVE-to-control mapping.

The retrieval query incorporates risk context such as:

- Vulnerability name
- Affected component
- Asset type
- Threat-intelligence summary
- Threat-report context
- Operational remediation guidance

## Semantic Retrieval

The repository includes:

```text
Xenova/all-MiniLM-L6-v2
```

for semantic similarity between risk context and NIST control text.

## Intent-Aware Reranking

Retrieved controls are further evaluated using remediation intent.

This helps prevent a semantically similar but operationally weak control from being selected when the risk clearly indicates a stronger remediation category.

## Fallback Retrieval

When semantic embeddings are unavailable, the system uses lexical and contextual retrieval.

This keeps the application functional in constrained environments.

## Production Deployment

The public Render Free deployment uses:

```text
SEMANTIC_RAG=false
```

This avoids loading the resource-intensive transformer model in the constrained production runtime.

The semantic retrieval implementation remains available in the codebase and can be enabled with:

```text
SEMANTIC_RAG=true
```

The live deployment therefore uses the lightweight retrieval path while retaining the full semantic RAG capability in the implementation.

---

# Threat Report Handling

The unstructured `synthetic_threat_report.md` is ingested separately from the structured CSV data.

The pipeline uses the report as **corroborating contextual evidence** by checking for relevant:

- CVEs
- Threat actors
- Campaigns
- Exploitation signals
- Ransomware indicators
- Initial-access or lateral-movement context

The report does not override structured security data. This prevents unstructured text from directly manipulating the deterministic risk score.

---

# AI Safety and Reliability

The architecture intentionally separates deterministic security logic from generative AI.

### Deterministic

- Risk scoring
- Top 5 ranking
- CVE matching
- Asset joins
- Threat-intelligence matching
- CISA KEV matching
- Business-impact weighting
- Evidence generation

### AI-assisted

- Risk explanations
- NIST control summaries
- Semantic document retrieval

This design reduces the risk of an LLM hallucination directly changing security prioritization.

Imported reports are treated as **data, not instructions**, which helps reduce prompt-injection risk from untrusted content.

---

# Quick Start

## Requirements

- Node.js
- npm

## Install

```bash
npm install
```

## Start locally

```bash
npm start
```

Open:

```text
http://localhost:3000
```

## Run analysis from CLI

```bash
npm run analyze
```

## Run tests

```bash
npm test
```

## Refresh external references

```bash
npm run refresh:references
```

---

# Deployment — Render

The public application is deployed on **Render**.

## Service configuration

```text
Service Type: Web Service
Runtime: Node
Branch: main
Start Command: npm start
```

The server listens on the platform-provided `PORT` and binds to `0.0.0.0`.

## Environment variables

### Production

```text
SEMANTIC_RAG=false
```

### Optional Gemini

```text
GEMINI_API_KEY=your_api_key
```

## Health check

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

## Risk report

```text
GET /api/risks
```

Returns the complete prioritized risk report used by the dashboard.

## Refresh references

```text
POST /api/references/refresh
```

Refreshes the cached NIST and CISA KEV reference data.

---

# Project Structure

```text
hivepro-ai-associate/
│
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

| Component | Technology |
|---|---|
| Runtime | Node.js |
| HTTP server | Node.js built-in `http` |
| Frontend | HTML, CSS, Vanilla JavaScript |
| Risk engine | JavaScript |
| Semantic retrieval | `@xenova/transformers` |
| Embedding model | `Xenova/all-MiniLM-L6-v2` |
| Generative AI | Google Gemini API (optional) |
| Security references | NIST SP 800-53 + CISA KEV |
| Data format | CSV, JSON, Markdown |
| Testing | Node.js test runner / assertions |
| Deployment | Render |

---

# API

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
- Threat-report evidence
- CISA KEV evidence
- Business-service context
- NIST remediation
- Scoring evidence
- Reference provenance

## Reference Refresh

```text
POST /api/references/refresh
```

Refreshes the NIST and CISA KEV reference caches.

---

# Testing

The automated test suite validates core behavior including:

- CSV parsing
- Data ingestion counts
- Top 5 generation
- Risk ordering
- Score normalization
- Threat/ransomware prioritization
- NIST control availability
- NIST source provenance

Run:

```bash
npm test
```

Expected:

```text
All tests passed
```

---

# Assignment Questions

## 1. What data would you keep structured vs embedded, and why?

I would keep assets, vulnerabilities, CVEs, CVSS, exploit status, business-service metadata, threat-intelligence metadata, KEV matches, remediation actions, and scoring factors **structured** because they require exact joins, filtering, deterministic scoring, validation, and auditing.

For semantic retrieval, I would embed **NIST control text and other long-form security content** because the relevant concept may not use the same keywords as the input risk. In this implementation, the threat report is currently ingested and used as contextual evidence rather than embedded.

## 2. What are some failure cases and how would you mitigate them?

**Incorrect NIST retrieval:** semantic similarity may return a plausible but operationally weak control. Mitigation: combine retrieval with remediation-intent reranking and keep source provenance visible.

**Missing or stale security data:** an asset may have no business-service match or a vulnerability may have no threat-intelligence match. Mitigation: use safe defaults, preserve available evidence, and never invent missing facts.

**External/model failure:** NIST/CISA downloads, embeddings, or Gemini may be unavailable. Mitigation: use cached references, lexical/context-aware NIST fallback, and deterministic explanations so the core risk report continues to work.

## 3. What is one thing you would change/improve?

I would next persist precomputed NIST embeddings and cache the generated risk report. This would reduce cold-start latency, reduce repeated computation, improve reliability on constrained infrastructure, and make semantic retrieval more practical for production use.

---

# Current Demo Dataset

The public deployment currently demonstrates the assignment using:

- **60 assets**
- **114 vulnerabilities**
- **40 threat-intelligence records**
- **20 business services**

The dashboard presents the five highest-priority open vulnerabilities produced by the contextual risk-scoring model.

---

# Submission

### Live Application

https://hivepro-ai-associate.onrender.com

### GitHub Repository

https://github.com/shashidharReddy866/hivepro-ai-associate

The repository contains the assignment data, application source, tests, NIST/CISA reference handling, deployment documentation, and implementation details.

---

# License

MIT
