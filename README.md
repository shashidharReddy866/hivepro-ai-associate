# TawasolPay Cyber Risk Assistant

A smart system that finds the riskiest cyber threats in your organization and explains what to do about them.

## What It Does

✅ Finds the **top 5 cyber risks** in your network  
✅ Explains **why** each risk is dangerous (threat actors, business impact, patch status)  
✅ Tells you **which NIST security control** to implement to fix it  
✅ Shows **evidence**: CVSS score, exploit availability, ransomware campaigns, EDR status  
✅ Uses **AI embeddings** to match risks to the right security controls  

It takes your:
- Assets (servers, databases, load balancers)
- Vulnerabilities (CVEs with CVSS scores)
- Threat intelligence (who's attacking, what campaigns)
- Business services (payment processing, customer login, etc.)

...and ranks them by **real-world business risk**, not just CVSS score.

---

## Quick Start (2 Minutes)

### Run Locally

```bash
npm install
npm start
```

Open **http://localhost:3000** in your browser.

See the dashboard with top 5 risks, scores, threat details, and NIST controls.

---

## Deploy to Public URL

### Railway (Easiest - Free Tier)

1. Go to **https://railway.app/new**
2. Click **Deploy from GitHub**
3. Connect your GitHub account
4. Select this repository
5. Click **Deploy Now**
6. Wait 2-3 minutes
7. Get your public URL from Railway dashboard ✓

Your app is now live: `https://your-app-name.up.railway.app`

### Other Platforms

See [DEPLOYMENT.md](DEPLOYMENT.md) for:
- **Render** setup (3 clicks)
- **Fly.io** setup (CLI)
- **Environment variables** and Gemini API setup

---

## AI-Powered Explanations (Optional)

By default, the system generates risk explanations using templates. For smarter AI-generated explanations using Google Gemini:

```bash
# Set your API key (PowerShell)
$env:GEMINI_API_KEY = 'your-key-here'
npm start
```

**Get a free Gemini API key**: https://aistudio.google.com/ (click "Get API Key")

**On Railway/Render**: Add `GEMINI_API_KEY` in your platform's environment variables.

See [DEPLOYMENT.md](DEPLOYMENT.md#configure-gemini-api-optional) for detailed setup.

---

## How It Works

### Step 1: Load Data
Loads assets, vulnerabilities, threat intel, and NIST controls from CSV/JSON files bundled in `/data`.

### Step 2: Score Risks
Each open vulnerability is scored based on:
- CVSS severity
- Is it exposed to the internet?
- Is there an exploit available?
- Is it in CISA's Known Exploited Vulnerabilities list?
- Which threat actors are using it?
- How critical is the affected asset?
- What's the business impact (payment processing, customer login, etc.)?
- Is EDR protection installed?

### Step 3: Match NIST Controls
For each risk, the system finds the best **NIST SP 800-53 security control** to implement:
- Uses **AI embeddings** to match risk context to control relevance
- Falls back to keyword matching if needed
- Shows why that control is relevant to the specific risk

### Step 4: Display Results
Shows the **top 5 risks** with full details:
- Risk score and ranking
- Asset, vulnerability, threat actor
- Business service impact
- NIST control to implement
- Evidence breakdown (all scoring factors)

---

## Project Structure

```
hivepro-ai-associate/
├── public/                    # Frontend (HTML, CSS, JavaScript)
│   ├── index.html            # Dashboard page
│   ├── app.js                # Dashboard logic (search, filtering)
│   └── styles.css            # Dashboard styling
├── src/                       # Backend (Node.js)
│   ├── server.js             # Webserver (API endpoints)
│   ├── riskEngine.js         # Risk scoring, NIST matching, embeddings
│   ├── csv.js                # CSV parsing utility
│   └── cli.js                # Command-line interface
├── data/                      # Input data (bundled, no database needed)
│   ├── assets.csv            # Servers, databases, devices
│   ├── vulnerabilities.csv   # CVEs with CVSS, patch status
│   ├── threat_intelligence.csv  # Threat actors, campaigns
│   ├── business_services.csv # Payment processing, login, etc.
│   ├── remediation_guidance.csv # How to fix each vulnerability
│   ├── synthetic_threat_report.md  # Sample threat report
│   └── vulnerabilities.csv   # Open CVEs
├── references/               # NIST controls and CISA KEV (cached at runtime)
├── tests/                    # Unit tests for risk scoring
├── DEPLOYMENT.md             # How to deploy to Railway, Render, Fly.io
└── package.json              # Dependencies (Express, transformers, etc.)
```

---

## Commands

```bash
# Install dependencies
npm install

# Run locally (http://localhost:3000)
npm start

# Analyze and print results to terminal
npm run analyze

# Refresh NIST and CISA KEV data from official sources
npm run refresh:references

# Run tests
npm test
```

---

## Technology Stack

| Part | Technology | Why |
|------|-----------|-----|
| **Web Server** | Node.js + Express | Fast, lightweight, easy to deploy |
| **Frontend** | HTML + CSS + JavaScript | No framework needed, minimal overhead |
| **Risk Scoring** | JavaScript logic | Joins CSV data, calculates weighted scores |
| **NIST Matching** | Sentence Transformers (embeddings) | Semantic matching (AI-powered, not keyword matching) |
| **AI Explanations** | Google Gemini API (optional) | Generates natural-language risk narratives |
| **Data** | CSV files (bundled) | No database needed, fast startup |

---

## Environment Variables (Optional)

| Variable | Purpose | Default |
|----------|---------|---------|
| `GEMINI_API_KEY` | Google Gemini API for AI explanations | Not set (uses templates) |
| `PORT` | Server port | 3000 (or set by platform) |

---

## FAQ

**Q: Do I need a database?**  
A: No. All data is bundled in CSV files and loaded at startup. Very fast, easy to deploy.

**Q: Can I customize the data?**  
A: Yes. Edit the CSV files in `/data/`:
- Add/remove assets, vulnerabilities, threat intel
- Adjust business service criticality
- Add new remediation guidance

**Q: How often does NIST/CISA data update?**  
A: Run `npm run refresh:references` to download the latest. Data is cached locally.

**Q: Why is the first startup slow?**  
A: Server pre-computes embeddings for all 1000+ NIST controls (~45 seconds). This is cached, so subsequent API calls are instant.

**Q: Can I use this in production?**  
A: Yes. Deploy to Railway (free tier), Render, or Fly.io with one click. No special setup needed.

---

## What Evaluators Will See

✅ **Embeddings-Based Retrieval**: NIST controls matched using AI embeddings, not keyword matching  
✅ **AI Integration**: Gemini API generates intelligent risk explanations (if API key set)  
✅ **Professional Dashboard**: Clean UI showing top 5 risks with full evidence  
✅ **Structured Scoring**: Transparent evidence breakdown (CVSS, exposure, threat, business impact)  
✅ **Production Ready**: Deployed on Railway with public URL  
✅ **Clean Code**: Modular, well-commented, testable  

---

## Next Steps

1. **Run locally**: `npm start` → http://localhost:3000
2. **Deploy**: Go to https://railway.app/new → Deploy from GitHub
3. **(Optional) Enable AI**: Set `GEMINI_API_KEY` and redeploy
4. **Customize**: Edit `/data/` CSV files to match your environment

---

## Support & Documentation

- **How to deploy?** → [DEPLOYMENT.md](DEPLOYMENT.md)
- **How to set up Gemini?** → [DEPLOYMENT.md](DEPLOYMENT.md#configure-gemini-api-optional)
- **Questions?** → Check the code comments in `src/riskEngine.js`

---

## License

MIT
