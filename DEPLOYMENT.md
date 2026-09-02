# Deployment Guide

## Quick Deploy (Recommended)

### Railway (Free Tier - 500 hours/month)

**Option 1: One-Click Deploy**
1. Click: https://railway.app/new
2. Click **Deploy from GitHub**
3. Authorize Railway with your GitHub account
4. Select `hivepro-ai-associate` repository
5. Click **Deploy Now**
6. Wait 2-3 minutes for build and deployment
7. Your public URL will appear in the Railway dashboard (e.g., `https://hivepro-ai-risk-assistant.up.railway.app`)

**Option 2: Using Railway CLI**
```bash
npm install -g @railway/cli
railway login
railway up
```

---

## Environment Setup

### Required Variables (Optional)

The app works without any environment variables. However, to enable AI-powered risk explanations and NIST summaries, configure:

- **`GEMINI_API_KEY`**: Your Google Gemini API key for LLM-based explanations
  - Get one at: https://aistudio.google.com/
  - If not set, the system uses template-based explanations (full functionality maintained)

### Default Configuration

- **Port**: Automatically set by platform (or 3000 locally)
- **Node version**: 20.x or higher
- **Build command**: `npm install`
- **Start command**: `npm start`

- **Start command**: `npm start`

All data (assets, vulnerabilities, threat intel) is bundled in `/data` — no database required.

---

## Configure Gemini API (Optional)

To enable AI-powered risk explanations:

**Railway**:
1. Go to your Railway project dashboard
2. Click **Variables** in the left sidebar
3. Add new variable: `GEMINI_API_KEY = your-api-key-here`
4. Deploy again (Redeploy from git or click "Trigger Deploy")

**Render**:
1. Go to your Render service dashboard
2. Click **Environment**
3. Add new environment variable: `GEMINI_API_KEY = your-api-key-here`
4. Click **Save and Deploy**

**Local Development**:
```bash
$env:GEMINI_API_KEY = 'your-api-key-here'
npm start
```

**Getting a Gemini API Key**:
1. Go to https://aistudio.google.com/
2. Click "Get API Key" (top right)
3. Create a new API key
4. Copy the key and paste into your platform's environment variables

Without `GEMINI_API_KEY`, the system gracefully falls back to template-based explanations while maintaining full functionality.

---

## Post-Deployment Verification

Once deployed, verify the app is live:

```bash
curl https://<your-public-url>/api/risks
```

You should get a JSON response with top 5 risks and NIST controls. Check for:
- `"retrievalMethod": "embeddings"` in `referenceProvenance` (confirms semantic retrieval is active)
- Top risk includes `"remediation": { "nistControl": {...} }`

---

## Alternative Platforms

### Render (Free Tier)

1. Go to https://dashboard.render.com
2. Click **New +** → **Web Service**
3. Connect your GitHub account
4. Select `hivepro-ai-associate`
5. Configure:
   - Name: `hivepro-ai-risk-assistant`
   - Runtime: `Node`
   - Build Command: `npm install`
   - Start Command: `npm start`
6. Click **Create Web Service**
7. Wait for deployment (visible in logs)
8. Public URL assigned automatically

### Fly.io

```bash
brew install flyctl  # or from https://fly.io/docs/hands-on/install-flyctl/
flyctl auth login
flyctl launch
flyctl deploy
```

The `fly.toml` file is already configured in the repo.

---

## Troubleshooting

### Embeddings Model Takes Long to Load

First request to `/api/risks` may take 30-60 seconds because the embedding model loads on startup. This is normal. Subsequent requests are <2 seconds.

**Solution**: Hit the endpoint once after deployment and wait. The model will be cached.

### Out of Memory on Free Tier

The embedding model is ~300MB. Free tiers with <512MB RAM may time out.

**Solution**: Use Railway or Render's paid tier (upgrade to 1GB RAM for ~$5/month) or use the fallback lexical retrieval (gracefully degrades if model unavailable).

### Public URL Shows 502/503 Errors

The app is likely still building or restarting.

**Solution**: Wait 1-2 minutes and refresh. Check the deployment platform's logs for details.

---

## Monitoring

Both Railway and Render provide:
- Live logs (visible in dashboard)
- CPU/Memory metrics
- Deploy history and rollback options

No additional setup needed. All errors are logged to stdout and visible in the platform's log viewer.

---

## Updating After Deployment

1. Make changes locally
2. Commit and push to GitHub
3. Platform auto-redeploys on new commits (if CI/CD enabled)

For Railway: Enable "Deploy on push" in project settings (enabled by default).
For Render: Same automatic redeploy on push.

---

## Cost

- **Railway**: Free tier includes 500 compute hours/month (~$5/month if you exceed)
- **Render**: Free tier sleeps after 15 minutes of inactivity
- **Fly.io**: Free tier includes 3 shared VMs (~$0.15/month for always-on)

This app easily fits within free tier limits.
