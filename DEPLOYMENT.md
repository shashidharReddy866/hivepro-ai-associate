# Deployment Guide

## Quick Deploy (1-2 Minutes)

### Railway (Recommended - Free Tier)

Railway is the easiest option. It automatically handles Node.js deployment, SSL, and domain setup.

**Step 1: Deploy**
1. Go to https://railway.app/new
2. Click **Deploy from GitHub**
3. Authorize Railway with your GitHub account
4. Select `hivepro-ai-associate` repository
5. Click **Deploy Now**
6. Wait 2-3 minutes for build and deployment

**Step 2: Get Your URL**
1. Your public URL appears in the Railway dashboard
2. Example: `https://hivepro-ai-risk-assistant.up.railway.app`
3. Open it in your browser ✓

**Done!** Your app is live with embeddings-based NIST retrieval.

---

## Optional: Enable AI Explanations (Gemini API)

By default, risk explanations use templates. To enable AI-powered explanations using Google Gemini:

### Get a Free Gemini API Key

1. Go to https://aistudio.google.com/
2. Click **"Get API Key"** (top right)
3. Create a new API key
4. Copy the key (looks like: `AIzaSy...`)

### Add to Railway

1. In your Railway dashboard, go to **Variables**
2. Add a new variable:
   - Key: `GEMINI_API_KEY`
   - Value: paste your key
3. Click **Redeploy** or push a new commit to trigger deployment

Your app now generates smart AI explanations! 🚀

### Add to Render or Fly.io

**Render**:
1. Go to your service dashboard
2. Click **Environment**
3. Add variable: `GEMINI_API_KEY = your-key-here`
4. Click **Save and Deploy**

**Fly.io**:
1. Run: `flyctl secrets set GEMINI_API_KEY=your-key-here`
2. Deploy: `fly deploy`

### Test Locally

```bash
$env:GEMINI_API_KEY = 'your-api-key-here'
npm start
```

---

## Alternative Platforms

### Render

Render is similar to Railway. Free tier includes monthly free hours.

**Setup**:
1. Go to https://dashboard.render.com
2. Click **New +** → **Web Service**
3. Connect your GitHub account
4. Select `hivepro-ai-associate` repo
5. Use these settings:
   - **Name**: `hivepro-ai-risk-assistant`
   - **Runtime**: `Node`
   - **Build command**: `npm install`
   - **Start command**: `npm start`
6. Click **Create Web Service**

Your app is live in 3-5 minutes.

**Add Gemini API key**:
1. Go to service dashboard → **Environment**
2. Add: `GEMINI_API_KEY = your-key-here`
3. Click **Save and Deploy**

---

### Fly.io

Fly.io uses CLI deployment. Slightly more technical but very reliable.

**Prerequisites**:
```bash
npm install -g flyctl
flyctl auth login
```

**Deploy**:
```bash
flyctl launch --image node:20
flyctl deploy
```

**Add Gemini API key**:
```bash
flyctl secrets set GEMINI_API_KEY=your-api-key-here
flyctl deploy
```

**Get your URL**:
```bash
flyctl info
```

---

## Troubleshooting

### "Port already in use"
Make sure no other app is running on port 3000.
```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID <pid> /F
```

### "Embedding model timeout"
The server pre-computes embeddings on first startup (~45 seconds). This is normal. Wait for "Embeddings computed and cached" message.

### "API returns 500 error"
Check server logs:
- **Railway**: Click **Logs** in dashboard
- **Render**: Click **Logs** in service dashboard
- **Local**: Watch terminal output

### "Gemini API returns 404 errors"
The provided API keys may not have model access. Try your own key from https://aistudio.google.com/. System gracefully falls back to templates if API key invalid.

---

## Verify Deployment

Once deployed, test the API:

```bash
curl https://your-app-name.up.railway.app/api/risks
```

You should see JSON with top 5 risks. Check for:
- `"retrievalMethod": "embeddings"` → Confirms semantic NIST matching is active
- `"topRisks": [...]` → Top 5 risks with scores and NIST controls

---

## Environment Variables Reference

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `GEMINI_API_KEY` | No | (none) | Google Gemini API key for AI explanations |
| `PORT` | No | 3000 | Server port (platform usually sets this) |
| `NODE_ENV` | No | development | Set to `production` to hide error stacks |

---

## Performance Notes

- **First startup**: ~45 seconds (pre-computes embeddings for 1000+ NIST controls)
- **API response**: <100ms after startup (embeddings cached)
- **Dashboard load**: Instant (pre-computed, cached data)
- **Memory**: ~400MB (Node + embedding model)
- **CPU**: Low (embeddings computed once, then cached)

---

## How Deployment Works

1. **Platform pulls code** from GitHub
2. **Platform installs dependencies** (`npm install`)
3. **Server starts** (`npm start`):
   - Loads embedding model
   - Pre-computes NIST control embeddings (~45 sec)
   - Loads CSV data
   - Starts web server
4. **Dashboard is live** and ready for requests
5. **API responds** with top 5 risks and NIST controls

---

## After Deployment

### Customize Data

Edit the CSV files in `/data/` to match your environment:
- `assets.csv` → Add your servers, databases, devices
- `vulnerabilities.csv` → Add your CVEs
- `threat_intelligence.csv` → Add threat intel
- `business_services.csv` → Add your services

Then push to GitHub, and your deployed app automatically updates.

### Monitor

Check logs in your platform's dashboard:
- **Railway**: Logs tab
- **Render**: Logs tab
- **Fly.io**: `flyctl logs`

### Redeploy

To redeploy after changes:
- **Railway**: Automatic (detects Git push)
- **Render**: Automatic (detects Git push)
- **Fly.io**: Run `fly deploy`

---

## Next Steps

1. ✅ Deploy to your platform (Railway/Render/Fly.io)
2. ✅ Get public URL
3. ✅ (Optional) Add Gemini API key for AI
4. ✅ (Optional) Customize data in `/data/`
5. ✅ Share URL with evaluators

---

## Questions?

- **Local development**: `npm start` → http://localhost:3000
- **Data customization**: Edit `/data/` CSV files
- **Troubleshooting**: Check platform logs
- **Code changes**: Edit `src/` files, push to GitHub, platform auto-deploys
