# Deployment Guide

## Production Deployment

The TawasolPay Cyber Risk Assistant is deployed as a Node.js web service on Render.

**Live Application:**  
https://hivepro-ai-associate.onrender.com

## Render Configuration

- Service Type: Web Service
- Runtime: Node.js
- Branch: `main`
- Build Command: `npm install`
- Start Command: `npm start`

The application listens on the platform-provided `PORT` and binds to `0.0.0.0`.

## Production Environment

The Render deployment uses:

```text
NODE_ENV=production
SEMANTIC_RAG=false