# Gemini API Setup Instructions

## Environment Configuration

The AI-powered explanations for risks and NIST control summaries use Google's Gemini API.

### Set Your API Key

Set the `GEMINI_API_KEY` environment variable with your Google Gemini API key:

**Local Development**:
```bash
# PowerShell
$env:GEMINI_API_KEY = 'your-api-key-here'

# Bash
export GEMINI_API_KEY='your-api-key-here'

# Windows CMD
set GEMINI_API_KEY=your-api-key-here
```

**Deployment (Railway/Render)**:
Add `GEMINI_API_KEY` as an environment variable in your platform's dashboard.

### Get a Gemini API Key

1. Go to [Google AI Studio](https://aistudio.google.com/)
2. Click "Get API Key" (top right)
3. Create a new API key or use an existing one
4. Ensure the API key has access to these models:
   - `gemini-2.0-flash` (recommended)
   - `gemini-1.5-pro`
   - `gemini-1.5-flash`

### Without an API Key

If `GEMINI_API_KEY` is not set, the system gracefully falls back to:
- Template-based risk explanations (uses scoring factors)
- Control text truncation (first sentence extraction)

This maintains full functionality while LLM features are unavailable.

## Architecture

The Gemini API is used to generate:

1. **Risk Explanations** (`generateRiskExplanation`):
   - Analyzes vulnerability severity, asset criticality, threat context
   - Generates concise narrative explaining why the risk ranks high
   - Uses risk factors: internet exposure, exploit availability, threat actor campaigns, EDR coverage, CISA KEV status

2. **NIST Control Summaries** (`generateNistControlSummary`):
   - Summarizes dense NIST control text in plain language
   - Focuses on what the control does and why it matters for the specific risk
   - Keeps summaries under 250 characters for readability

Both functions have fallback mechanisms that trigger if:
- API key is not set
- Gemini API is unavailable
- Network errors occur
- Rate limits are exceeded

## Troubleshooting

### "models/gemini-pro is not found" Error

This means the API key doesn't have access to that model. Try:
1. Ensuring the API key is enabled for generative models
2. Using a different model name (the code will try alternatives)
3. Checking your Google Cloud quotas and billing

### LLM Features Disabled

If you see fallback explanations in the output, it means either:
- `GEMINI_API_KEY` environment variable is not set
- The API call failed (check logs for error details)
- The API key doesn't have model access

This is normal and expected. The system will continue to work with template-based explanations.

## Verification

To verify LLM integration is active locally:

```bash
$env:GEMINI_API_KEY = 'your-key-here'
npm run analyze
```

If the API key is configured properly, you'll see AI-generated risk explanations in the output instead of template sentences.
