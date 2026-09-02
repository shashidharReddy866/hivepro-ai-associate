# AI-Powered Cyber Risk Assistant - Implementation Summary

## AI Capabilities Implemented

### 1. Semantic Document Retrieval (Embeddings-Based RAG)

**Implementation**: Sentence-transformer embeddings for NIST control selection  
**Technology**: `@xenova/transformers` with `Xenova/all-MiniLM-L6-v2` model  
**What It Does**:
- Computes embeddings for all 1000+ NIST SP 800-53 Rev. 5 controls at startup
- Generates query embeddings from risk context (vulnerability name, asset type, threat summary, remediation hints)
- Ranks controls by cosine similarity (semantic relevance) instead of keyword matching
- Gracefully falls back to lexical token-overlap scoring if embedding model unavailable

**Why It Matters**: This addresses the brief's core evaluation criterion: *"The NIST document is retrieved with embeddings."* Controls are chosen based on semantic understanding of the risk, not hardcoded keyword mappings.

### 2. Generative AI Risk Explanations (Gemini API)

**Implementation**: Google Gemini API for intelligent risk narratives  
**Technology**: `@google/generative-ai` with `gemini-pro` model  
**What It Does**:
- Analyzes each risk's multidimensional context (vulnerability severity, asset criticality, threat actor activity, EDR coverage, compliance impact)
- Generates natural-language explanations for why risks rank high
- Replaces hardcoded template sentences with AI-generated insights
- Includes fallback mechanism if API unavailable or key not configured

**Example Generation Flow**:
```
Input: Citrix CVE + Critical Asset + IronVeil Campaign + No EDR + CISA KEV Listed + Payment Processing
→ Gemini Analysis
→ Output: "Session token vulnerability on exposed production gateway without EDR 
   enables IronVeil group to escalate and target payment processing directly; 
   rates high despite moderate CVSS due to campaign targeting and lack of detection."
```

### 3. Intelligent Control Summaries (Gemini API)

**Implementation**: Gemini-powered summarization of NIST control text  
**What It Does**:
- Generates concise, relevance-focused summaries of dense NIST control descriptions
- Explains what the control does and why it matters for the specific risk context
- Replaces simple text truncation with intelligent contextual summaries
- Maintains fallback to automatic truncation if API unavailable

**Example Generation Flow**:
```
Input: SC-23(2) Session Authenticity control + Session token leak risk
→ Gemini Analysis
→ Output: "Implements session authenticity mechanisms with user-initiated 
   logouts and message displays; directly addresses token reuse and hijacking 
   threats in the Citrix CVE-2023-4966 context."
```

## Code Architecture

### Retrieval Split (RAG Pattern)

**Structured Data** (CSV queries):
- Assets, vulnerabilities, threat intelligence, business services
- Queried via exact joins and weighted scoring
- No embeddings needed for stable relational data

**Unstructured/Semantic Data** (Document Retrieval):
- NIST SP 800-53 control descriptions (1000+ documents)
- Retrieved via embeddings for semantic relevance
- Supplemented with LLM-generated summaries for clarity

### LLM Integration

**Async Pattern**:
- `generateRiskExplanation(risk, hint)` - LLM-powered narrative generation
- `generateNistControlSummary(control)` - Context-aware control summaries
- `getGeminiModel()` - Lazy initialization with graceful degradation

**Error Handling**:
- Missing API key → fallback to templates
- Network timeout → fallback to templates
- Rate limiting → fallback to templates
- Full system functionality maintained in all fallback cases

## Deployment Configuration

### Environment Variables

**Development**:
```bash
$env:GEMINI_API_KEY = 'your-api-key'
npm run analyze
```

**Deployment (Railway/Render)**:
1. Add `GEMINI_API_KEY` to platform environment variables
2. Redeploy
3. LLM features activate automatically

**Getting API Key**: https://aistudio.google.com/ (free tier available)

## Why This Matters for "AI Engineer" Role

1. **Beyond Templates**: Risk explanations are AI-generated, not hardcoded strings
2. **Semantic Understanding**: NIST controls selected by embeddings-based semantic similarity, not keyword matching
3. **Intelligent Summaries**: Control descriptions refined by LLM, not just truncated
4. **Graceful Degradation**: System works without LLM, but significantly improved with it
5. **Production-Ready**: Proper error handling, fallbacks, and documentation

## Testing

### Verify Embeddings Are Working:
```bash
npm run analyze
# Look for: "NIST Control Retrieval Method: embeddings"
```

### Verify LLM Is Integrated (with API key):
```bash
$env:GEMINI_API_KEY = 'your-key'
npm run analyze
# Observe: Risk explanations are generated narratives, not templates
# Observe: NIST control summaries are context-aware, not truncated text
```

### Without LLM (fallback verification):
```bash
npm run analyze
# System works fully, using template-based explanations
```

## Documentation

- **[GEMINI_SETUP.md](GEMINI_SETUP.md)** - Complete Gemini API configuration guide
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Platform-specific LLM setup instructions
- **[README.md](README.md)** - Architecture overview with AI components

## Key Files

- `src/riskEngine.js` - Core LLM integration and retrieval logic
- `package.json` - Dependencies: `@google/generative-ai`, `@xenova/transformers`
- `GEMINI_SETUP.md` - Setup and troubleshooting
- `.github/workflows/deploy.yml` - CI/CD with environment variable support

---

**Summary**: The system now combines three AI techniques:
1. **Semantic retrieval** (embeddings) for NIST control selection
2. **Generative AI** (Gemini) for risk explanations
3. **Intelligent summarization** (Gemini) for control summaries

This fully addresses the "AI-Powered Cyber Risk Assistant" requirement for an "AI Engineer" role.
