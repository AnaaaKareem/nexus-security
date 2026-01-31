# FinOps & Resource Strategy

As this system relies on computationally expensive AI models, a FinOps strategy is essential to manage resources and costs, even when running locally.

## 1. Resource Cost Model

### Local Deployment (Current)

- **Currency**: Compute Time & Electricity.
- **Primary Cost Driver**: GPU/CPU usage during Inference.
- **Metric**: `Seconds per Scan`.
- **Optimization**:
  - Use **Quantized Models** (e.g., `q4_k_m`) to reduce RAM usage and increase speed.
  - Batching is currently *not* implemented but recommended for future scaling.

### Cloud Deployment (Future)

If migrating to SaaS LLMs (OpenAI, Anthropic) or Cloud GPUs:

- **Currency**: Token Counts (Input + Output).
- **Metric**: `Cost per Scan` = $(InputTokens \times P_{in}) + (OutputTokens \times P_{out})$.

## 2. Token Usage Estimation

Typical usage per finding:

| Phase | Input Tokens (Est) | Output Tokens (Est) |
| :--- | :--- | :--- |
| Triage | 1,500 (Snippet + System Prompt) | 200 (JSON Verdict) |
| Remediation | 1,500 (Snippet) | 500 (Code Patch) |
| **Total** | **3,000** | **700** |

*Note: With 100 findings per scan, this equates to ~300k input tokens.*

## 3. Controlling Costs (Strategies)

### A. Pre-Filtering (The "Thin" Layer)

We only send findings to the LLM that are detected by static tools (Semgrep/Trivy). We do *not* feed the entire codebase to the LLM, effectively filtering out 99% of non-vulnerable code.

### B. Confidence Thresholds

- **Ignore Low Severity**: Configure system to only Triage "High" and "Critical" findings to save tokens.
- **Auto-Reject**: If the LLM is < 50% confident, mark as "Needs Human Review" rather than retrying locally.

### C. Caching (Redis)

- **Hash Caching**: Hash the (Code Snippet + Rule ID). If we have seen this exact combination before, serve the cached verdict from Redis instead of querying the LLM again.
- **TTL**: Set a Time-To-Live of 30 days for cached decisions.
