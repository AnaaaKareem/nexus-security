# AI Models Explained

The system leverages Large Language Models (LLMs) to perform complex reasoning tasks that traditional static analysis tools cannot handle.

## Primary Model

- **Model Name**: `DeepSeek r1 distill qwen 32b`
- **Deployment**: Local inference via **LmStudio**.
- **Reason for Choice**:
  - Strong instruction-following capabilities.
  - Specialized in code understanding and generation.
  - Efficient enough to run on local hardware (Quantized).

## Model Usage by Service

### 1. Analysis Service (Triage)

- **Task**: Binary Classification (TP vs FP).
- **Input**: Vulnerability description, Rule ID, Code Snippet (+/- 5 lines).
- **Prompt Strategy**: Chain-of-Thought (CoT) prompting to ask the model to explain *why* code is vulnerable before giving a verdict.

### 2. Remediation Service (Fixing)

- **Task**: Code Generation (Infilling/Replacement).
- **Input**: Vulnerable code, Vulnerability classification.
- **Output**: A precise code patch (diff) to fix the issue without altering logic.

### 3. Red Team / Sandbox (Verification)

- **Task**: Script Generation.
- **Input**: Vulnerability details.
- **Output**: A standalone Python script (PoC) that attempts to trigger the vulnerability (e.g., sending a payload to an endpoint).

## Configuration

The model settings can be tuned in the `.env` file:

```ini
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_MODEL=deepseek-coder-v2-lite
LLM_TEMPERATURE=0.1  # Low temperature for deterministic outputs
LLM_MAX_TOKENS=2048
```

## Training & Feedback

The system includes a Feedback Loop (RLHF foundation). User feedback on the dashboard ("This is False Positive") is stored in the database and can be exported to fine-tune future versions of the model for domain-specific accuracy.
