# AI Agents Framework

The system utilizes specialized "Agents" — logical components wrapping an LLM with specific tools and prompts — to perform distinct security tasks.

## 1. Triage Agent (`services/analysis`)

**Goal**: Determine if a finding is a True Positive.

- **Tools**: None (Pure reasoning).
- **Prompt Strategy**:
  - Context: "You are a Senior Security Engineer."
  - Input: Code Snippet + Vulnerability Rule.
  - Output: JSON `{ "verdict": "TP", "confidence": 0.9, "reasoning": "..." }`.
- **Behavior**: It looks for data flow connectivity (taint analysis logic) within the provided snippet.

## 2. Remediation Agent (`services/remediation`)

**Goal**: Fix the code without breaking functionality.

- **Tools**: None (Code generation).
- **Prompt Strategy**:
  - Context: "You are a Secure Code Developer."
  - Input: Vulnerable Code + Fix Requirement.
  - Output: A unified diff or replacement block.
- **safeguards**: The system calculates a diff ratio. If > 50% of the file is changed, the fix is rejected to prevent hallucinations.

## 3. Red Team Agent (Conceptual / In-Sandbox)

**Goal**: Verify exploitability.

- **Tools**: Python Script Execution (Sandbox).
- **Prompt Strategy**:
  - Input: Vulnerability Details.
  - Output: A Python script (`poc.py`).
- **Workflow**:
  1. Agent generates code.
  2. Orchestrator extracts code.
  3. Sandbox executes code.
  4. Success = Exit Code 0.

## 4. Orchestrator (The Manager)

While not an "LLM Agent" itself, the Orchestrator uses **LangGraph** to manage the hand-offs between these agents, effectively acting as the "Meta-Agent" or Controller.
