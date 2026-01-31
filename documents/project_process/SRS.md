# Software Requirements Specification (SRS)

## 1. Introduction

### 1.1 Purpose

The purpose of the Universal Security Brain is to reduce the "noise" of traditional security scanners by using AI to triage findings and automate remediation.

### 1.2 Scope

The system covers Static Application Security Testing (SAST), Secret Scanning, and Infrastructure-as-Code (IaC) scanning.

## 2. Functional Requirements

### 2.1 Ingestion

- **FR-01**: The system MUST accept SARIF file uploads.
- **FR-02**: The system MUST support direct source code uploads (ZIP).
- **FR-03**: The system MUST provide an API endpoint for CI/CD integration.

### 2.2 Analysis (Triage)

- **FR-04**: The system MUST use an LLM to analyze every "High" and "Critical" finding.
- **FR-05**: The system MUST classify findings as True Positive (TP) or False Positive (FP).
- **FR-06**: The system MUST persist the LLM's reasoning for auditability.

### 2.3 Remediation

- **FR-07**: For confirmed TPs, the system MUST generate a valid code patch.
- **FR-08**: The system MUST validate that the patch allows the code to compile/parse (Basic Syntax Check).

### 2.4 User Interface

- **FR-09**: Users MUST be able to view scan status in real-time.
- **FR-10**: Users MUST be able to provide feedback on AI verdicts.

## 3. Non-Functional Requirements

### 3.1 Performance

- **NFR-01**: Scan ingestion response time MUST be < 2 seconds.
- **NFR-02**: AI Analysis per finding MUST complete within 30 seconds (on recommended hardware).

### 3.2 Security

- **NFR-03**: API calls MUST be authenticated via API Key.
- **NFR-04**: Source code MUST be deleted from the temp directory after processing.

### 3.3 Reliability

- **NFR-05**: The specific Orchestrator Worker MUST automatically retry failed jobs at least once.
