# User Manual: Universal Security Brain

## 1. Introduction

This manual guides you through using the **Universal Security Brain Dashboard** to monitor and manage security vulnerabilities in your codebase.

## 2. Accessing the Dashboard

Open your web browser and navigate to:
**[http://localhost:8001](http://localhost:8001)**

## 3. Dashboard Overview

### The Home Screen

The home screen provides a high-level view of your security posture.

- **Active Scans**: Shows scans currently in progress.
- **Recent Activity**: A list of completed scans sorted by date.
- **Risk Score**: A dynamic score representing the aggregate risk of your projects.

### Starting a New Scan

1. Click the **"New Scan"** button in the top navigation.
2. Enter the **Project Name** (e.g., `my-team/backend-service`).
3. (Optional) Provide the **Git Connect URL** if the system can clone it directly.
4. **Upload Source**: Alternatively, drag and drop a ZIP file of your source code.
5. Click **"Start Scan"**.
   - You will see a notification: "Scan Queued".

## 4. Viewing Results

### The Scan Detail Page

Click on any scan in the list to view details.

- **Vulnerability Table**: Lists all detected issues.
  - **Severity**: Red (Critical), Orange (High), Yellow (Medium).
  - **Tool**: Which scanner found it (e.g., Semgrep).
  - **AI Verdict**: The Brain's analysis.
    - **TP (True Positive)**: Confirmed vulnerability.
    - **FP (False Positive)**: Likely a false alarm.

### Reviewing AI Decisions

1. Click on a finding row to expand it.
2. Read the **AI Reasoning**: The model explains why it flagged this code.
3. Check the **Code Snippet**: See the vulnerability in context.
4. **Feedback**:
   - Click **"Confirm TP"** if you agree (helps train the model).
   - Click **"Mark as FP"** if the AI is wrong.

## 5. Applying Fixes

For valid vulnerabilities, the AI generates a fix.

1. Look for the **"View Patch"** button.
2. A modal will show the `diff` (Old Code vs. New Code).
3. (Future Feature) Click "Create PR" to automatically apply this fix to your repository.
