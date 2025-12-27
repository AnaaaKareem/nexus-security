#!/bin/bash
# Get the directory of the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR/.."

# Send a test request with SARIF findings and Anomaly Metrics

# Create a dummy SARIF file
echo '{
  "runs": [{
    "tool": { "driver": { "name": "Semgrep" } },
    "results": [{
      "ruleId": "python.lang.security.audit.dangerous-system-call",
      "message": { "text": "Potential Command Injection" },
      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "app.py" } } }]
    }]
  }]
}' > dummy_report.sarif

echo "📡 Sending Request to http://localhost:8000/triage..."

curl -X POST "http://localhost:8000/triage" \
  -H "X-API-Key: AIzaSyCnWtbs7fO1F-FGuH4ianAGQ7siF0dnHrw" \
  -F "project=test/live-demo" \
  -F "sha=HEAD" \
  -F "token=AIzaSyCnWtbs7fO1F-FGuH4ianAGQ7siF0dnHrw" \
  -F "files=@dummy_report.sarif" \
  -F "build_duration=120.0" \
  -F "artifact_size=55000000" \
  -F "changed_files=3" \
  -F "test_coverage=85.0"

echo -e "\n✅ Request Sent!"
rm dummy_report.sarif
