CREATE TABLE scans (
	id INTEGER NOT NULL, 
	project_name VARCHAR, 
	commit_sha VARCHAR, 
	timestamp DATETIME, 
	PRIMARY KEY (id)
);
CREATE INDEX ix_scans_commit_sha ON scans (commit_sha);
CREATE INDEX ix_scans_id ON scans (id);
CREATE INDEX ix_scans_project_name ON scans (project_name);
CREATE TABLE findings (
	id INTEGER NOT NULL, 
	scan_id INTEGER, 
	triage_decision VARCHAR, 
	sandbox_logs TEXT, 
	tool VARCHAR, 
	rule_id VARCHAR, 
	file VARCHAR, 
	line INTEGER, 
	message TEXT, 
	snippet TEXT, 
	ai_verdict VARCHAR, 
	ai_confidence FLOAT, 
	ai_reasoning TEXT, 
	risk_score FLOAT, 
	severity VARCHAR, 
	remediation_patch TEXT, 
	red_team_success BOOLEAN, 
	red_team_output TEXT, 
	pr_url VARCHAR, 
	pr_error VARCHAR, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id)
);
CREATE INDEX ix_findings_id ON findings (id);
CREATE TABLE pipeline_metrics (
	id INTEGER NOT NULL, 
	scan_id INTEGER, 
	build_duration_seconds FLOAT, 
	artifact_size_bytes INTEGER, 
	num_changed_files INTEGER, 
	test_coverage_percent FLOAT, 
	timestamp DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id)
);
CREATE INDEX ix_pipeline_metrics_id ON pipeline_metrics (id);
CREATE TABLE feedbacks (
	id INTEGER NOT NULL, 
	finding_id INTEGER, 
	user_verdict VARCHAR, 
	comments TEXT, 
	timestamp DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id)
);
CREATE INDEX ix_feedbacks_id ON feedbacks (id);
