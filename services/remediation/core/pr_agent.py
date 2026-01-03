"""
GitHub PR Agent Service.

Handles the creation of git branches, commits, and Pull Requests to automate
remediation of security findings.
"""

import os
import time
from github import Github
from common.core.logger import get_logger

logger = get_logger(__name__)

def create_consolidated_pr(repo_name, branch_name, file_updates, issue_summary):
    """
    Creates or updates a single Pull Request containing multiple file updates.
    
    OPTIMIZATION: Uses a stable branch name if provided, or defaults to the passed one.
    If the branch exists, it appends commits. If a PR exists, it updates it.
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        logger.error("GITHUB_TOKEN not found")
        raise ValueError("GITHUB_TOKEN environment variable is not set")
        
    logger.info(f"🚀 Agent: process started for {repo_name}. Fixes: {len(file_updates)}")
    
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        
        # 1. Determine Base Branch
        base_branch = "main"
        try:
            source = repo.get_branch(base_branch)
        except:
            base_branch = "master"
            source = repo.get_branch(base_branch)
            
        # 2. Handle Feature Branch (Reuse if exists)
        # Use a stable branch name to prevent spamming
        STABLE_BRANCH = "ai-security-fixes"
        branch_name = STABLE_BRANCH 
        
        try:
            # Check if branch exists
            repo.get_branch(branch_name)
            logger.info(f"🌿 Branch {branch_name} already exists. Appending to it.")
        except:
            # Create if it doesn't exist
            logger.info(f"🌿 Creating new branch {branch_name} from {base_branch}...")
            repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=source.commit.sha)
        
        # 3. Apply all updates
        for update in file_updates:
            fpath = update['path']
            try:
                # Get current file SHA (if it exists on the branch)
                try:
                    contents = repo.get_contents(fpath, ref=branch_name)
                    logger.info(f"💾 Updating {fpath}...")
                    repo.update_file(
                        path=fpath,
                        message=f"🛡️ AI Fix: {update['message']}",
                        content=update['content'],
                        sha=contents.sha,
                        branch=branch_name
                    )
                except:
                    # File might be new or not on this branch yet
                    logger.info(f"💾 Creating {fpath}...")
                    repo.create_file(
                        path=fpath,
                        message=f"🛡️ AI Fix: {update['message']}",
                        content=update['content'],
                        branch=branch_name
                    )
            except Exception as e:
                logger.error(f"⚠️ Could not update {fpath}: {e}")
                
        # 4. Check for existing PR
        existing_pr = None
        open_prs = repo.get_pulls(state='open', head=f"{repo.owner.login}:{branch_name}")
        for pr in open_prs:
            existing_pr = pr
            break
            
        # 5. Create or Comment on PR
        body = _generate_pr_body(file_updates)
        
        if existing_pr:
            logger.info(f"🔄 Updating existing PR #{existing_pr.number}")
            existing_pr.create_issue_comment(f"**🔄 AI Agent Update**: Added {len(file_updates)} new fixes.\n\n{body}")
            return existing_pr.html_url
        else:
            logger.info(f"📝 Opening new Consolidated PR...")
            pr = repo.create_pull(
                title=f"🛡️ AI Security Fixes (Consolidated)",
                body=body,
                head=branch_name,
                base=base_branch
            )
            logger.info(f"✅ PR CREATED: {pr.html_url}")
            return pr.html_url

    except Exception as e:
        logger.error(f"❌ Agent Error: {e}")
        raise e

def _generate_pr_body(file_updates):
    body = "## 🤖 AI Security Agent Report\n\nThis PR consolidates the following security fixes:\n\n"
    from collections import defaultdict
    grouped = defaultdict(list)
    for u in file_updates:
        grouped[u['path']].append(u)
        
    for fpath, updates in grouped.items():
        body += f"### 📄 {fpath}\n"
        for u in updates:
            body += f"- **Issue:** {u['message']}\n"
            if u.get('red_team_success'):
                body += f"  - 🧪 **Verified Exploit:**\n    ```bash\n    {u.get('red_team_output', '').strip()}\n    ```\n"
            elif u.get('red_team_output'):
                 body += f"  - ⚠️ **Exploit Attempt Failed:**\n    ```bash\n    {u.get('red_team_output', '').strip()}\n    ```\n"
        body += "\n"
    return body

# Helper to maintain backward compatibility if needed, though mostly unused now
def create_security_pr(repo_name, branch_name, patch_content, file_path, issue_message, temp_dir=None):
    # Just redirect to consolidated for now or implement similar reuse log if needed
    pass