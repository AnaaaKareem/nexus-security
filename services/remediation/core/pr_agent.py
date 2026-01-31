"""
GitHub PR Agent Service.

Handles the creation of git branches, commits, and Pull Requests to automate
remediation of security findings.
"""

import time
from github import Github, GithubException
from common.core.logger import get_logger

# Import from Vault secrets module (falls back to env vars if Vault unavailable)
from common.core.secrets import get_github_token

logger = get_logger(__name__)

from core.gitlab_agent import create_consolidated_mr_gitlab

def create_consolidated_pr(repo_name, branch_name, file_updates, issue_summary, provider="github"):
    """
    Creates or updates a single Pull/Merge Request containing multiple file updates.
    
    OPTIMIZATION: Uses a stable branch name if provided, or defaults to the passed one.
    If the branch exists, it appends commits. If a PR exists, it updates it.
    
    Args:
        provider (str): 'github' or 'gitlab' (default: 'github')
    """
    if provider and provider.lower() in ["gitlab", "gitlab-ci"]:
        return create_consolidated_mr_gitlab(repo_name, branch_name, file_updates, issue_summary)

    token = get_github_token()
    if not token:
        logger.error("GITHUB_TOKEN not found in Vault or environment")
        raise ValueError("GITHUB_TOKEN is not set in Vault or environment variables")
        
    logger.info(f"🚀 Agent: process started for {repo_name}. Fixes: {len(file_updates)}")
    
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        
        # Step 1: Determine base branch (main or master)
        base_branch = "main"
        try:
            source = repo.get_branch(base_branch)
        except:
            base_branch = "master"  # Fallback for older repos
            source = repo.get_branch(base_branch)
            
        # Step 2: Create or reuse feature branch
        if not branch_name:
            branch_name = "ai-security-fixes"  # Stable default branch for all AI fixes
        
        try:
            # Check if branch already exists
            repo.get_branch(branch_name)
            logger.info(f"🌿 Branch {branch_name} already exists. Appending to it.")
        except:
            # Create new branch from base
            logger.info(f"🌿 Creating new branch {branch_name} from {base_branch}...")
            repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=source.commit.sha)
        
        # Step 3: Apply all file updates to the branch
        for update in file_updates:
            fpath = update['path']
            # Retry loop for handling 409 Conflict (SHA race condition)
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # Try to get current file (to get its SHA for update)
                    try:
                        contents = repo.get_contents(fpath, ref=branch_name)
                        # File exists - update it
                        logger.info(f"💾 Updating {fpath} (Attempt {attempt+1})...")
                        repo.update_file(
                            path=fpath,
                            message=f"🛡️ AI Fix: {update['message']}",
                            content=update['content'],
                            sha=contents.sha,  # Required for update
                            branch=branch_name
                        )
                        break  # Success, exit retry loop
                    except GithubException as e:
                        if e.status == 404:
                            # File doesn't exist - create it
                            logger.info(f"💾 Creating {fpath}...")
                            repo.create_file(
                                path=fpath,
                                message=f"🛡️ AI Fix: {update['message']}",
                                content=update['content'],
                                branch=branch_name
                            )
                            break  # Success
                        elif e.status == 409:
                            # SHA conflict - retry after short delay
                            logger.warning(f"⚠️ Conflict (409) updating {fpath}. Retrying ({attempt+1}/{max_retries})...")
                            time.sleep(1)
                            continue
                        else:
                            raise e
                except Exception as e:
                    if attempt == max_retries - 1:
                        logger.error(f"⚠️ Could not update {fpath} after retries: {e}")
                    else:
                        logger.warning(f"Error updating {fpath}: {e}")
                
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
    """
    Generates a markdown body for the consolidated Pull Request.
    Includes a table of contents or list of all fixed issues, grouped by file.
    Also includes Red Team verification logs if available.

    Args:
        file_updates (list): List of file update dictionaries.

    Returns:
        str: Markdown formatted PR description.
    """
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
    """
    Creates a Pull Request for a single security fix.
    
    Legacy wrapper that routes to create_consolidated_pr to ensure all fixes
    go to the shared STABLE_BRANCH (ai-security-fixes).
    """
    logger.info(f"🔄 Routing legacy create_security_pr for {file_path} to create_consolidated_pr")
    
    # Construct a single file update object
    file_updates = [{
        "path": file_path,
        "content": patch_content,
        "message": issue_message
    }]
    
    # Delegate to the consolidated handler
    # Note: create_consolidated_pr will override branch_name with STABLE_BRANCH
    return create_consolidated_pr(repo_name, branch_name, file_updates, issue_message, provider="github")

def create_pr_for_fix(finding, project, branch="main"):
    """
    Wrapper to align with main.py expectation.
    extracts patch and details from finding dict.
    """
    file_path = finding.get("file")
    # Try different keys for the fix content
    patch = finding.get("fix") or finding.get("generated_fix") or finding.get("patch")
    message = finding.get("message", "Fix security vulnerability")
    
    if not patch:
        # Fallback for testing or if patch is somehow in 'content'
        if "content" in finding: patch = finding["content"]
        else: raise ValueError(f"No fix content provided for {file_path}")

    return create_security_pr(project, branch, patch, file_path, message)