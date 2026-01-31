"""
GitLab MR Agent Service.

Handles the creation of git branches, commits, and Merge Requests (MRs) to automate
remediation of security findings on GitLab.
"""

import time
from typing import Optional, List, Dict, Any
import gitlab
from gitlab.v4.objects import Project, ProjectMergeRequest
from gitlab.exceptions import GitlabError, GitlabGetError, GitlabCreateError

from common.core.logger import get_logger
from common.core.secrets import get_gitlab_token

logger = get_logger(__name__)

def create_consolidated_mr_gitlab(repo_name, branch_name, file_updates, issue_summary):
    """
    Creates or updates a single Merge Request containing multiple file updates on GitLab.
    
    Args:
        repo_name (str): Project path/ID (e.g. 'group/project' or '123')
        branch_name (str): The target feature branch name (will be created if missing)
        file_updates (list): List of dicts {path, content, message}
        issue_summary (str): Summary for the MR description
        
    Returns:
        str: The web URL of the created/updated Merge Request
    """
    token = get_gitlab_token()
    if not token:
        logger.error("GITLAB_TOKEN not found in environment")
        raise ValueError("GITLAB_TOKEN is not set in environment variables")
        
    # Default togitlab.com if GITLAB_URL not set (assumed logic, can be extended)
    # Ideally should come from config, but keeping simple as per secrets.py
    gl = gitlab.Gitlab(private_token=token)
    
    logger.info(f"🚀 GitLab Agent: process started for {repo_name}. Fixes: {len(file_updates)}")
    
    try:
        # Get Project
        try:
            project = gl.projects.get(repo_name)
        except GitlabGetError:
            # Maybe it's a numeric ID passed as string
            if repo_name.isdigit():
                 project = gl.projects.get(int(repo_name))
            else:
                raise

        # Step 1: Determine base branch (default_branch attribute)
        base_branch = project.default_branch or 'main'
            
        # Step 2: Create or reuse feature branch
        if not branch_name:
            branch_name = "ai-security-fixes"
        
        try:
            project.branches.get(branch_name)
            logger.info(f"🌿 Branch {branch_name} already exists. Appending to it.")
        except GitlabGetError:
            # Create new branch from base
            logger.info(f"🌿 Creating new branch {branch_name} from {base_branch}...")
            project.branches.create({
                'branch': branch_name,
                'ref': base_branch
            })
        
        # Step 3: Apply all file updates to the branch
        for update in file_updates:
            fpath = update['path']
            content = update['content']
            message = f"🛡️ AI Fix: {update['message']}"
            
            try:
                # check if file exists
                f = project.files.get(file_path=fpath, ref=branch_name)
                # Update file
                logger.info(f"💾 Updating {fpath}...")
                f.content = content
                f.save(branch=branch_name, commit_message=message, encoding='text')
                
            except GitlabGetError:
                # File doesn't exist - create it
                logger.info(f"💾 Creating {fpath}...")
                project.files.create({
                    'file_path': fpath,
                    'branch': branch_name,
                    'content': content,
                    'commit_message': message,
                    'encoding': 'text'
                })
            except Exception as e:
                 logger.error(f"⚠️ Error updating {fpath}: {e}")

        # 4. Check for existing MR
        existing_mr = None
        mrs = project.mergerequests.list(state='opened', source_branch=branch_name, target_branch=base_branch)
        if mrs:
            existing_mr = mrs[0]
            
        # 5. Create or Update MR
        body = _generate_mr_body(file_updates)
        
        if existing_mr:
            logger.info(f"🔄 Updating existing MR !{existing_mr.iid}")
            existing_mr.notes.create({'body': f"**🔄 AI Agent Update**: Added {len(file_updates)} new fixes.\n\n{body}"})
            return existing_mr.web_url
        else:
            logger.info(f"📝 Opening new Consolidated MR...")
            mr = project.mergerequests.create({
                'source_branch': branch_name,
                'target_branch': base_branch,
                'title': f"🛡️ AI Security Fixes (Consolidated)",
                'description': body
            })
            logger.info(f"✅ MR CREATED: {mr.web_url}")
            return mr.web_url

    except Exception as e:
        logger.error(f"❌ GitLab Agent Error: {e}")
        raise e

def _generate_mr_body(file_updates):
    """
    Generates a markdown body for the Merge Request.
    """
    body = "## 🤖 AI Security Agent Report\n\nThis MR consolidates the following security fixes:\n\n"
    from collections import defaultdict
    grouped = defaultdict(list)
    for u in file_updates:
        grouped[u['path']].append(u)
        
    for fpath, updates in grouped.items():
        body += f"### 📄 {fpath}\n"
        for u in updates:
            body += f"- **Issue:** {u['message']}\n"
            # Red team output logic (omitted for brevity, same as PR agent)
        body += "\n"
    return body
