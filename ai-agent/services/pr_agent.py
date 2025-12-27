"""
GitHub PR Agent Service.

Handles the creation of git branches, commits, and Pull Requests to automate
remediation of security findings.
"""

import os
from github import Github

def create_security_pr(repo_name, branch_name, patch_content, file_path, issue_message, temp_dir=None):
    """
    Creates a Pull Request in the target repository using the PyGithub API.
    
    This implementation creates the branch, commits the change, and opens the PR
    entirely via the GitHub API, creating a robust implementation that doesn't 
    depend on local git configuration.

    Args:
        repo_name (str): The repository full name (owner/repo).
        branch_name (str): The name of the new branch.
        patch_content (str): The corrected file content.
        file_path (str): The path to the file being patched.
        issue_message (str): The description of the issue for commit message and PR body.
        temp_dir (str, optional): Deprecated. Not used in API-based approach.

    Returns:
        str: The URL of the created Pull Request.
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN environment variable is not set")

    print(f"🚀 Agent: Starting PR creation via PyGithub for {repo_name}...")

    try:
        # 1. Initialize PyGithub
        g = Github(token)
        repo = g.get_repo(repo_name)
        
        # 2. Get the default branch (usually main or master) to base our work on
        # We try 'main' first, but query the repo to be sure if possible. 
        # For simplicity in this logic, we assume 'main' as per original code, 
        # but we could fetch repo.default_branch
        base_branch = "main" 
        try:
            source = repo.get_branch(base_branch)
        except:
            base_branch = "master"
            source = repo.get_branch(base_branch)

        # 3. Create a new branch (reference)
        ref = f"refs/heads/{branch_name}"
        print(f"🌿 Agent: Creating branch {branch_name} from {base_branch}...")
        repo.create_git_ref(ref=ref, sha=source.commit.sha)

        # 4. Get the file to update (we need its sha to update it)
        try:
            contents = repo.get_contents(file_path, ref=branch_name)
            
            # 5. Update the file (Commit)
            print(f"💾 Agent: Committing fix to {file_path}...")
            repo.update_file(
                path=file_path,
                message=f"🛡️ AI Fix: {issue_message}",
                content=patch_content,
                sha=contents.sha,
                branch=branch_name
            )
        except Exception as e:
            # Handle case where file might not exist or other API error
            print(f"❌ Error updating file: {e}")
            raise e

        # 6. Create the Pull Request
        print(f"📝 Agent: Opening Pull Request...")
        pr = repo.create_pull(
            title=f"🛡️ AI Security Fix: {issue_message}",
            body=f"## 🤖 AI Security Agent Report\n**Vulnerability:** {issue_message}\n\nReview fix for `{file_path}`.",
            head=branch_name,
            base=base_branch
        )
        
        url = pr.html_url
        print(f"✅ PR CREATED: {url}")
        return url

    except Exception as e:
        print(f"❌ Agent Error (PyGithub): {e}")
        raise e

def create_consolidated_pr(repo_name, branch_name, file_updates, issue_summary):
    """
    Creates a single Pull Request containing multiple file updates.

    Args:
        repo_name (str): The repository full name.
        branch_name (str): The name of the new branch.
        file_updates (list): List of dicts: {'path': str, 'content': str, 'message': str}
        issue_summary (str): Summary for the PR title/body.

    Returns:
        str: The URL of the created Pull Request.
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN environment variable is not set")
        
    print(f"🚀 Agent: Creating consolidated PR for {len(file_updates)} fixes...")
    
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        
        # 1. Get Base Branch
        base_branch = "main"
        try:
            source = repo.get_branch(base_branch)
        except:
            base_branch = "master"
            source = repo.get_branch(base_branch)
            
        # 2. Create Branch
        ref = f"refs/heads/{branch_name}"
        print(f"🌿 Agent: Creating branch {branch_name}...")
        repo.create_git_ref(ref=ref, sha=source.commit.sha)
        
        # 3. Apply all updates
        for update in file_updates:
            fpath = update['path']
            try:
                # Try to get file to see if it exists (for update vs create)
                # Note: This logic assumes update, but handling create if needed would be similar
                contents = repo.get_contents(fpath, ref=branch_name)
                print(f"💾 Agent: Updating {fpath}...")
                repo.update_file(
                    path=fpath,
                    message=f"🛡️ AI Fix: {update['message']}",
                    content=update['content'],
                    sha=contents.sha,
                    branch=branch_name
                )
            except Exception as e:
                print(f"⚠️ Could not update {fpath}: {e}")
                
        # 4. Create PR
        print(f"📝 Agent: Opening Consolidated PR...")
        body = "## 🤖 AI Security Agent Report\n\nThis PR consolidates the following security fixes:\n\n"
        
        # Group updates by file path
        from collections import defaultdict
        grouped_updates = defaultdict(list)
        for update in file_updates:
            grouped_updates[update['path']].append(update)
            
        for fpath, updates in grouped_updates.items():
            # Sort findings within the file by risk_score (descending)
            updates.sort(key=lambda x: x.get('risk_score', 0), reverse=True)

        # Sort files by their highest risk score
        sorted_files = sorted(grouped_updates.items(), 
                              key=lambda item: max([u.get('risk_score', 0) for u in item[1]]), 
                              reverse=True)
            
        for fpath, updates in sorted_files:
            body += f"### 📄 {fpath}\n"
            for u in updates:
                line_str = f"Line {u.get('line', 'N/A')}"
                sev_str = f" ({u.get('severity', 'Unknown')})" if u.get('severity') else ""
                body += f"- **{line_str}**: {u['message']}{sev_str}\n"
            body += "\n"
            
        print("-" * 40)
        print("📝 GENERATED PR BODY:")
        print(body)
        print("-" * 40)

        pr = repo.create_pull(
            title=f"🛡️ Consolidated Security Fixes ({len(file_updates)})",
            body=body,
            head=branch_name,
            base=base_branch
        )
        
        print(f"✅ CONSOLIDATED PR CREATED: {pr.html_url}")
        return pr.html_url

    except Exception as e:
        print(f"❌ Agent Error (Consolidated PR): {e}")
        raise e