import os

def populate_snippets(findings: list, source_root: str):
    """
    Reads the source code for each finding from the disk and adds it to the finding dict.

    Args:
        findings (List[Dict]): The list of findings to update.
        source_root (str): The root directory where the repo is checked out.
    """
    for f in findings:
        # Initialize snippet as None or a clear message to avoid KeyErrors later
        f["snippet"] = "⚠️ Source code not found on local Fedora disk."
        
        path = os.path.join(source_root, f["file"])
        
        if os.path.exists(path):
            try:
                with open(path, 'r', errors='replace') as s:
                    lines = s.readlines()
                    
                    if not lines:
                        f["snippet"] = "⚠️ File is empty."
                        continue

                    # SARIF/Gitleaks lines are 1-based; Python is 0-based
                    actual_line = int(f.get("line", 1)) - 1 
                    
                    # Extract context (5 lines before and after)
                    start = max(0, actual_line - 5)
                    end = min(len(lines), actual_line + 5)
                    
                    extracted_snippet = "".join(lines[start:end])
                    if not extracted_snippet.strip():
                         f["snippet"] = "⚠️ Snippet is empty."
                    else:
                         f["snippet"] = extracted_snippet

            except Exception as e:
                print(f"❌ Could not read file {path}: {e}")
