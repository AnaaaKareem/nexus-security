"""
Data Export Utility for ML Training.

Exports feedback gathered from the AI Agent database into a JSONL format
suitable for fine-tuning LLMs (specifically formatted for Unsloth/Alpaca).
"""

# Import json for serialization
import json
# Import session from sqlalchemy
from sqlalchemy.orm import Session
# Import local database and models modules
from core import database, models

# Define function to export feedback data to JSONL format
def export_to_jsonl(output_file="security_feedback.jsonl"):
    """
    Exports user feedback from the database to a JSON Lines file.

    Query the `feedbacks` table and formats each entry as an instruction-input-output
    object for SFT (Supervised Fine-Tuning).

    Args:
        output_file (str): The path to save the JSONL file.
    """
    # Create a database session
    db = database.SessionLocal()
    # Query all feedback records from the database
    feedbacks = db.query(models.Feedback).all()
    
    # Open the output file in write mode
    with open(output_file, "w") as f:
        # Iterate through each feedback item
        for fb in feedbacks:
            # Access the related finding object
            finding = fb.finding
            
            # Construct entry in Unsloth/Alpaca Format for fine-tuning
            entry = {
                # The instruction provided to the LLM (context + prompt)
                "instruction": f"Analyze this security finding:\nRule: {finding.rule_id}\nMessage: {finding.message}\nCode Snippet:\n{finding.snippet}\n\nIs this a True Positive or a False Positive?",
                # Empty input (instruction contains all context)
                "input": "",
                # The expected output (the user's corrected verdict/comments)
                "output": json.dumps({"verdict": fb.user_verdict, "reason": fb.comments})
            }
            # Write the JSON line to file
            f.write(json.dumps(entry) + "\n")
    
    # Print summary of export
    print(f"Exported {len(feedbacks)} feedback items to {output_file}")

# Main execution block
if __name__ == "__main__":
    export_to_jsonl()