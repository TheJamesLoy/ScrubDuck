#!/usr/bin/env python3
"""
ScrubDuck CLI - The Unified Entry Point
=======================================
Orchestrates the Code Engine (AST) and Data Engine (Regex/NLP) 
to provide a Risk Assessment and Sanitization workflow.

Usage:
  python scrubduck_cli.py my_code.py --dry-run
  python scrubduck_cli.py server.log --dry-run
"""

import argparse
import sys
import json
import os
from typing import List, Dict, Tuple

# Import engines
try:
    import scrubduck
    import doc_ducky
except ImportError:
    print("Error: Could not import engines. Make sure scrubduck.py and doc_ducky.py are in the same folder.")
    sys.exit(1)

class ScrubDuckCLI:
    def __init__(self):
        self.code_engine = scrubduck.ContextAwareSanitizer()
        self.doc_engine = doc_ducky.DocScrubber()

    def detect_type(self, filepath: str) -> str:
        """Determines if the file is 'code' or 'document'."""
        ext = os.path.splitext(filepath)[1].lower()
        if ext in ['.py']:
            return 'CODE'
        return 'DOC'

    def calculate_risk(self, findings: List[Dict]) -> Tuple[str, int]:
        """Calculates a Risk Score (0-100) and Label based on findings."""
        score = 0
        weights = {
            "AWS_KEY": 50,
            "STRIPE_KEY": 50,
            "SECRET_VAR_ASSIGNMENT": 40,
            "CREDIT_CARD_REGEX": 40,
            "HIGH_ENTROPY_SECRET": 30,
            "US_SSN": 30,
            "AUTH_BEARER": 25,
            "EMAIL_ADDRESS": 10,
            "PERSON": 5,
            "IPV4": 5,
            "LOCATION": 5
        }

        for f in findings:
            # Handle list vs dict structure from different engines
            label = f.get('label') if isinstance(f, dict) else f[2]
            score += weights.get(label, 5)

        # Normalize Score
        if score == 0: return "SAFE", 0
        if score < 20: return "LOW", score
        if score < 50: return "MEDIUM", score
        if score < 100: return "HIGH", score
        return "CRITICAL", score

    def run_analysis(self, filepath: str):
        """Runs a Dry Run analysis and prints a report."""
        file_type = self.detect_type(filepath)
        print(f"\n🦆 ScrubDuck Analysis: {filepath} [{file_type} Mode]")
        print("=" * 60)

        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if file_type == 'CODE':
                # Code engine returns tuples: (start, end, label)
                raw_findings = self.code_engine.scan_only(content)
                # Normalize to dicts
                findings = [{"label": f[2], "snippet": content[f[0]:f[1]]} for f in raw_findings]
            else:
                # Doc engine handles PDF extraction internally if needed
                if filepath.endswith('.pdf'):
                    content = self.doc_engine.extract_text(filepath)
                
                # Doc engine returns dicts: {label, snippet, ...}
                findings = self.doc_engine.scan_only(content)

        except Exception as e:
            print(f"Error reading file: {e}")
            return

        # Generate Report
        risk_label, risk_score = self.calculate_risk(findings)
        
        # Color codes (if supported)
        RED = "\033[91m"
        GREEN = "\033[92m"
        RESET = "\033[0m"
        color = RED if risk_score > 50 else GREEN

        print(f"Risk Level: {color}{risk_label} (Score: {risk_score}){RESET}")
        print(f"Total Issues Found: {len(findings)}\n")

        if len(findings) > 0:
            print(f"{'TYPE':<25} | {'CONTENT (Truncated)':<30}")
            print("-" * 60)
            for f in findings[:10]: # Show top 10
                label = f['label']
                snippet = f['snippet'].replace('\n', ' ').strip()
                if len(snippet) > 27: snippet = snippet[:27] + "..."
                print(f"{label:<25} | {snippet:<30}")
            
            if len(findings) > 10:
                print(f"... and {len(findings) - 10} more.")
        else:
            print("No sensitive data found. This file looks safe! ✅")
        
        print("\nTo sanitize this file, run:")
        print(f"  python scrubduck_cli.py {filepath} --scrub")

    def run_scrub(self, filepath: str, output_path: str = None):
        """Runs the actual sanitization."""
        file_type = self.detect_type(filepath)
        
        # Logic to call the correct engine's sanitize/scrub method
        # (Reusing existing CLI logic via subprocess or direct call)
        # For MVP, we point the user to the specific script
        if file_type == 'CODE':
            print(f"Running Code Sanitizer on {filepath}...")
            # Direct call to engine
            with open(filepath, 'r') as f: content = f.read()
            clean = self.code_engine.sanitize(content)
            print("\n[SANITIZED OUTPUT]\n")
            print(clean)
        else:
            print(f"Running Doc Scrubber on {filepath}...")
            content = self.doc_engine.extract_text(filepath)
            clean = self.doc_engine.scrub(content)
            print("\n[SCRUBBED OUTPUT]\n")
            print(clean)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ScrubDuck: The AI Data Airlock")
    parser.add_argument("file", help="Path to file")
    parser.add_argument("--dry-run", action="store_true", help="Analyze risk without modifying file")
    parser.add_argument("--scrub", action="store_true", help="Sanitize the file")
    
    args = parser.parse_args()
    cli = ScrubDuckCLI()

    if args.dry_run:
        cli.run_analysis(args.file)
    elif args.scrub:
        cli.run_scrub(args.file)
    else:
        # Default behavior: Dry Run
        cli.run_analysis(args.file)