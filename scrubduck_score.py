#!/usr/bin/env python3
"""
ScrubDuck Score - The Unified Entry Point
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
import yaml
from typing import List, Dict, Tuple

try:
    import scrubduck
    import doc_ducky
except ImportError:
    print("Error: Could not import engines. Make sure scrubduck.py and doc_ducky.py are in the same folder.")
    sys.exit(1)

class ScrubDuckCLI:
    def __init__(self):
        self.config = self.load_config()
        # Initialize engines WITH config
        self.code_engine = scrubduck.ContextAwareSanitizer(config=self.config)
        self.doc_engine = doc_ducky.DocScrubber(config=self.config)

    def load_config(self) -> Dict:
        """Loads .scrubduck.yaml from current directory or home directory."""
        paths = [
            os.path.join(os.getcwd(), '.scrubduck.yaml'),
            os.path.join(os.path.expanduser("~"), '.scrubduck.yaml')
        ]
        
        for p in paths:
            if os.path.exists(p):
                try:
                    with open(p, 'r') as f:
                        config = yaml.safe_load(f)
                        print(f"🦆 Loaded configuration from: {p}")
                        return config or {}
                except Exception as e:
                    print(f"⚠️ Error loading config {p}: {e}")
        
        return {}

    def detect_type(self, filepath: str) -> str:
        ext = os.path.splitext(filepath)[1].lower()
        if ext in ['.py']:
            return 'CODE'
        return 'DOC'

    def calculate_risk(self, findings: List[Dict]) -> Tuple[str, int]:
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
        
        # Add weights for custom rules if present
        if 'custom_rules' in self.config:
            for rule in self.config['custom_rules']:
                if 'score' in rule:
                    weights[rule['name']] = rule['score']

        for f in findings:
            label = f.get('label') if isinstance(f, dict) else f[2]
            score += weights.get(label, 5)

        if score == 0: return "SAFE", 0
        if score < 20: return "LOW", score
        if score < 50: return "MEDIUM", score
        if score < 100: return "HIGH", score
        return "CRITICAL", score

    def run_analysis(self, filepath: str):
        file_type = self.detect_type(filepath)
        print(f"\n🦆 ScrubDuck Analysis: {filepath} [{file_type} Mode]")
        print("=" * 60)

        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if file_type == 'CODE':
                raw_findings = self.code_engine.scan_only(content)
                findings = [{"label": f[2], "snippet": content[f[0]:f[1]]} for f in raw_findings]
            else:
                if filepath.endswith('.pdf'):
                    content = self.doc_engine.extract_text(filepath)
                findings = self.doc_engine.scan_only(content)

        except Exception as e:
            print(f"Error reading file: {e}")
            return

        risk_label, risk_score = self.calculate_risk(findings)
        
        RED = "\033[91m"
        GREEN = "\033[92m"
        RESET = "\033[0m"
        color = RED if risk_score > 50 else GREEN

        print(f"Risk Level: {color}{risk_label} (Score: {risk_score}){RESET}")
        print(f"Total Issues Found: {len(findings)}\n")

        if len(findings) > 0:
            print(f"{'TYPE':<25} | {'CONTENT (Truncated)':<30}")
            print("-" * 60)
            for f in findings[:10]: 
                label = f['label']
                snippet = f['snippet'].replace('\n', ' ').strip()
                if len(snippet) > 27: snippet = snippet[:27] + "..."
                print(f"{label:<25} | {snippet:<30}")
            
            if len(findings) > 10:
                print(f"... and {len(findings) - 10} more.")
        else:
            print("No sensitive data found. This file looks safe! ✅")
        
        print("\nTo sanitize this file, run:")
        print(f"  python scrubduck_score.py {filepath} --scrub")

    def run_scrub(self, filepath: str, output_path: str = None):
        file_type = self.detect_type(filepath)
        
        if file_type == 'CODE':
            print(f"Running ScrubDuck on {filepath}...")
            with open(filepath, 'r') as f: content = f.read()
            clean = self.code_engine.sanitize(content)
            print("\n[SANITIZED OUTPUT]\n")
            print(clean)
        else:
            print(f"Running Doc Ducky on {filepath}...")
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
        cli.run_analysis(args.file)