#!/usr/bin/env python3
"""
ScrubDuck CLI - The Unified Entry Point
=======================================
Orchestrates the Code Engine (AST) and Data Engine (Regex/NLP) 
to provide a Risk Assessment and Sanitization workflow.

Now supports VS Code Extension Protocol via --mode sanitize_json.
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
    sys.stderr.write("Error: Could not import engines. Ensure scrubduck.py and doc_ducky.py are in the same folder.\n")
    sys.exit(1)

class ScrubDuckCLI:
    def __init__(self):
        self.config = self.load_config()
        self.code_engine = scrubduck.ContextAwareSanitizer(config=self.config)
        self.doc_engine = doc_ducky.DocScrubber(config=self.config)

    def load_config(self) -> Dict:
        paths = [
            os.path.join(os.getcwd(), '.scrubduck.yaml'),
            os.path.join(os.path.expanduser("~"), '.scrubduck.yaml')
        ]
        for p in paths:
            if os.path.exists(p):
                try:
                    with open(p, 'r') as f:
                        return yaml.safe_load(f) or {}
                except: pass
        return {}

    def detect_type(self, filepath: str) -> str:
        if not filepath: return 'DOC' # Default to Doc if unknown
        ext = os.path.splitext(filepath)[1].lower()
        if ext in ['.py']:
            return 'CODE'
        return 'DOC'

    def run_extension_sanitize(self, text: str, filepath: str):
        """Handler for VS Code Extension Sanitize Request."""
        file_type = self.detect_type(filepath)
        
        if file_type == 'CODE':
            clean_text = self.code_engine.sanitize(text)
            token_map = self.code_engine.token_map
        else:
            # Determine format for structured data
            ext = os.path.splitext(filepath)[1].lower().replace('.', '')
            if ext in ['js', 'ts', 'yaml', 'yml']: ext = 'txt'
            
            clean_text = self.doc_engine.scrub(text, file_type=ext)
            token_map = self.doc_engine.token_map

        # Return JSON for VS Code
        print(json.dumps({
            "text": clean_text,
            "map": token_map,
            "engine": file_type
        }))

    def run_extension_restore(self, text: str, token_map_str: str):
        """Handler for VS Code Extension Restore Request."""
        # Restore logic is generic (string replacement), so we can use either engine.
        # We use doc_engine as it has the same base restore method.
        try:
            token_map = json.loads(token_map_str)
            restored_text = self.doc_engine.restore(text, external_map=token_map)
            print(json.dumps({"text": restored_text}))
        except Exception as e:
            sys.stderr.write(f"Restore failed: {str(e)}")
            sys.exit(1)

    # --- CLI / Dry Run Methods ---

    def calculate_risk(self, findings: List[Dict]) -> Tuple[str, int]:
        score = 0
        weights = {
            "AWS_KEY": 50, "STRIPE_KEY": 50, "SECRET_VAR_ASSIGNMENT": 40,
            "CREDIT_CARD_REGEX": 40, "HIGH_ENTROPY_SECRET": 30, "US_SSN": 30,
            "AUTH_BEARER": 25, "EMAIL_ADDRESS": 10, "PERSON": 5, "IPV4": 5, "LOCATION": 5
        }
        if 'custom_rules' in self.config:
            for rule in self.config['custom_rules']:
                if 'score' in rule: weights[rule['name']] = rule['score']

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
            if len(findings) > 10: print(f"... and {len(findings) - 10} more.")
        else:
            print("No sensitive data found. This file looks safe! ✅")
        
        print("\nTo sanitize this file, run:")
        if file_type == 'CODE':
            print(f"  python scrubduck.py {filepath}")
        else:
            print(f"  python doc_ducky.py {filepath}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ScrubDuck: The AI Data Airlock")
    parser.add_argument("file", nargs="?", help="Path to file")
    parser.add_argument("--dry-run", action="store_true", help="Analyze risk without modifying file")
    
    # Extension Protocol
    parser.add_argument("--mode", choices=["sanitize_json", "restore_json"], help="VS Code Mode")
    parser.add_argument("--filepath", help="Original filename (for type detection)")
    parser.add_argument("--map", help="JSON Token Map")

    args = parser.parse_args()
    cli = ScrubDuckCLI()

    if args.mode == "sanitize_json":
        try:
            text = sys.stdin.read()
            cli.run_extension_sanitize(text, args.filepath or "")
        except Exception as e:
            sys.stderr.write(str(e))
            sys.exit(1)

    elif args.mode == "restore_json":
        try:
            text = sys.stdin.read()
            if not args.map: sys.exit(1)
            cli.run_extension_restore(text, args.map)
        except Exception as e:
            sys.stderr.write(str(e))
            sys.exit(1)

    elif args.file:
        cli.run_analysis(args.file)
    else:
        print("Usage: python scrubduck_score.py <file> --dry-run")