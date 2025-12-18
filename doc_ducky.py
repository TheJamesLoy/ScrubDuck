#!/usr/bin/env python3
"""
ScrubDuck - Document & Log Scrubber
====================================
A tool to redact PII and sensitive data from unstructured documents 
(Text, Logs, PDFs) to make them safe for LLM analysis.

Focus: PII, IPs, Auth Tokens, Credit Cards, Stripe Keys.
"""

import re
import sys
import argparse
import json
import os
import yaml
from typing import List, Dict, Tuple, Optional
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

def load_config() -> Dict:
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
                    # print(f"🦆 Loaded configuration from: {p}") # Optional: Uncomment for debug
                    return config or {}
            except Exception as e:
                sys.stderr.write(f"⚠️ Error loading config {p}: {e}\n")
    return {}

class DocScrubber:
    def __init__(self, config: Optional[Dict] = None):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        
        # Load Config
        self.config = config or {}
        self.ignore_list = set(self.config.get('ignore', []))
        
        # Initialize Patterns
        self.log_patterns = {
            "IPV4": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "AUTH_BEARER": r"Bearer [a-zA-Z0-9\-\._~\+\/]+",
            "AWS_KEY": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])",
            "S3_BUCKET": r"(?<=s3://)[a-z0-9][a-z0-9\.-]+|(?<=bucket\s')[a-z0-9][a-z0-9\.-]+(?=')|(?<=bucket\s\")[a-z0-9][a-z0-9\.-]+(?=\")|(?<=for\s')[a-z0-9][a-z0-9\.-]+(?=')",
            "STRIPE_KEY": r"sk_live_[0-9a-zA-Z]+",
            "CREDIT_CARD_REGEX": r"\b(?:\d{4}[ -]?){3}\d{4}\b",
            "US_ZIP": r"\b\d{5}(?:-\d{4})?\b",
            "STREET_ADDRESS": r"(?i)\b\d{1,6}\s+(?:[A-Za-z0-9\.]+\s){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Plaza|Square|Loop|Parkway|Pkwy|Circle|Cir|Trail|Trl|Highway|Hwy)(?:\s+(?:Suite|Ste|Apt|Unit)\s+\d+)?\b",
            "GENERIC_TOKEN": r"(?<=token=)[a-zA-Z0-9\_\-]+",
            "USERNAME": r"(?<=user\s')[\w\.-]+(?=')|(?<=user\s\")[\w\.-]+(?=\")|(?<=user:\s)[\w\.-]+|(?<=user=)[\w\.-]+",
        }
        
        # Merge Custom Rules from Config
        if 'custom_rules' in self.config:
            for rule in self.config['custom_rules']:
                self.log_patterns[rule['name']] = rule['regex']

    def extract_text(self, file_path: str) -> str:
        """Extracts text from various file formats."""
        if file_path.endswith('.pdf'):
            if not PdfReader:
                return "Error: pypdf not installed. Run 'pip install pypdf'"
            try:
                reader = PdfReader(file_path)
                text = ""
                for page in reader.pages:
                    text += page.extract_text() + "\n"
                return text
            except Exception as e:
                return f"Error reading PDF: {str(e)}"
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def scan_only(self, text: str) -> List[Dict]:
        findings = []

        # 1. Regex Scan (Includes Custom Rules)
        for label, pattern in self.log_patterns.items():
            for match in re.finditer(pattern, text):
                snippet = match.group()
                if snippet in self.ignore_list: continue # Check allow-list
                
                findings.append({
                    "start": match.start(),
                    "end": match.end(),
                    "label": label,
                    "snippet": snippet
                })

        # 2. NLP Scan
        results = self.analyzer.analyze(
            text=text,
            entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "IP_ADDRESS", "LOCATION"],
            language='en'
        )
        
        for r in results:
            snippet = text[r.start:r.end]
            if snippet in self.ignore_list: continue # Check allow-list
            
            findings.append({
                "start": r.start,
                "end": r.end,
                "label": r.entity_type,
                "snippet": snippet
            })

        findings.sort(key=lambda x: x['start'])
        return findings

    def scrub(self, text: str) -> str:
        # Use scan_only to get findings (which respects the ignore list), 
        # then replace in reverse order.
        
        findings = self.scan_only(text)
        
        # Deduplicate and sort by start index reverse to replace safely
        findings.sort(key=lambda x: x['start'], reverse=True)
        
        scrubbed_text = text
        processed_indices = set()
        
        for f in findings:
            start, end = f['start'], f['end']
            # Simple collision check
            if any(i in processed_indices for i in range(start, end)): continue
            for i in range(start, end): processed_indices.add(i)
            
            label = f['label']
            scrubbed_text = scrubbed_text[:start] + f"<{label}>" + scrubbed_text[end:]
            
        return scrubbed_text

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ScrubDuck: Document & Log Scrubber")
    parser.add_argument("file", help="Path to the file (PDF, TXT, LOG, JSON)")
    parser.add_argument("--out", help="Output file path (optional)")
    parser.add_argument("--mode", choices=["scrub", "scan_json"], default="scrub", help="Operation mode")
    
    args = parser.parse_args()
    
    # LOAD CONFIG (This was missing before!)
    config = load_config()
    scrubber = DocScrubber(config=config)

    raw_text = scrubber.extract_text(args.file)
    if raw_text.startswith("Error"):
        sys.stderr.write(raw_text)
        sys.exit(1)

    if args.mode == "scan_json":
        findings = scrubber.scan_only(raw_text)
        print(json.dumps(findings))
        
    else:
        print(f"--- Processing {args.file} ---")
        clean_text = scrubber.scrub(raw_text)
        
        if args.out:
            with open(args.out, 'w') as f:
                f.write(clean_text)
            print(f"Success! Scrubbed data saved to: {args.out}")
        else:
            print("\n--- [SCRUBBED OUTPUT] ---\n")
            print(clean_text)
            print("\n--- [END OUTPUT] ---")