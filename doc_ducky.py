#!/usr/bin/env python3
"""
ScrubDuck - Document & Log Sanitizer
====================================
A tool to redact PII and sensitive data from unstructured documents 
(Text, Logs, PDFs) to make them safe for LLM analysis.

Focus: PII, IPs, Auth Tokens, Credit Cards, Stripe Keys.
"""

import re
import sys
import argparse
import json
from typing import List, Dict, Tuple
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

class DocScrubber:
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        
        # IMPROVED REGEX PATTERNS
        self.log_patterns = {
            # Standard IPv4
            "IPV4": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            
            # Auth Headers (Bearer Tokens)
            "AUTH_BEARER": r"Bearer [a-zA-Z0-9\-\._~\+\/]+",
            
            # AWS Access Keys (AKIA...)
            "AWS_KEY": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])",
            
            # S3 Buckets
            # 1. s3://name
            # 2. bucket 'name' or "name"
            # 3. for 'name' (common in "policies for 'my-bucket'")
            "S3_BUCKET": r"(?<=s3://)[a-z0-9][a-z0-9\.-]+|(?<=bucket\s')[a-z0-9][a-z0-9\.-]+(?=')|(?<=bucket\s\")[a-z0-9][a-z0-9\.-]+(?=\")|(?<=for\s')[a-z0-9][a-z0-9\.-]+(?=')",

            # Stripe Secret Keys (sk_live_...)
            "STRIPE_KEY": r"sk_live_[0-9a-zA-Z]+",
            
            # Credit Cards (Groups of 4 digits, separated by space or dash)
            # Catches: 1234 5678 1234 5678 or 1234-5678-1234-5678
            "CREDIT_CARD_REGEX": r"\b(?:\d{4}[ -]?){3}\d{4}\b",
            
            # US Zip Codes (5 digits, optional -4)
            # Added to protect physical location data
            "US_ZIP": r"\b\d{5}(?:-\d{4})?\b",
            
            # Common US Street Addresses (Number + Name + Suffix)
            # Uses (?i) for case-insensitivity. Now includes Parkway, Circle, Suite, etc.
            "STREET_ADDRESS": r"(?i)\b\d{1,6}\s+(?:[A-Za-z0-9\.]+\s){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Plaza|Square|Loop|Parkway|Pkwy|Circle|Cir|Trail|Trl|Highway|Hwy)(?:\s+(?:Suite|Ste|Apt|Unit)\s+\d+)?\b",

            # Generic "Token=" patterns
            "GENERIC_TOKEN": r"(?<=token=)[a-zA-Z0-9\_\-]+",

            # Usernames in logs (matches: user 'name', user "name", user: name, user=name)
            "USERNAME": r"(?<=user\s')[\w\.-]+(?=')|(?<=user\s\")[\w\.-]+(?=\")|(?<=user:\s)[\w\.-]+|(?<=user=)[\w\.-]+",
        }

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

    def scrub(self, text: str) -> str:
        """
        1. Runs Regex for technical secrets (IPs, Tokens).
        2. Runs NLP (Presidio) for Human PII (Names, Emails, Phones).
        """
        scrubbed_text = text

        # Phase 1: Technical Regex (Fast Redaction)
        # We iterate through patterns and replace matches
        for label, pattern in self.log_patterns.items():
            scrubbed_text = re.sub(pattern, f"<{label}>", scrubbed_text)

        # Phase 2: NLP PII Redaction (Slower, Contextual)
        # Note: We removed CREDIT_CARD from here because our Regex above is more aggressive for logs
        results = self.analyzer.analyze(
            text=scrubbed_text,
            entities=[
                "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "IP_ADDRESS", "LOCATION"
            ],
            language='en'
        )

        anonymized_result = self.anonymizer.anonymize(
            text=scrubbed_text,
            analyzer_results=results,
            operators={
                "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
                "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE>"}),
                "US_SSN": OperatorConfig("replace", {"new_value": "<SSN>"}),
                "IP_ADDRESS": OperatorConfig("replace", {"new_value": "<IP_ADDR>"}),
                "LOCATION": OperatorConfig("replace", {"new_value": "<LOCATION>"}),
            }
        )

        return anonymized_result.text

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ScrubDuck: Document & Log Sanitizer")
    parser.add_argument("file", help="Path to the file (PDF, TXT, LOG, JSON)")
    parser.add_argument("--out", help="Output file path (optional)")
    
    args = parser.parse_args()
    scrubber = DocScrubber()

    print(f"--- Processing {args.file} ---")
    
    # 1. Extract
    raw_text = scrubber.extract_text(args.file)
    
    # 2. Scrub
    clean_text = scrubber.scrub(raw_text)
    
    # 3. Output
    if args.out:
        with open(args.out, 'w') as f:
            f.write(clean_text)
        print(f"Success! Scrubbed data saved to: {args.out}")
    else:
        print("\n--- [SCRUBBED OUTPUT] ---\n")
        print(clean_text)
        print("\n--- [END OUTPUT] ---")