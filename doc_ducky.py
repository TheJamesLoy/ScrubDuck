#!/usr/bin/env python3
"""
ScrubDuck - Document & Log Scrubber
====================================
A tool to redact PII and sensitive data from unstructured documents 
(Text, Logs, PDFs) and STRUCTURED data (JSON, CSV, XML).

Features:
- Unidirectional (Logs): Permanently destroys secrets.
- Bidirectional (Configs): Maps secrets to placeholders for restoration.
"""

import re
import sys
import argparse
import json
import os
import yaml
import csv
import io
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Optional, Any, Set
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine # Kept for reference, but we implement custom mapping now

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
                    return config or {}
            except Exception as e:
                sys.stderr.write(f"⚠️ Error loading config {p}: {e}\n")
    return {}

class DocScrubber:
    def __init__(self, config: Optional[Dict] = None):
        self.analyzer = AnalyzerEngine()
        # self.anonymizer = AnonymizerEngine() # We use custom logic now for bidirectional support
        self.config = config or {}
        self.ignore_list = set(self.config.get('ignore', []))
        
        # State for Bidirectional Mapping
        self.token_map: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}
        
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
        
        if 'custom_rules' in self.config:
            for rule in self.config['custom_rules']:
                self.log_patterns[rule['name']] = rule['regex']

    def _get_placeholder(self, entity_type: str) -> str:
        """Generates indexed placeholders like <EMAIL_1>."""
        if entity_type not in self.counters: self.counters[entity_type] = 0
        self.counters[entity_type] += 1
        return f"<{entity_type}_{self.counters[entity_type]}>"

    def extract_text(self, file_path: str) -> str:
        if file_path.endswith('.pdf'):
            if not PdfReader: return "Error: pypdf not installed."
            try:
                reader = PdfReader(file_path)
                return "\n".join([p.extract_text() for p in reader.pages])
            except Exception as e: return f"Error reading PDF: {e}"
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e: return f"Error reading file: {e}"

    def scan_only(self, text: str) -> List[Dict]:
        """Dry Run Scan. Returns list of findings without modifying text."""
        findings = []

        # 1. Regex Scan
        for label, pattern in self.log_patterns.items():
            for match in re.finditer(pattern, text):
                snippet = match.group()
                if snippet in self.ignore_list: continue
                findings.append({"start": match.start(), "end": match.end(), "label": label, "snippet": snippet})

        # 2. NLP Scan
        results = self.analyzer.analyze(
            text=text,
            entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "IP_ADDRESS", "LOCATION"],
            language='en'
        )
        for r in results:
            snippet = text[r.start:r.end]
            if snippet in self.ignore_list: continue
            findings.append({"start": r.start, "end": r.end, "label": r.entity_type, "snippet": snippet})

        findings.sort(key=lambda x: x['start'])
        return findings

    def _scrub_string(self, text: str) -> str:
        """
        Scrub a single string using Regex + NLP.
        Populates self.token_map for bidirectional support.
        """
        # Get all findings using the shared scan logic
        # We assume scan_only returns findings sorted by start index
        findings = self.scan_only(text)
        
        # Sort reverse by start index to replace from end-to-start
        # (This prevents index shifting when we modify the string)
        findings.sort(key=lambda x: x['start'], reverse=True)
        
        scrubbed_text = text
        processed_indices = set()
        
        for f in findings:
            start, end, label, snippet = f['start'], f['end'], f['label'], f['snippet']
            
            # Simple collision detection (if ranges overlap, skip the second one encountered)
            # Since we iterate reverse, "second one" means "earlier in string".
            # For strict safety, if overlaps occur, we might miss one, but sorting usually handles it.
            range_set = set(range(start, end))
            if not range_set.isdisjoint(processed_indices):
                continue
            processed_indices.update(range_set)
            
            # Generate Bidirectional Placeholder
            placeholder = self._get_placeholder(label)
            
            # Store in Map
            self.token_map[placeholder] = snippet
            
            # Replace
            scrubbed_text = scrubbed_text[:start] + placeholder + scrubbed_text[end:]
            
        return scrubbed_text

    # --- STRUCTURED HANDLERS ---

    def _scrub_json_obj(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self._scrub_json_obj(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._scrub_json_obj(i) for i in obj]
        elif isinstance(obj, str):
            return self._scrub_string(obj)
        else:
            return obj

    def _scrub_csv(self, text: str) -> str:
        input_io = io.StringIO(text)
        output_io = io.StringIO()
        reader = csv.reader(input_io)
        writer = csv.writer(output_io)
        for row in reader:
            clean_row = [self._scrub_string(cell) for cell in row]
            writer.writerow(clean_row)
        return output_io.getvalue()

    def _scrub_xml_element(self, elem: ET.Element):
        if elem.text: elem.text = self._scrub_string(elem.text)
        if elem.tail: elem.tail = self._scrub_string(elem.tail)
        for key, value in elem.attrib.items():
            elem.attrib[key] = self._scrub_string(value)
        for child in elem:
            self._scrub_xml_element(child)

    def scrub(self, text: str, file_type: str = 'txt') -> str:
        """
        Main Dispatcher. Routes to specific handlers based on file type.
        Resets the token map at start of scrub.
        """
        self.token_map = {}
        self.counters = {}
        
        try:
            if file_type == 'json':
                data = json.loads(text)
                clean_data = self._scrub_json_obj(data)
                return json.dumps(clean_data, indent=2)
            elif file_type == 'csv':
                return self._scrub_csv(text)
            elif file_type == 'xml':
                try:
                    root = ET.fromstring(text)
                    self._scrub_xml_element(root)
                    return ET.tostring(root, encoding='unicode')
                except ET.ParseError:
                    return self._scrub_string(text)
            else:
                return self._scrub_string(text)
        except Exception as e:
            sys.stderr.write(f"⚠️ Structure parsing failed ({e}). Falling back to raw text.\n")
            return self._scrub_string(text)

    def restore(self, text: str, external_map: Dict[str, str] = None) -> str:
        """Restores original values from the token map."""
        map_to_use = external_map if external_map is not None else self.token_map
        restored = text
        # Restore longest placeholders first to avoid partial replacements
        sorted_map = sorted(map_to_use.items(), key=lambda x: len(x[0]), reverse=True)
        for placeholder, original in sorted_map:
            restored = restored.replace(placeholder, original)
        return restored

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ScrubDuck: Document & Log Sanitizer")
    parser.add_argument("file", help="Path to the file")
    parser.add_argument("--out", help="Output file path (optional)")
    # Added sanitize_json and restore_json for VS Code / CLI support
    parser.add_argument("--mode", choices=["scrub", "scan_json", "sanitize_json", "restore_json"], default="scrub", help="Operation mode")
    parser.add_argument("--map", help="JSON string of token map")
    
    args = parser.parse_args()
    
    config = load_config()
    scrubber = DocScrubber(config=config)

    if args.mode == "restore_json":
        # Restore doesn't need file extraction, usually reads from stdin or string arg in extension
        try:
            if not args.map: sys.exit(1)
            input_text = sys.stdin.read()
            token_map = json.loads(args.map)
            restored_text = scrubber.restore(input_text, external_map=token_map)
            print(json.dumps({"text": restored_text}))
        except Exception as e:
            sys.stderr.write(str(e))
            sys.exit(1)
        sys.exit(0)

    # For other modes, we need to read the file
    raw_text = scrubber.extract_text(args.file)
    if raw_text.startswith("Error"):
        sys.stderr.write(raw_text)
        sys.exit(1)

    ext = os.path.splitext(args.file)[1].lower().replace('.', '')
    if ext in ['js', 'ts', 'yaml', 'yml']: ext = 'txt'

    if args.mode == "scan_json":
        findings = scrubber.scan_only(raw_text)
        print(json.dumps(findings))
        
    elif args.mode == "sanitize_json":
        # Bidirectional JSON Output
        clean_text = scrubber.scrub(raw_text, file_type=ext)
        print(json.dumps({ "text": clean_text, "map": scrubber.token_map }))

    else:
        # Default Console Output
        print(f"--- Processing {args.file} as [{ext.upper()}] ---")
        clean_text = scrubber.scrub(raw_text, file_type=ext)
        
        if args.out:
            with open(args.out, 'w') as f:
                f.write(clean_text)
            print(f"Success! Scrubbed data saved to: {args.out}")
        else:
            print("\n--- [SCRUBBED OUTPUT] ---\n")
            print(clean_text)
            print("\n--- [END OUTPUT] ---")