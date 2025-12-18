#!/usr/bin/env python3
"""
ScrubDuck - Context Aware Scrubber
=====================================
A tool to detect and redact sensitive information (API keys, PII, passwords) 
from source code before sending it to Large Language Models (LLMs), 
and restore them in the response.

Author: ScrubDuck Contributors
License: MIT
"""

import ast
import re
import math
import textwrap
import argparse
import sys
import json
import os
import yaml
from typing import List, Tuple, Dict, Set, Optional
from presidio_analyzer import AnalyzerEngine

# ==========================================
#              DEFAULTS
# ==========================================

DEFAULT_SUSPICIOUS_VAR_NAMES = {
    "password", "secret", "key", "token", "auth", "credential", 
    "pwd", "api_key", "access_key", "client_secret", "private", 
    "cert", "ssh"
}

DEFAULT_REGEX_PATTERNS = {
    "AWS_KEY": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])", 
    "IPV4": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "IPV6": r"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)"
}

PRIORITY_MAP = {
    "AWS_KEY": 110,               
    "SECRET_VAR_ASSIGNMENT": 100, 
    "IPV4": 80,
    "IPV6": 80,
    "EMAIL_ADDRESS": 50,
    "PERSON": 50,
    "HIGH_ENTROPY_SECRET": 10     
}

ENTROPY_THRESHOLD = 3.2 

# ==========================================
#              CORE LOGIC
# ==========================================

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

class EntropyScanner:
    @staticmethod
    def calculate_entropy(data: str) -> float:
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    @staticmethod
    def scan(text: str) -> List[Tuple[int, int, str]]:
        findings = []
        for match in re.finditer(r'[^\s"\'\(\)\{\}\[\]=,;:\\]+', text):
            token = match.group()
            if len(token) < 8: continue 
            if re.match(r'^[a-zA-Z_]+$', token): continue
            
            score = EntropyScanner.calculate_entropy(token)
            if score > ENTROPY_THRESHOLD:
                findings.append((match.start(), match.end(), "HIGH_ENTROPY_SECRET"))
        return findings

class CodeVisitor(ast.NodeVisitor):
    def __init__(self, suspicious_vars: Set[str]):
        self.findings = [] 
        self.suspicious_vars = suspicious_vars

    def _check_and_add(self, node, var_name):
        if any(s in var_name for s in self.suspicious_vars):
            if isinstance(node.value, (ast.Constant, ast.Str)):
                val = node.value.s if hasattr(node.value, 's') else node.value.value
                if isinstance(val, str) and val:
                    self.findings.append((node.value, "SECRET_VAR_ASSIGNMENT"))

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._check_and_add(node, target.id.lower())
            elif isinstance(target, ast.Subscript):
                slice_val = None
                if isinstance(target.slice, (ast.Constant, ast.Str)): 
                    slice_val = target.slice.s if hasattr(target.slice, 's') else target.slice.value
                if isinstance(slice_val, str):
                    self._check_and_add(node, slice_val.lower())
        self.generic_visit(node)

class ContextAwareSanitizer:
    def __init__(self, config: Optional[Dict] = None):
        self.analyzer = AnalyzerEngine()
        self.token_map: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}
        
        # Load Config
        self.config = config or {}
        self.ignore_list = set(self.config.get('ignore', []))
        
        # Merge Suspicious Vars
        self.suspicious_vars = DEFAULT_SUSPICIOUS_VAR_NAMES.copy()
        if 'suspicious_vars' in self.config:
            self.suspicious_vars.update(self.config['suspicious_vars'])
            
        # Merge Custom Regex
        self.regex_patterns = DEFAULT_REGEX_PATTERNS.copy()
        if 'custom_rules' in self.config:
            for rule in self.config['custom_rules']:
                self.regex_patterns[rule['name']] = rule['regex']
                # Add to priority map dynamically if weight is provided
                if 'score' in rule:
                    PRIORITY_MAP[rule['name']] = rule['score'] + 50 # Base boost

    def _get_placeholder(self, entity_type: str) -> str:
        if entity_type not in self.counters: self.counters[entity_type] = 0
        self.counters[entity_type] += 1
        return f"<{entity_type}_{self.counters[entity_type]}>"

    def _analyze_ast(self, text: str) -> List[Tuple[int, int, str]]:
        findings = []
        try:
            clean_text = textwrap.dedent(text)
            tree = ast.parse(clean_text)
            # Pass dynamic suspicious vars to visitor
            visitor = CodeVisitor(self.suspicious_vars)
            visitor.visit(tree)
            
            for node, label in visitor.findings:
                val = node.s if hasattr(node, 's') else node.value
                start = 0
                while True:
                    idx = text.find(val, start)
                    if idx == -1: break
                    findings.append((idx, idx + len(val), label))
                    start = idx + len(val)
                if start == 0 and '\n' in val:
                    prefix = val[:20]
                    idx = text.find(prefix)
                    if idx != -1:
                        end_val_suffix = val[-20:]
                        end_idx = text.find(end_val_suffix, idx)
                        if end_idx != -1:
                             findings.append((idx, end_idx + 20, label))
        except:
            pass
        return findings

    def scan_only(self, text: str) -> List[Tuple[int, int, str]]:
        findings = []
        
        # 1. Presidio
        p_results = self.analyzer.analyze(text=text, entities=["PERSON", "EMAIL_ADDRESS"], language='en')
        for r in p_results:
            entity_text = text[r.start:r.end]
            if r.entity_type == "PERSON":
                if "_" in entity_text: continue 
                if any(char.isdigit() for char in entity_text): continue
            findings.append((r.start, r.end, r.entity_type))

        # 2. Regex (Includes Custom Rules)
        for label, pattern in self.regex_patterns.items():
            for match in re.finditer(pattern, text):
                findings.append((match.start(), match.end(), label))

        # 3. Entropy
        findings.extend(EntropyScanner.scan(text))

        # 4. AST
        findings.extend(self._analyze_ast(text))

        # FILTER: Remove findings that match the Allow-List
        filtered_findings = []
        for start, end, label in findings:
            snippet = text[start:end]
            if snippet in self.ignore_list:
                continue
            filtered_findings.append((start, end, label))

        filtered_findings.sort(key=lambda x: (x[0], PRIORITY_MAP.get(x[2], 0)), reverse=True)
        return filtered_findings

    def sanitize(self, text: str) -> str:
        self.token_map = {}
        self.counters = {}
        findings = self.scan_only(text)
        
        sanitized_text = text
        processed_indices: Set[int] = set()

        for start, end, label in findings:
            if any(i in processed_indices for i in range(start, end)): continue
            for i in range(start, end): processed_indices.add(i)

            original_value = text[start:end]
            placeholder = self._get_placeholder(label)
            self.token_map[placeholder] = original_value
            sanitized_text = sanitized_text[:start] + placeholder + sanitized_text[end:]

        return sanitized_text

    def restore(self, text: str, external_map: Dict[str, str] = None) -> str:
        map_to_use = external_map if external_map is not None else self.token_map
        restored = text
        sorted_map = sorted(map_to_use.items(), key=lambda x: len(x[0]), reverse=True)
        for placeholder, original in sorted_map:
            restored = restored.replace(placeholder, original)
        return restored

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs="?", help="File to process")
    parser.add_argument("--mode", choices=["sanitize_json", "restore_json", "scan_only"], help="Mode")
    parser.add_argument("--map", help="JSON string of token map")
    
    args = parser.parse_args()
    
    # LOAD CONFIG AUTOMATICALLY
    config = load_config()
    sanitizer = ContextAwareSanitizer(config=config)

    if args.mode == "scan_only":
        try:
            input_text = sys.stdin.read()
            findings = sanitizer.scan_only(input_text)
            results = [{"label": f[2], "start": f[0], "end": f[1], "snippet": input_text[f[0]:f[1]]} for f in findings]
            print(json.dumps(results))
        except Exception as e:
            sys.stderr.write(str(e))
            sys.exit(1)

    elif args.mode == "sanitize_json":
        try:
            input_text = sys.stdin.read()
            clean_text = sanitizer.sanitize(input_text)
            print(json.dumps({ "text": clean_text, "map": sanitizer.token_map }))
        except Exception as e:
            sys.stderr.write(str(e))
            sys.exit(1)

    elif args.mode == "restore_json":
        try:
            if not args.map: sys.exit(1)
            input_text = sys.stdin.read()
            token_map = json.loads(args.map)
            restored_text = sanitizer.restore(input_text, external_map=token_map)
            print(json.dumps({"text": restored_text}))
        except Exception as e:
            sys.stderr.write(str(e))
            sys.exit(1)

    elif args.file:
        try:
            with open(args.file, "r") as f: content = f.read()
            print(f"--- Processing {args.file} ---")
            clean_code = sanitizer.sanitize(content)
            print("\n[SANITIZED]:\n" + clean_code)
            print("\n" + "="*50 + "\nPaste AI Response below (Type 'END' on new line):\n")
            lines = []
            while True:
                line = sys.stdin.readline()
                if not line or line.strip() == 'END': break
                lines.append(line)
            print("\n[RESTORED]:\n" + sanitizer.restore("".join(lines)))
        except FileNotFoundError:
            print(f"Error: Could not find {args.file}")
    else:
        print("Run with a filename or use --mode for JSON API.")