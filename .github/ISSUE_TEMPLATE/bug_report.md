---
name: Bug report
about: Create a report to help us improve
title: "[BUG]"
labels: ''
assignees: ''

---

# ⚠️ SECURITY WARNING ⚠️
DO NOT PASTE REAL SECRETS, API KEYS, OR PII INTO THIS ISSUE.
If you are reporting a sanitization failure (leak), please use dummy data (e.g., replace sk-real-key with sk-fake-key-123) that mimics the format of your secret.

## Describe the Bug 🐛 

A clear and concise description of what the bug is.

## To Reproduce

Steps to reproduce the behavior:
1. Go to file '...'
2. Paste this code snippet:
  - Paste your SAFE / DUMMY code here
3. Run command 'ScrubDuck: Sanitize'
4. See error/leak

## Expected Behavior

A clear and concise description of what you expected to happen (e.g., "The variable password should be replaced with <SECRET_VAR_1>").

## Actual Behavior

What actually happened? (e.g., "The variable was ignored and the secret remained visible").

## Screenshots / Logs

If applicable, add screenshots to help explain your problem.
If the VS Code extension failed, please paste the output from the Debug Console here.

## Environment (please complete the following information):

OS: [e.g. macOS 14, Windows 11]
VS Code Version: [e.g. 1.85.1]
Python Version: [e.g. 3.11]
ScrubDuck Version: [e.g. v1.0.0]

## Additional Context

Add any other context about the problem here. Does this happen in Python files only, or other languages too?
