# 🦆 ScrubDuck 

ScrubDuck is a local-first security tool that acts as an "AI Airlock." It strips sensitive data (API keys, PII, passwords, customer info) from your source code, server logs, and documents so you can safely use LLMs for debugging and analysis without leaking proprietary secrets.

# ✨ Features

## 🐍 Code Sanitizer (For Source Code)

Context-Aware: Detects secrets based on variable names (AST Parsing), not just regex.

Entropy Scanning: Mathematically detects random tokens (like zb83#91!k29) that look like passwords.

Bi-Directional: Automatically restores the original secrets when the AI responds, so your code remains runnable.

## 📄 Document & Log Scrubber (For Data)

Log Analysis: Strips IPs, Auth Tokens (Bearer/JWT), AWS Keys, and Usernames from server logs.

PII Removal: Uses Microsoft Presidio to redact Names, Emails, Phone Numbers, and Addresses from unstructured text.

PDF Support: Can read and sanitize PDF reports directly.

Unidirectional: Permanently destroys sensitive data (ideal for sharing logs/tickets).

# 🚀 Installation

## Clone the repository:

git clone [https://github.com/TheJamesLoy/scrubduck.git](https://github.com/TheJamesLoy/scrubduck.git)

cd scrubduck


## Set up the environment:

python3 -m venv venv
source venv/bin/activate  
### On Windows: 
venv\Scripts\activate


## Install dependencies:

pip install -r requirements.txt
python -m spacy download en_core_web_lg


# 💻 Usage

## CLI Mode

### To clean a specific code file:

python scrubduck.py my_dirty_code.py


Copy the [SANITIZED] output.

Paste it into LLM.

Paste LLM's response back into the terminal.

The tool will output the [RESTORED] code with your secrets injected back in.

### To clean a specific document/log:

python doc_ducky.py my_dirty_doc.py

## VS Code Extension

This repository includes a VS Code extension that wraps the Python engine.

Navigate to vscode-extension/.

Run npm install and npm run compile.

Press F5 to debug or use vsce package to build an installer.

# 🤝 Contributing

Pull requests are welcome! Please make sure to update tests as appropriate.

# 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.