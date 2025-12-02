# 🦆 ScrubDuck 

Sanitize your code before sending it to AI.

ScrubDuck is a local-first security tool that strips sensitive data (API keys, PII, passwords) from your source code and replaces them with context-aware placeholders. It allows you to use LLMs for debugging without leaking proprietary secrets.

# ✨ Features

Context-Aware: Detects secrets based on variable names (AST Parsing), not just regex.

Entropy Scanning: mathematically detects random tokens (like zb83#91!k29) that look like passwords.

PII Detection: Uses Microsoft Presidio to remove names and emails.

Bi-Directional: Automatically restores the original secrets when the AI responds.

Local Execution: No data is ever sent to a third-party server (other than the LLM you choose to use).

# 🚀 Installation

## Clone the repository:

git clone [https://github.com/YOUR_USERNAME/scrubduck.git](https://github.com/YOUR_USERNAME/scrubduck.git)

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

To clean a specific file:

python scrubduck.py my_unsafe_code.py


Copy the [SANITIZED] output.

Paste it into ChatGPT.

Paste ChatGPT's response back into the terminal.

The tool will output the [RESTORED] code with your secrets injected back in.

## VS Code Extension

This repository includes a VS Code extension that wraps the Python engine.

Navigate to vscode-extension/.

Run npm install and npm run compile.

Press F5 to debug or use vsce package to build an installer.

# 🤝 Contributing

Pull requests are welcome! Please make sure to update tests as appropriate.

# 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.