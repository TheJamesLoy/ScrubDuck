"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const cp = require("child_process");
const fs = require("fs");
const path = require("path");
let globalSecretMap = {};
function activate(context) {
    console.log('ScrubDuck is active!');
    let sanitizeDisposable = vscode.commands.registerCommand('scrubduck.sanitize', () => __awaiter(this, void 0, void 0, function* () {
        yield handleCommand('sanitize_json');
    }));
    let restoreDisposable = vscode.commands.registerCommand('scrubduck.restore', () => __awaiter(this, void 0, void 0, function* () {
        yield handleCommand('restore_json');
    }));
    context.subscriptions.push(sanitizeDisposable);
    context.subscriptions.push(restoreDisposable);
}
function handleCommand(mode) {
    return __awaiter(this, void 0, void 0, function* () {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor.');
            return;
        }
        const selection = editor.selection;
        const text = editor.document.getText(selection);
        if (!text) {
            vscode.window.showWarningMessage('No text selected!');
            return;
        }
        // --- CONFIGURATION LOADING ---
        const config = vscode.workspace.getConfiguration('scrubduck');
        // 1. Get paths from User Settings
        let scriptPath = config.get('scriptPath');
        let pythonPath = config.get('pythonPath');
        // 2. Check if settings are missing
        if (!scriptPath || !pythonPath) {
            // Try to guess defaults if we are running inside the source repo (Development Mode)
            if (vscode.workspace.workspaceFolders) {
                const root = vscode.workspace.workspaceFolders[0].uri.fsPath;
                if (!scriptPath && fs.existsSync(path.join(root, 'scrubduck.py'))) {
                    scriptPath = path.join(root, 'scrubduck.py');
                }
                if (!pythonPath && fs.existsSync(path.join(root, 'venv', 'bin', 'python'))) {
                    pythonPath = path.join(root, 'venv', 'bin', 'python');
                }
            }
        }
        // 3. If still missing, stop and alert user
        if (!scriptPath || !pythonPath) {
            const action = "Open Settings";
            vscode.window.showErrorMessage("ScrubDuck is not configured. Please set 'scrubduck.scriptPath' and 'scrubduck.pythonPath'.", action).then(selection => {
                if (selection === action) {
                    vscode.commands.executeCommand('workbench.action.openSettings', 'ScrubDuck');
                }
            });
            return;
        }
        // --- EXECUTION ---
        try {
            const mapArgs = mode === 'restore_json' ? JSON.stringify(globalSecretMap) : null;
            if (mode === 'restore_json' && Object.keys(globalSecretMap).length === 0) {
                vscode.window.showErrorMessage('No secrets found in memory. Sanitize first!');
                return;
            }
            const result = yield runPythonScript(pythonPath, scriptPath, mode, text, mapArgs);
            if (result.text) {
                editor.edit(editBuilder => {
                    editBuilder.replace(selection, result.text);
                });
                if (result.map) {
                    globalSecretMap = result.map;
                    vscode.window.showInformationMessage('Sanitized!');
                }
                else if (mode === 'restore_json') {
                    vscode.window.showInformationMessage('Restored!');
                }
            }
        }
        catch (err) {
            console.error('Execution Error:', err);
            vscode.window.showErrorMessage('Error: ' + err);
        }
    });
}
function runPythonScript(pythonPath, scriptPath, mode, stdin, mapArgs) {
    return new Promise((resolve, reject) => {
        let args = [scriptPath, '--mode', mode];
        if (mapArgs)
            args.push('--map', mapArgs);
        console.log(`Spawning: ${pythonPath} ${args.join(' ')}`);
        const process = cp.spawn(pythonPath, args);
        let stdoutData = '';
        let stderrData = '';
        process.stdout.on('data', (data) => { stdoutData += data.toString(); });
        process.stderr.on('data', (data) => {
            stderrData += data.toString();
            console.log(`STDERR: ${data.toString()}`);
        });
        process.stdin.write(stdin);
        process.stdin.end();
        process.on('error', (err) => {
            reject(`Failed to start python process: ${err.message}`);
        });
        process.on('close', (code) => {
            if (code !== 0) {
                reject(`Python failed (Code ${code}). Check Debug Console.`);
            }
            else {
                try {
                    resolve(JSON.parse(stdoutData));
                }
                catch (e) {
                    console.log(`Raw Output: ${stdoutData}`);
                    reject("Invalid JSON output from Python");
                }
            }
        });
    });
}
function deactivate() { }
//# sourceMappingURL=extension.js.map