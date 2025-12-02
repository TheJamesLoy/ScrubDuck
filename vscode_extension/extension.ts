import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as fs from 'fs'; 
import * as path from 'path';

let globalSecretMap: any = {};

export function activate(context: vscode.ExtensionContext) {

    console.log('ScrubDuck is active!');

    let sanitizeDisposable = vscode.commands.registerCommand('scrubduck.sanitize', async () => {
        await handleCommand('sanitize_json');
    });

    let restoreDisposable = vscode.commands.registerCommand('scrubduck.restore', async () => {
        await handleCommand('restore_json');
    });

    context.subscriptions.push(sanitizeDisposable);
    context.subscriptions.push(restoreDisposable);
}

async function handleCommand(mode: string) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) { vscode.window.showErrorMessage('No active editor.'); return; }

    const selection = editor.selection;
    const text = editor.document.getText(selection);

    if (!text) { vscode.window.showWarningMessage('No text selected!'); return; }

    // --- CONFIGURATION LOADING ---
    const config = vscode.workspace.getConfiguration('scrubduck');
    
    // 1. Get paths from User Settings
    let scriptPath = config.get<string>('scriptPath');
    let pythonPath = config.get<string>('pythonPath');

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
        vscode.window.showErrorMessage(
            "ScrubDuck is not configured. Please set 'scrubduck.scriptPath' and 'scrubduck.pythonPath'.",
            action
        ).then(selection => {
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

        const result = await runPythonScript(pythonPath, scriptPath, mode, text, mapArgs);
        
        if (result.text) {
            editor.edit(editBuilder => {
                editBuilder.replace(selection, result.text);
            });
            
            if (result.map) {
                globalSecretMap = result.map;
                vscode.window.showInformationMessage('Sanitized!');
            } else if (mode === 'restore_json') {
                vscode.window.showInformationMessage('Restored!');
            }
        }
    } catch (err: any) {
        console.error('Execution Error:', err);
        vscode.window.showErrorMessage('Error: ' + err);
    }
}

function runPythonScript(pythonPath: string, scriptPath: string, mode: string, stdin: string, mapArgs: string | null): Promise<any> {
    return new Promise((resolve, reject) => {
        let args = [scriptPath, '--mode', mode];
        if (mapArgs) args.push('--map', mapArgs);

        console.log(`Spawning: ${pythonPath} ${args.join(' ')}`);

        const process = cp.spawn(pythonPath, args);
        let stdoutData = '';
        let stderrData = '';

        process.stdout.on('data', (data: Buffer) => { stdoutData += data.toString(); });
        process.stderr.on('data', (data: Buffer) => { 
            stderrData += data.toString();
            console.log(`STDERR: ${data.toString()}`); 
        });

        process.stdin.write(stdin);
        process.stdin.end();

        process.on('error', (err) => {
            reject(`Failed to start python process: ${err.message}`);
        });

        process.on('close', (code: number) => {
            if (code !== 0) {
                reject(`Python failed (Code ${code}). Check Debug Console.`);
            } else {
                try {
                    resolve(JSON.parse(stdoutData));
                } catch (e) {
                    console.log(`Raw Output: ${stdoutData}`);
                    reject("Invalid JSON output from Python");
                }
            }
        });
    });
}

export function deactivate() {}