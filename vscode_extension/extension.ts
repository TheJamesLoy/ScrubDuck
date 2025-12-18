import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as fs from 'fs'; 
import * as path from 'path';

let globalSecretMap: any = {};

export function activate(context: vscode.ExtensionContext) {

    console.log('ScrubDuck is active! 🦆');

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
    
    // Pass the actual filename so the CLI knows if it's Python or JSON
    const filePathArg = editor.document.fileName;

    if (!text) { vscode.window.showWarningMessage('No text selected!'); return; }

    // --- CONFIGURATION LOADING ---
    const config = vscode.workspace.getConfiguration('scrubduck');
    let scriptPath = config.get<string>('scriptPath');
    let pythonPath = config.get<string>('pythonPath');

    // Auto-detect defaults (Development Mode)
    if (!scriptPath || !pythonPath) {
        if (vscode.workspace.workspaceFolders) {
            const root = vscode.workspace.workspaceFolders[0].uri.fsPath;
            // PREFER scrubduck_score.py as the entry point now!
            if (!scriptPath && fs.existsSync(path.join(root, 'scrubduck_score.py'))) {
                scriptPath = path.join(root, 'scrubduck_score.py');
            }
            if (!pythonPath && fs.existsSync(path.join(root, 'venv', 'bin', 'python'))) {
                pythonPath = path.join(root, 'venv', 'bin', 'python');
            }
        }
    }

    if (!scriptPath || !pythonPath) {
        vscode.window.showErrorMessage("ScrubDuck not configured. Set paths in Settings.");
        return;
    }

    try {
        const mapArgs = mode === 'restore_json' ? JSON.stringify(globalSecretMap) : null;
        
        if (mode === 'restore_json' && Object.keys(globalSecretMap).length === 0) {
            vscode.window.showErrorMessage('No secrets found in memory. Scrub first!');
            return;
        }

        const result = await runPythonScript(pythonPath, scriptPath, mode, text, mapArgs, filePathArg);
        
        if (result.text) {
            editor.edit(editBuilder => {
                editBuilder.replace(selection, result.text);
            });
            
            if (result.map) {
                globalSecretMap = result.map;
                vscode.window.showInformationMessage(`Scrubbed using ${result.engine || 'Default'} Engine!`);
            } else if (mode === 'restore_json') {
                vscode.window.showInformationMessage('Restored!');
            }
        }
    } catch (err: any) {
        console.error('Execution Error:', err);
        vscode.window.showErrorMessage('ScrubDuck Error: ' + err);
    }
}

function runPythonScript(pythonPath: string, scriptPath: string, mode: string, stdin: string, mapArgs: string | null, filePathArg: string): Promise<any> {
    return new Promise((resolve, reject) => {
        let args = [scriptPath, '--mode', mode, '--filepath', filePathArg];
        if (mapArgs) args.push('--map', mapArgs);

        console.log(`Spawning: ${pythonPath} ${args.join(' ')}`);

        const process = cp.spawn(pythonPath, args);
        let stdoutData = '';
        let stderrData = '';

        process.stdout.on('data', (data: Buffer) => { stdoutData += data.toString(); });
        process.stderr.on('data', (data: Buffer) => { stderrData += data.toString(); });

        process.stdin.write(stdin);
        process.stdin.end();

        process.on('close', (code: number) => {
            if (code !== 0) {
                console.error(stderrData);
                reject(`Python failed. Check Debug Console.`);
            } else {
                try {
                    resolve(JSON.parse(stdoutData));
                } catch (e) {
                    reject("Invalid JSON output from Python");
                }
            }
        });
    });
}

export function deactivate() {}