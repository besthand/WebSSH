import {
    getStoredConnections,
    createSession,
    decryptPrivateKeyFromStorage
} from './js/ssh-manager.js';

// --- OpenRouter API (using fetch for browser compatibility) ---
const OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions';

// --- UI Elements ---
const terminalContainer = document.getElementById('terminal');
const statusDot = document.getElementById('terminal-status-dot');
const statusText = document.getElementById('terminal-status-text');
const currentConnectionNameEl = document.getElementById('current-connection-name');
const selectConnectionBtn = document.getElementById('select-connection-btn');
const logsContainer = document.getElementById('logs-container');
const clearLogsBtn = document.getElementById('clear-logs-btn');
const agentInput = document.getElementById('agent-input');
const startAgentBtn = document.getElementById('start-agent-btn');
const stopAgentBtn = document.getElementById('stop-agent-btn');
const modelDisplay = document.getElementById('model-display');
const settingsBtn = document.getElementById('settings-btn');
const apiKeyModalEl = document.getElementById('api-key-modal');
const apiKeyInput = document.getElementById('api-key-input');
const modelIdInput = document.getElementById('model-id-input');
const saveApiKeyBtn = document.getElementById('save-api-key-btn');
const connectionModalEl = document.getElementById('connection-modal');
const connectionListGroup = document.getElementById('connection-list-group');
const openConnectionModalBtn = document.getElementById('select-connection-btn');
const credentialModalEl = document.getElementById('credential-modal');
const credentialModalTitle = document.getElementById('credential-modal-title');
const credentialLabel = document.getElementById('credential-label');
const credentialInput = document.getElementById('credential-input');
const credentialHint = document.getElementById('credential-hint');
const credentialSubmitBtn = document.getElementById('credential-submit-btn');

// --- State ---
let term;
let fitAddon;
let socket;
let currentSessionId;
let currentConnection;
let agentRunning = false;
let agentLoopController = null; // AbortController
let terminalBuffer = '';
let isTerminalReady = false;
let lastPromptLine = -1;

// --- Constants ---
const DEFAULT_MODEL = 'google/gemini-2.0-flash-001';

// --- Initialization ---
function initView() {
    // Init Terminal
    console.log('[agent] Initializing terminal...');
    term = new Terminal({
        convertEol: true,
        cursorBlink: true,
        fontSize: 15,
        fontFamily: '"JetBrains Mono", "Cascadia Code", "Fira Code", monospace',
        cols: 80, // Default cols
        rows: 24, // Default rows
        theme: {
            background: '#05070d',
            foreground: '#ffffff',
            cursor: '#f8f8f2',
        },
        allowProposedApi: true,
    });
    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);

    // Debug container size
    const rect = terminalContainer.getBoundingClientRect();
    console.log('[agent] Terminal container size:', rect.width, rect.height);

    term.open(terminalContainer);
    fitAddon.fit();
    console.log('[agent] Terminal fitted to:', term.cols, term.rows);

    window.addEventListener('resize', () => {
        fitAddon.fit();
        emitResize();
    });

    // Terminal Status Monitoring
    term.onData(data => {
        // User manual input? Maybe block during agent run?
        if (socket && socket.connected) {
            socket.emit('data', data);
        }
    });

    term.onCursorMove(updateTerminalStatus);

    // Load Settings
    const savedKey = localStorage.getItem('openrouter_api_key');
    const savedModel = localStorage.getItem('openrouter_model') || DEFAULT_MODEL;
    if (savedKey) apiKeyInput.value = savedKey;
    modelIdInput.value = savedModel;
    modelDisplay.textContent = savedModel;

    loadConnectionsToModal();
}

function emitResize() {
    if (!term || !socket || !socket.connected) return;
    const { cols, rows } = term;
    console.log('[agent] emitResize', { cols, rows });
    // Log to UI for debugging
    if (cols === 0 || rows === 0) {
        addLog('error', `Terminal size invalid: ${cols}x${rows}. Retrying...`);
        setTimeout(emitResize, 500); // Retry
        return;
    }
    // Only log once or if changed significantly? 
    // Let's just log it to system so we know it happened.
    // addLog('system', `Terminal resized to ${cols}x${rows}`);

    socket.emit('resize', {
        cols,
        rows,
        width: terminalContainer.clientWidth,
        height: terminalContainer.clientHeight,
    });
}

// --- Terminal Utils ---
function updateTerminalStatus() {
    if (!term) return;
    const buffer = term.buffer.active;
    const cursorY = buffer.cursorY;
    const line = buffer.getLine(cursorY + buffer.baseY)?.translateToString().trimEnd();

    // Simple heuristic for prompt detection
    const isPrompt = /[#$%>]\s?$/.test(line);

    if (isPrompt) {
        statusDot.className = 'status-indicator-dot ready';
        statusText.textContent = 'Ready';
        isTerminalReady = true;
        lastPromptLine = cursorY + buffer.baseY;
    } else {
        statusDot.className = 'status-indicator-dot busy';
        statusText.textContent = 'Busy';
        isTerminalReady = false;
    }
}

// --- Agent Logic ---

async function runAgent(task) {
    if (!localStorage.getItem('openrouter_api_key')) {
        addLog('error', '請先設定 OpenRouter API Key');
        return;
    }
    if (!currentSessionId) {
        addLog('error', '請先建立 SSH 連線');
        return;
    }
    if (!socket || !socket.connected) {
        addLog('error', 'SSH 連線已斷開，請重新選擇連線');
        currentSessionId = null;
        currentConnectionNameEl.textContent = '未連線';
        statusDot.className = 'status-indicator-dot';
        statusText.textContent = 'Disconnected';
        return;
    }

    agentRunning = true;
    updateAgentUI(true);
    agentLoopController = new AbortController();
    const signal = agentLoopController.signal;

    addLog('user', task);

    const conversationHistory = [
        {
            role: 'system',
            content: `You are an expert Linux System Administrator AI Agent connected to a remote server via SSH.

CAPABILITIES:
1. Execute shell commands to gather information or perform tasks
2. Analyze terminal output and provide insights
3. Answer questions about the server based on gathered information

OUTPUT FORMAT (JSON only, no markdown):
{
  "thought": "Your analysis and reasoning...",
  "command": "shell command to execute",
  "answer": "Direct answer to user (optional)"
}

RULES:
- If user asks a QUESTION about the server (e.g., "what is the disk usage?"), gather the info with commands, then provide "answer" with your findings and set "command" to "DONE"
- If user asks for an ACTION (e.g., "delete old files"), execute commands and report progress
- NEVER use 'echo' to display answers - use the "answer" field instead
- When task is complete, set "command": "DONE"
- Avoid interactive commands (vi, nano, top, less) unless with non-interactive flags
- Use cat, grep, find, df, free, etc. for inspection
- Be concise and accurate

EXAMPLE - Question:
User: "How much disk space is available?"
Turn 1: {"thought": "Need to check disk usage", "command": "df -h"}
Turn 2: {"thought": "Disk info gathered", "command": "DONE", "answer": "The root partition has 50GB free out of 100GB (50% used)"}

EXAMPLE - Action:
User: "Clean up /tmp folder"
Turn 1: {"thought": "First check what's in /tmp", "command": "ls -la /tmp"}
Turn 2: {"thought": "Found old files, removing", "command": "rm -rf /tmp/*.log"}
Turn 3: {"thought": "Cleanup complete", "command": "DONE", "answer": "Removed 15 log files from /tmp"}`
        }
    ];

    // Initial Context
    let currentOutput = "Session Started. Waiting for command.";

    try {
        const maxTurns = 20;
        for (let turn = 0; turn < maxTurns; turn++) {
            if (signal.aborted) break;

            // 1. Construct Prompt
            const prompt = `
TASK: ${task}

CURRENT TERMINAL OUTPUT (Last 20 lines):
${getInternalTerminalContext()}

Generate your next move.
`;
            // We don't push every prompt to history to save context window, 
            // but we maintain the conversation flow. 
            // For simplicity/robustness in this "stateless" agent loop, 
            // we can just send the system prompt + task + current context every time, 
            // or maintain a short history. 
            // Let's use a sliding window of messages.

            const messages = [
                ...conversationHistory,
                { role: 'user', content: prompt }
            ];

            addLog('system', `Thinking... (Turn ${turn + 1})`);

            // 2. Call LLM
            const response = await callOpenRouter(messages, signal);
            const content = response.choices[0].message.content;

            // 3. Parse Response
            let plan;
            try {
                // Try to find JSON in the response
                const jsonMatch = content.match(/\{[\s\S]*\}/);
                if (jsonMatch) {
                    plan = JSON.parse(jsonMatch[0]);
                } else {
                    // Fallback if model didn't output JSON
                    plan = { thought: "Raw Output", command: "echo 'Model error'" };
                    addLog('error', 'Model response format error: ' + content);
                }
            } catch (e) {
                addLog('error', 'Failed to parse model response');
                break;
            }

            addLog('agent', `💭 ${plan.thought}`);

            // Display answer if provided
            if (plan.answer) {
                addLog('agent', `📋 ${plan.answer}`);
            }

            if (plan.command === 'DONE') {
                addLog('system', '✅ Agent 已完成任務');
                break;
            }

            if (plan.command && plan.command !== 'DONE') {
                addLog('agent', `⚡ 執行: ${plan.command}`);
                // 4. GUI Feedback & Execution
                await executeCommand(plan.command);
            }

            // Add to history (optional, or just rely on context)
            // conversationHistory.push({ role: 'assistant', content: content });
        }

        // If we reach here without error, task completed successfully
        agentInput.value = '';
    } catch (error) {
        if (signal.aborted) {
            addLog('system', '⏹️ Agent 已被使用者停止');
        } else {
            addLog('error', `Agent Error: ${error.message}`);
        }
        // Don't clear input on error so user can retry
    } finally {
        agentRunning = false;
        updateAgentUI(false);
        agentInput.focus();
    }
}

async function callOpenRouter(messages, signal) {
    const apiKey = localStorage.getItem('openrouter_api_key');
    const model = localStorage.getItem('openrouter_model') || DEFAULT_MODEL;

    if (!apiKey) {
        throw new Error('請先設定 OpenRouter API Key');
    }

    try {
        const response = await fetch(OPENROUTER_API_URL, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json',
                'HTTP-Referer': window.location.origin,
                'X-Title': 'WebSSH Agent',
            },
            body: JSON.stringify({
                model: model,
                messages: messages,
                temperature: 0.1
            }),
            signal
        });

        if (!response.ok) {
            const errorBody = await response.json().catch(() => ({}));
            const errorMsg = errorBody.error?.message || response.statusText;
            throw new Error(`API Error (${response.status}): ${errorMsg}`);
        }

        return await response.json();
    } catch (error) {
        console.error('[agent] OpenRouter API Error:', error);
        throw error;
    }
}

async function executeCommand(command) {
    if (!socket || !socket.connected) throw new Error('Socket disconnected');

    // Send command
    socket.emit('data', command + '\n');

    // Wait for "Ready" state (prompt detection)
    // We poll every 500ms
    const startTime = Date.now();
    const timeout = 30000; // 30s timeout for single command

    // Wait a bit for the command to echo and start processing
    await new Promise(r => setTimeout(r, 500));

    while (Date.now() - startTime < timeout) {
        // Check for password prompt
        const lastLine = getLastTerminalLine().toLowerCase();
        if (isPasswordPrompt(lastLine)) {
            addLog('system', '🔐 偵測到密碼輸入提示');
            const password = await askCredential(
                '輸入密碼',
                '請輸入要求的密碼',
                '此密碼將會發送到終端機'
            );
            if (password !== null) {
                socket.emit('data', password + '\n');
                await new Promise(r => setTimeout(r, 500)); // Wait for response
            } else {
                // User cancelled - send Ctrl+C to abort
                socket.emit('data', '\x03');
                addLog('system', '已取消密碼輸入');
                return;
            }
        }

        if (isTerminalReady) {
            // Command likely finished
            return;
        }
        await new Promise(r => setTimeout(r, 500));
    }
    // Timeout warning
    addLog('system', 'Command timed out waiting for prompt. Continuing...');
}

// Detect password prompts in terminal output
function isPasswordPrompt(line) {
    const passwordPatterns = [
        'password:',
        'password for',
        '密碼：',
        '密碼:',
        'passphrase:',
        'passphrase for',
        '[sudo]',
        'authentication password',
    ];
    return passwordPatterns.some(pattern => line.includes(pattern));
}

// Get the last non-empty line from terminal
function getLastTerminalLine() {
    if (!term) return '';
    const buffer = term.buffer.active;
    for (let i = buffer.cursorY + buffer.baseY; i >= 0; i--) {
        const line = buffer.getLine(i)?.translateToString().trim();
        if (line) return line;
    }
    return '';
}

function getInternalTerminalContext() {
    if (!term) return '';
    // Get last 20 lines
    const totalLines = term.buffer.active.length;
    const startLine = Math.max(0, totalLines - 20);
    let text = '';
    for (let i = startLine; i < totalLines; i++) {
        text += term.buffer.active.getLine(i)?.translateToString() + '\n';
    }
    return text;
}

// --- UI Helpers ---

function addLog(type, message) {
    const div = document.createElement('div');
    div.className = `log-entry ${type}`;

    // Parse markdown for agent messages
    let content;
    if (type === 'agent' && typeof marked !== 'undefined') {
        // Configure marked to open links in new tab
        const renderer = new marked.Renderer();
        renderer.link = function (href, title, text) {
            const titleAttr = title ? ` title="${title}"` : '';
            return `<a href="${href}"${titleAttr} target="_blank" rel="noopener noreferrer">${text}</a>`;
        };
        content = marked.parse(message, { renderer });
    } else {
        content = escapeHtml(message);
    }

    div.innerHTML = `<div class="fw-bold text-uppercase" style="font-size:0.7em; opacity:0.7">${type}</div><div class="log-content">${content}</div>`;
    logsContainer.appendChild(div);
    logsContainer.scrollTop = logsContainer.scrollHeight;
}

function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function updateAgentUI(running) {
    if (running) {
        startAgentBtn.classList.add('d-none');
        stopAgentBtn.classList.remove('d-none');
        agentInput.disabled = true;
    } else {
        startAgentBtn.classList.remove('d-none');
        stopAgentBtn.classList.add('d-none');
        agentInput.disabled = false;
    }
}

// --- Connection Management ---

function loadConnectionsToModal() {
    const connections = getStoredConnections();
    connectionListGroup.innerHTML = '';
    if (connections.length === 0) {
        connectionListGroup.innerHTML = '<div class="list-group-item">No connections found. Go to Terminal tab to add one.</div>';
        return;
    }
    connections.forEach(conn => {
        const item = document.createElement('a');
        item.href = '#';
        item.className = 'list-group-item list-group-item-action';
        item.innerHTML = `
        <div class="d-flex w-100 justify-content-between">
          <h5 class="mb-1">${conn.name}</h5>
          <small>${conn.host}</small>
        </div>
     `;
        item.onclick = (e) => {
            e.preventDefault();
            connectTo(conn);
            hideModal(connectionModalEl);
        };
        connectionListGroup.appendChild(item);
    });
}

// Helper function to get credential via modal
function askCredential(title, label, hint = '') {
    return new Promise((resolve) => {
        credentialModalTitle.textContent = title;
        credentialLabel.textContent = label;
        credentialHint.textContent = hint;
        credentialInput.value = '';

        const handleSubmit = () => {
            const value = credentialInput.value;
            cleanup();
            hideModal(credentialModalEl);
            resolve(value);
        };

        const handleCancel = () => {
            cleanup();
            hideModal(credentialModalEl);
            resolve(null);
        };

        const handleKeydown = (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                handleSubmit();
            } else if (e.key === 'Escape') {
                handleCancel();
            }
        };

        const cleanup = () => {
            credentialSubmitBtn.removeEventListener('click', handleSubmit);
            credentialInput.removeEventListener('keydown', handleKeydown);
            credentialModalEl.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
                btn.removeEventListener('click', handleCancel);
            });
        };

        credentialSubmitBtn.addEventListener('click', handleSubmit);
        credentialInput.addEventListener('keydown', handleKeydown);
        credentialModalEl.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
            btn.addEventListener('click', handleCancel);
        });

        showModal(credentialModalEl);
        setTimeout(() => credentialInput.focus(), 100);
    });
}

async function connectTo(conn) {
    try {
        addLog('system', `Connecting to ${conn.name}...`);
        let credentials = {};

        if (conn.authType === 'password') {
            const password = await askCredential(
                '輸入密碼',
                `${conn.username}@${conn.host} 的密碼`,
                ''
            );
            if (password === null) { addLog('system', '已取消連線'); return; }
            if (!password) { addLog('error', '密碼不可為空'); return; }
            credentials.password = password;
        } else {
            if (conn.certificate?.encryptedKey) {
                const passphrase = await askCredential(
                    '輸入 Passphrase',
                    '私鑰 Passphrase',
                    '如果私鑰沒有設定密碼，請留空直接按確定'
                );
                if (passphrase === null) { addLog('system', '已取消連線'); return; }

                // Decrypt
                try {
                    const key = await decryptPrivateKeyFromStorage(conn.certificate.encryptedKey, passphrase);
                    credentials.privateKey = key;
                    credentials.passphrase = passphrase;
                } catch (e) {
                    addLog('error', '解密私鑰失敗: ' + e.message);
                    return;
                }
            } else {
                addLog('error', 'No stored private key found. Please manage keys in Terminal tab.');
                return;
            }
        }

        const session = await createSession(conn, credentials);
        currentSessionId = session.sessionId;
        currentConnection = conn;
        currentConnectionNameEl.textContent = conn.name;

        // Connect Socket - Must use /ssh namespace and correct auth params
        socket = io('/ssh', {
            path: '/ws',
            auth: {
                sessionId: session.sessionId,
                socketToken: session.socketToken
            },
        });

        socket.on('connect', () => {
            addLog('system', 'Socket connected. Terminal ready.');
            // Waiting a bit for the DOM to be fully ready ensuring correct sizing
            setTimeout(() => {
                console.log('[agent] Focusing terminal and fitting...');
                term.focus();
                fitAddon.fit();
                console.log('[agent] Terminal fitted to:', term.cols, term.rows);
                emitResize();
            }, 500); // Increased timeout to 500ms
        });

        socket.on('data', (data) => {
            term.write(data);
        });

        socket.on('error', (err) => {
            addLog('error', 'Socket error: ' + err);
        });

        socket.on('disconnect', (reason) => {
            addLog('system', `連線已斷開: ${reason}`);
            statusDot.className = 'status-indicator-dot';
            statusText.textContent = 'Disconnected';
            currentSessionId = null;
            currentConnectionNameEl.textContent = '未連線 (請重新連線)';

            // Stop agent if running
            if (agentRunning && agentLoopController) {
                agentLoopController.abort();
            }
        });

    } catch (error) {
        addLog('error', 'Connection failed: ' + error.message);
    }
}

// --- Event Listeners ---

document.addEventListener('DOMContentLoaded', initView);

// Warn before leaving page
window.addEventListener('beforeunload', (e) => {
    if (currentSessionId || agentRunning) {
        e.preventDefault();
        e.returnValue = ''; // Required for Chrome
        return '您有正在進行的 SSH 連線或 Agent 任務，確定要離開嗎？';
    }
});

saveApiKeyBtn.addEventListener('click', () => {
    const key = apiKeyInput.value.trim();
    const model = modelIdInput.value.trim();
    if (key) {
        localStorage.setItem('openrouter_api_key', key);
        localStorage.setItem('openrouter_model', model);
        modelDisplay.textContent = model;
        addLog('system', 'Settings saved.');
    }
});
// Manual Modal Handling
function showModal(modalEl) {
    modalEl.classList.add('show', 'd-block');
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop fade show';
    backdrop.id = modalEl.id + '-backdrop';
    document.body.appendChild(backdrop);

    // Close on backdrop click (if not static)
    backdrop.addEventListener('click', () => hideModal(modalEl));
}

function hideModal(modalEl) {
    modalEl.classList.remove('show', 'd-block');
    const backdrop = document.getElementById(modalEl.id + '-backdrop');
    if (backdrop) backdrop.remove();
}

// Bind Close Buttons
document.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
    btn.addEventListener('click', (e) => {
        const modal = e.target.closest('.modal');
        hideModal(modal);
    });
});

selectConnectionBtn.addEventListener('click', () => {
    loadConnectionsToModal();
    showModal(connectionModalEl);
});

settingsBtn.addEventListener('click', () => {
    showModal(apiKeyModalEl);
});

// Store the task for clearing on success
let currentTask = '';

function submitTask() {
    const task = agentInput.value.trim();
    if (!task) return;
    currentTask = task;
    runAgent(task);
}

startAgentBtn.addEventListener('click', submitTask);

// Enter key to submit (Shift+Enter for new line)
agentInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        submitTask();
    }
});

stopAgentBtn.addEventListener('click', () => {
    if (agentLoopController) {
        agentLoopController.abort();
    }
});

clearLogsBtn.addEventListener('click', () => {
    logsContainer.innerHTML = '';
});

