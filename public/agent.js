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
const confirmModalEl = document.getElementById('confirm-modal');
const confirmCommandEl = document.getElementById('confirm-command');
const confirmPurposeEl = document.getElementById('confirm-purpose');
const confirmAllowBtn = document.getElementById('confirm-allow-btn');
const confirmDenyBtn = document.getElementById('confirm-deny-btn');

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
- LANGUAGE: Always communicate in **Traditional Chinese (繁體中文)** for "thought" and "answer" fields.
- MINIMALISM: Execute only the necessary steps to complete the task. Avoid redundant info-gathering.
- EFFICIENCY: Combine commands if possible (e.g., using && or ;) to reduce turns.
- DANGEROUS COMMANDS: If a command affects multiple files or targets (e.g., 'rm', 'chmod'), list all targets clearly in your "thought" field so the user knows exactly what will be affected.
- If user asks a QUESTION, gather info then provide "answer" and set "command" to "DONE".
- If user asks for an ACTION, execute and report success.
- Use the "answer" field for communication; NEVER use 'echo' in commands for talking.
- When task is complete, set "command": "DONE".
- Avoid interactive commands (vi, nano, top, less). Use non-interactive alternatives (sed, cat, grep).
- Be extremely concise in your thoughts and answers.

EXAMPLE - Question (Efficient):
User: "Which process is using the most memory?"
Turn 1: {"thought": "檢查目前記憶體佔用最多的程序", "command": "ps -eo pid,ppid,cmd,%mem --sort=-%mem | head -n 2"}
Turn 2: {"thought": "已找到程序資訊", "command": "DONE", "answer": "目前 'node' 程序 (PID 1234) 佔用了 15% 的記憶體。"}

EXAMPLE - Action (Multiple Targets):
User: "Delete log1.txt and log2.txt"
Turn 1: {"thought": "準備刪除以下目標：\\n1. log1.txt\\n2. log2.txt", "command": "rm log1.txt log2.txt"}
Turn 2: {"thought": "刪除完成", "command": "DONE", "answer": "已成功刪除指定的兩個日誌檔案。"}`
        }
    ];

    // Initial Context
    let currentOutput = "Session Started. Waiting for command.";

    try {
        const maxTurns = 30;
        for (let turn = 0; turn < maxTurns; turn++) {
            if (signal.aborted) break;

            // 1. Construct Prompt
            const prompt = `
TASK: ${task}

CURRENT TERMINAL OUTPUT(Last 20 lines):
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

            addLog('thinking', plan.thought);

            // Display answer if provided
            if (plan.answer) {
                addLog('agent', plan.answer);
            }

            if (plan.command === 'DONE') {
                addLog('system', '✅ Agent 已完成任務');
                break;
            }

            if (plan.command && plan.command !== 'DONE') {
                addLog('agent', `⚡ 執行: ${plan.command}`);
                // 4. GUI Feedback & Execution
                await executeCommand(plan.command, plan.thought);
            }

            // Add AI response to conversation history for context continuity
            conversationHistory.push({
                role: 'assistant',
                content: content
            });

            // Add updated terminal output as user message for next turn
            conversationHistory.push({
                role: 'user',
                content: `Command executed. Current terminal output:\n${getInternalTerminalContext()}`
            });
        }

        // If we reach here without error, task completed successfully
        agentInput.value = '';
    } catch (error) {
        if (signal.aborted) {
            addLog('system', '⏹️ Agent 已被使用者停止');
        } else {
            addLog('error', `Agent Error: ${error.message} `);
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
                'Authorization': `Bearer ${apiKey} `,
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
            throw new Error(`API Error(${response.status}): ${errorMsg} `);
        }

        return await response.json();
    } catch (error) {
        console.error('[agent] OpenRouter API Error:', error);
        throw error;
    }
}

// Detect dangerous/destructive commands
function isDangerousCommand(command) {
    const dangerousPatterns = [
        // Delete operations
        /\brm\s+(-[rRfF]+\s+)?[\/\w]/,          // rm, rm -rf
        /\brmdir\b/,                              // rmdir
        /\bunlink\b/,                             // unlink

        // Format/partition operations
        /\bmkfs\b/,                               // mkfs
        /\bfdisk\b/,                              // fdisk
        /\bparted\b/,                             // parted
        /\bdd\s+.*of=/,                           // dd write operations

        // System modification
        /\bchmod\s+[0-7]*[0-7][0-7][0-7]/,        // chmod with octal
        /\bchown\b/,                              // chown
        /\bchgrp\b/,                              // chgrp

        // Service/system control
        /\bsystemctl\s+(stop|disable|mask|restart)/,  // systemctl dangerous ops
        /\bservice\s+\w+\s+(stop|restart)/,      // service stop/restart
        /\breboot\b/,                             // reboot
        /\bshutdown\b/,                           // shutdown
        /\bhalt\b/,                               // halt
        /\bpoweroff\b/,                           // poweroff

        // Package management (can break system)
        /\bapt(-get)?\s+(remove|purge|autoremove)/,  // apt remove
        /\byum\s+(remove|erase)/,                 // yum remove
        /\bdnf\s+(remove|erase)/,                 // dnf remove
        /\bpacman\s+-R/,                          // pacman remove

        // Database operations
        /\bDROP\s+(DATABASE|TABLE|INDEX)/i,       // SQL DROP
        /\bDELETE\s+FROM/i,                       // SQL DELETE
        /\bTRUNCATE\b/i,                          // SQL TRUNCATE

        // User/group management
        /\buserdel\b/,                            // userdel
        /\bgroupdel\b/,                           // groupdel
        /\bpasswd\b/,                             // passwd

        // Network
        /\biptables\s+-[FXZ]/,                    // iptables flush
        /\bufw\s+(disable|reset)/,                // ufw disable

        // Kill processes
        /\bkill\s+-9/,                            // kill -9
        /\bkillall\b/,                            // killall
        /\bpkill\b/,                              // pkill

        // Write to important locations
        />\s*\/etc\//,                            // write to /etc
        />\s*\/boot\//,                           // write to /boot

        // Dangerous pipes
        /\|\s*sh\b/,                              // pipe to shell
        /\|\s*bash\b/,                            // pipe to bash
    ];

    return dangerousPatterns.some(pattern => pattern.test(command));
}

// Ask user to confirm dangerous command
function confirmDangerousCommand(command, purpose) {
    return new Promise((resolve) => {
        confirmCommandEl.textContent = command;
        confirmPurposeEl.textContent = purpose || '未提供目的';

        const handleAllow = () => {
            cleanup();
            hideModal(confirmModalEl);
            resolve(true);
        };

        const handleDeny = () => {
            cleanup();
            hideModal(confirmModalEl);
            resolve(false);
        };

        const cleanup = () => {
            confirmAllowBtn.removeEventListener('click', handleAllow);
            confirmDenyBtn.removeEventListener('click', handleDeny);
            confirmModalEl.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
                btn.removeEventListener('click', handleDeny);
            });
        };

        confirmAllowBtn.addEventListener('click', handleAllow);
        confirmDenyBtn.addEventListener('click', handleDeny);
        confirmModalEl.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
            btn.addEventListener('click', handleDeny);
        });

        showModal(confirmModalEl);
    });
}

async function executeCommand(command, purpose) {
    if (!socket || !socket.connected) throw new Error('Socket disconnected');

    // Check for dangerous commands
    if (isDangerousCommand(command)) {
        addLog('system', '⚠️ 偵測到高風險指令，等待使用者確認...');
        const confirmed = await confirmDangerousCommand(command, purpose);
        if (!confirmed) {
            addLog('system', '❌ 使用者拒絕執行該指令');
            throw new Error('使用者拒絕執行危險指令');
        }
        addLog('system', '✅ 使用者已確認執行');
    }

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

    // Configure marked to open links in new tab
    const getMarkedContent = (text) => {
        if (typeof marked !== 'undefined') {
            const renderer = new marked.Renderer();
            renderer.link = function (href, title, text) {
                const titleAttr = title ? ` title="${title}"` : '';
                return `<a href="${href}"${titleAttr} target="_blank" rel="noopener noreferrer">${text}</a>`;
            };
            return marked.parse(text, { renderer });
        }
        return escapeHtml(text);
    };

    if (type === 'user') {
        // User message - simple, no label
        div.innerHTML = `<div class="log-content">${escapeHtml(message)}</div>`;
    } else if (type === 'thinking') {
        // Thinking message - collapsible
        const id = 'thinking-' + Date.now();
        div.innerHTML = `
            <div class="thinking-toggle collapsed" onclick="this.classList.toggle('collapsed'); document.getElementById('${id}').classList.toggle('collapsed');">
                <span class="chevron">▼</span>
                <span>💭 AI 思考過程</span>
            </div>
            <div id="${id}" class="thinking-content collapsed log-content">${getMarkedContent(message)}</div>
        `;
    } else if (type === 'agent') {
        // Agent response - with markdown
        div.innerHTML = `<div class="log-content">${getMarkedContent(message)}</div>`;
    } else if (type === 'system') {
        // System message - minimal
        div.innerHTML = `<span>${escapeHtml(message)}</span>`;
    } else {
        // Error and others
        div.innerHTML = `<div class="fw-bold text-uppercase" style="font-size:0.7em; opacity:0.7">${type}</div><div class="log-content">${escapeHtml(message)}</div>`;
    }

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

// Load connections to modal
function loadConnectionsToModal() {
    const connections = getStoredConnections();
    connectionListGroup.innerHTML = '';

    if (connections.length === 0) {
        connectionListGroup.innerHTML = `
            <div class="text-center text-muted py-4">
                <i class="ti ti-server-off mb-2" style="font-size: 2rem;"></i>
                <p>尚未建立任何連線</p>
                <p class="small">請至主頁面新增 SSH 連線</p>
            </div>
        `;
        return;
    }

    connections.forEach(conn => {
        const item = document.createElement('a');
        item.className = 'list-group-item list-group-item-action';
        item.href = '#';
        item.innerHTML = `
            <div class="d-flex align-items-center">
                <span class="avatar avatar-sm me-2 bg-blue-lt">
                    <i class="ti ti-server"></i>
                </span>
                <div class="flex-fill">
                    <div class="fw-bold">${conn.name}</div>
                    <div class="text-muted small">${conn.username}@${conn.host}:${conn.port}</div>
                </div>
                <span class="badge badge-outline text-${conn.authType === 'password' ? 'blue' : 'green'}">
                    ${conn.authType === 'password' ? '密碼' : '私鑰'}
                </span>
            </div>
        `;

        item.addEventListener('click', (e) => {
            e.preventDefault();
            hideModal(connectionModalEl);
            connectTo(conn);
        });

        connectionListGroup.appendChild(item);
    });
}

async function connectTo(conn) {
    try {
        addLog('system', `Connecting to ${conn.name}...`);
        let credentials = {};

        if (conn.authType === 'password') {
            const password = await askCredential(
                '輸入密碼',
                `${conn.username} @${conn.host} 的密碼`,
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
            addLog('system', `連線已斷開: ${reason} `);
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
    modalEl.style.display = 'block';
    modalEl.classList.add('show');
    modalEl.setAttribute('aria-modal', 'true');
    modalEl.removeAttribute('aria-hidden');

    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop fade show';
    backdrop.id = modalEl.id + '-backdrop';
    document.body.appendChild(backdrop);
    document.body.classList.add('modal-open');

    // Close on backdrop click (if not static)
    backdrop.addEventListener('click', () => hideModal(modalEl));
}

function hideModal(modalEl) {
    modalEl.style.display = 'none';
    modalEl.classList.remove('show');
    modalEl.setAttribute('aria-hidden', 'true');
    modalEl.removeAttribute('aria-modal');

    const backdrop = document.getElementById(modalEl.id + '-backdrop');
    if (backdrop) backdrop.remove();

    // Only remove modal-open if no other modals are open
    if (!document.querySelector('.modal.show')) {
        document.body.classList.remove('modal-open');
    }
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

