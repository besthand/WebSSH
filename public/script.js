import { extractFileContent } from './js/utils.js';
import {
  getStoredConnections,
  saveConnection,
  deleteConnection,
  encryptPrivateKeyForStorage,
  decryptPrivateKeyFromStorage,
  createSession
} from './js/ssh-manager.js';

const views = {
  list: document.getElementById('view-connections'),
  editor: document.getElementById('view-editor'),
  terminal: document.getElementById('view-terminal'),
};
const tableBody = document.getElementById('connection-table-body');
const addConnectionBtn = document.getElementById('add-connection-btn');
const refreshConnectionsBtn = document.getElementById('refresh-connections-btn');
const connectionForm = document.getElementById('connection-form');
const connectionIdInput = connectionForm.querySelector('input[name="id"]');
const connectionAuthTypeSelect = connectionForm.querySelector('select[name="authType"]');
const connectionCertificateCard = document.querySelector('[data-connection-certificate]');
const connectionKeyTextField = connectionForm.querySelector('textarea[name="connectionPrivateKey"]');
const connectionKeyFileInput = connectionForm.querySelector('input[name="connectionPrivateKeyFile"]');
const connectionPassphraseField = connectionForm.querySelector('input[name="connectionPassphrase"]');
const keyWrapper = document.querySelector('[data-key-wrapper]');
const keyOverlay = document.querySelector('[data-key-overlay]');
const revealKeyBtn = document.getElementById('reveal-key-btn');
const clearKeyBtn = document.getElementById('clear-key-btn');
connectionForm.dataset.clearStoredKey = 'false';
const cancelEditBtn = document.getElementById('cancel-edit-btn');
const editorTitle = document.getElementById('editor-title');
const alertBox = document.getElementById('global-alert');
const credentialModal = document.getElementById('credential-modal');
const credentialForm = document.getElementById('credential-form');
const credentialPasswordBlock = credentialForm.querySelector('.credential-password-field');
const credentialCertificateBlock = credentialForm.querySelector('.credential-certificate-field');
const credentialFileInput = credentialForm.querySelector('input[name="privateKeyFile"]');
const credentialKeyInputs = {
  block: credentialForm.querySelector('[data-certificate-block]'),
  keyTextarea: credentialForm.querySelector('[data-certificate-key]'),
  fileInput: credentialForm.querySelector('[data-certificate-file]'),
  storedKeyHint: credentialForm.querySelector('[data-stored-key-hint]'),
};
const credentialErrorEl = document.getElementById('credential-error');
const closeCredentialModalBtn = document.getElementById('close-credential-modal');

const contextMenu = document.getElementById('context-menu');
const backToListBtn = document.getElementById('back-to-list-btn');
const terminalFullscreenBtn = document.getElementById('terminal-fullscreen-btn');
const terminalCard = document.getElementById('view-terminal');
const terminalWrapper = terminalCard.querySelector('.terminal-wrapper');
const terminalNameEl = document.getElementById('terminal-connection-name');
const terminalHostEl = document.getElementById('terminal-connection-host');
const statusDot = document.getElementById('terminal-status-dot');
const statusText = document.getElementById('terminal-status-text');
const activeSessionBanner = document.getElementById('active-session-banner');
const activeSessionNameEl = document.getElementById('active-session-name');
const activeSessionHostEl = document.getElementById('active-session-host');
const resumeSessionBtn = document.getElementById('resume-session-btn');
const disconnectSessionBtn = document.getElementById('disconnect-session-btn');
const activeSessionsCard = document.getElementById('active-sessions-card');
const activeSessionListEl = document.getElementById('active-session-list');

const term = new Terminal({
  convertEol: true,
  cursorBlink: true,
  fontSize: 15,
  fontFamily: '"JetBrains Mono", "Cascadia Code", "Fira Code", Menlo, Monaco, "Courier New", monospace',
  theme: {
    background: '#05070d',
    foreground: '#ffffff',
    cursor: '#f8f8f2',
  },
  allowProposedApi: true,
});
const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(document.getElementById('terminal'));
term.onCursorMove(updateTerminalStatus);
fitAddon.fit();



let savedConnections = getStoredConnections();
let editingId = null;


let contextMenuTargetId = null;
let currentConnection = null;
let onDataDisposable = null;
let modalBackdrop = null;
const runningSessions = new Map();
let currentSessionId = null;
const MAX_SESSION_BUFFER = 50000;


const resizeObserver = new ResizeObserver(() => {
  fitAddon.fit();
  emitResize();
});
resizeObserver.observe(terminalWrapper);


function showAlert(message, type = 'info') {
  if (!message) {
    alertBox.className = 'alert d-none';
    alertBox.textContent = '';
    return;
  }
  alertBox.textContent = message;
  alertBox.className = `alert alert-${type}`;
}

function showCredentialError(message) {
  if (!credentialErrorEl) return;
  credentialErrorEl.textContent = message;
  credentialErrorEl.classList.remove('d-none');
}

function clearCredentialError() {
  if (!credentialErrorEl) return;
  credentialErrorEl.textContent = '';
  credentialErrorEl.classList.add('d-none');
}

function showView(name) {
  Object.entries(views).forEach(([key, element]) => {
    element.classList.toggle('d-none', key !== name);
  });
}

// Crypto & Storage functions moved to ssh-manager.js and utils.js


function resetForm() {
  editingId = null;
  connectionIdInput.value = '';
  connectionForm.reset();
  connectionForm.port.value = 22;
  connectionKeyTextField.value = '';
  connectionKeyFileInput.value = '';
  connectionPassphraseField.value = '';
  editorTitle.textContent = '新增連線';
  updateConnectionAuthFields();
  setKeyBlurred(false);
  connectionForm.dataset.clearStoredKey = 'false';
}

function fillForm(connection) {
  editingId = connection.id;
  connectionIdInput.value = connection.id;
  connectionForm.name.value = connection.name;
  connectionForm.host.value = connection.host;
  connectionForm.port.value = connection.port;
  connectionForm.username.value = connection.username;
  connectionForm.authType.value = connection.authType;
  connectionKeyTextField.value = '';
  connectionPassphraseField.value = '';
  connectionKeyFileInput.value = '';
  editorTitle.textContent = `編輯：${connection.name}`;
  updateConnectionAuthFields();
  setKeyBlurred(Boolean(connection.certificate?.encryptedKey));
  connectionForm.dataset.clearStoredKey = 'false';
}

function updateConnectionAuthFields() {
  if (!connectionCertificateCard) return;
  const type = connectionAuthTypeSelect.value;
  connectionCertificateCard.classList.toggle('d-none', type !== 'certificate');
  if (type !== 'certificate') {
    setKeyBlurred(false);
  }
}

function setKeyBlurred(blurred) {
  if (!keyWrapper || !keyOverlay) return;
  keyWrapper.dataset.blurred = blurred ? 'true' : 'false';
  keyOverlay.classList.toggle('d-none', !blurred);
}

function renderActiveSessions() {
  if (!activeSessionsCard || !activeSessionListEl) {
    return;
  }
  if (!runningSessions.size) {
    activeSessionsCard.classList.add('d-none');
    activeSessionListEl.innerHTML = '<div class="list-group-item text-muted">目前沒有進行中的連線</div>';
    return;
  }
  activeSessionsCard.classList.remove('d-none');
  activeSessionListEl.innerHTML = Array.from(runningSessions.values())
    .map(info => {
      const { connection, id } = info;
      const isActive = id === currentSessionId;
      return `
        <div class="list-group-item active-session-list d-flex justify-content-between align-items-center">
          <div class="session-meta">
            <strong>${connection.name} ${isActive ? '<span class="badge bg-blue ms-2">目前顯示</span>' : ''}</strong>
            <small>${connection.username}@${connection.host}:${connection.port}</small>
          </div>
          <div class="btn-list">
            ${isActive
          ? '<button class="btn btn-sm btn-outline-secondary" data-action="resume-session" data-session-id="' +
          id +
          '"><i class="ti ti-screen-share"></i> 重新整理</button>'
          : '<button class="btn btn-sm btn-outline-primary" data-action="resume-session" data-session-id="' +
          id +
          '"><i class="ti ti-screen-share"></i> 切換</button>'
        }
            <button class="btn btn-sm btn-outline-danger" data-action="terminate-session" data-session-id="${id}">
              <i class="ti ti-plug-off"></i> 中斷
            </button>
          </div>
        </div>`;
    })
    .join('');
  updateActiveSessionBanner();
}

function updateActiveSessionBanner() {
  if (!activeSessionBanner) {
    return;
  }
  if (!runningSessions.size) {
    activeSessionBanner.classList.add('d-none');
    return;
  }
  const info =
    (currentSessionId && runningSessions.get(currentSessionId)) ||
    runningSessions.values().next().value;
  if (!info) {
    activeSessionBanner.classList.add('d-none');
    return;
  }
  activeSessionNameEl.textContent = info.connection.name;
  activeSessionHostEl.textContent = `${info.connection.username}@${info.connection.host}:${info.connection.port}`;
  activeSessionBanner.classList.remove('d-none');
}

function getCurrentSessionInfo() {
  return currentSessionId ? runningSessions.get(currentSessionId) : null;
}

function updateTerminalStatus() {
  if (!statusDot || !statusText || !currentSessionId) return;

  const activeBuffer = term.buffer.active;
  // 檢查游標所在行
  const lineIndex = activeBuffer.baseY + activeBuffer.cursorY;
  const line = activeBuffer.getLine(lineIndex);

  if (!line) return;

  const lineText = line.translateToString().trim();

  // 啟發式檢查：如果結尾是常見的 Prompt 字元
  // 偵測是否為等待輸入狀態 ($, #, %, >)
  const isPrompt = /[#$%>]\s?$/.test(lineText);

  if (isPrompt) {
    statusDot.className = 'status-indicator-dot ready';
    statusDot.title = '等待輸入指令';
    statusText.textContent = '準備就緒 (Prompt)';
  } else {
    statusDot.className = 'status-indicator-dot busy';
    statusDot.title = '正在執行或處理中';
    statusText.textContent = '忙碌中 / 執行中...';
  }
}

function handleSessionOutput(info, chunk) {
  if (currentSessionId === info.id && views.terminal && !views.terminal.classList.contains('d-none')) {
    term.write(chunk);
  } else {
    info.buffer = (info.buffer || '') + chunk;
    if (info.buffer.length > MAX_SESSION_BUFFER) {
      info.buffer = info.buffer.slice(-MAX_SESSION_BUFFER);
    }
  }
  updateTerminalStatus();
}

function switchToSession(sessionId) {
  const info = runningSessions.get(sessionId);
  if (!info) return;
  currentSessionId = sessionId;
  terminalNameEl.textContent = info.connection.name;
  terminalHostEl.textContent = `${info.connection.username}@${info.connection.host}:${info.connection.port}`;
  showView('terminal');

  // 關鍵：顯示視圖後立即重新計算大小
  setTimeout(() => {
    fitAddon.fit();
    emitResize();
  }, 50);

  setKeyBlurred(false);
  term.clear();
  if (info.buffer) {
    term.write(info.buffer);
    info.buffer = '';
  }
  if (onDataDisposable) {
    onDataDisposable.dispose();
  }
  onDataDisposable = term.onData(data => {
    const active = getCurrentSessionInfo();
    if (active) {
      active.socket.emit('data', data);
    }
  });
  emitResize();
  updateActiveSessionBanner();
  updateTerminalStatus();
  setTimeout(() => {
    term.focus();
    emitResize();
  }, 0);
}

function registerSessionSocket(connection, session) {
  const sessionId = session.sessionId;
  const socket = io('/ssh', {
    path: '/ws',
    auth: {
      sessionId,
      socketToken: session.socketToken,
    },
  });
  const info = {
    id: sessionId,
    connection,
    socket,
    buffer: '',
  };
  runningSessions.set(sessionId, info);

  socket.on('connect', () => handleSessionOutput(info, '\r\n*** 已連線至遠端主機 ***\r\n'));
  socket.on('data', chunk => handleSessionOutput(info, chunk));
  socket.on('status', message => handleSessionOutput(info, `\r\n*** ${message} ***\r\n`));
  socket.on('error', message => showAlert(message || 'Socket 錯誤', 'danger'));
  const disconnectHandler = () => {
    if (runningSessions.has(sessionId)) {
      removeRunningSession(sessionId, '連線已結束');
    }
  };
  socket.on('disconnect', disconnectHandler);
  info.disconnectHandler = disconnectHandler;

  switchToSession(sessionId);
  renderActiveSessions();
}

function removeRunningSession(sessionId, message) {
  const info = runningSessions.get(sessionId);
  if (!info) return;
  runningSessions.delete(sessionId);
  if (info.socket) {
    info.socket.off('disconnect', info.disconnectHandler);
  }
  if (currentSessionId === sessionId) {
    currentSessionId = null;
    term.write(`\r\n*** ${message} ***\r\n`);
    showView('list');
  }
  renderActiveSessions();
}

function terminateSession(sessionId, message = '連線已中斷') {
  const info = runningSessions.get(sessionId);
  if (!info) return;
  info.socket.off('disconnect', info.disconnectHandler);
  info.socket.disconnect();
  removeRunningSession(sessionId, message);
}

function loadConnections(showNotice = false) {
  savedConnections = getStoredConnections();
  renderTable();
  if (showNotice) {
    showAlert('連線清單已更新', 'info');
  } else {
    showAlert('', 'info');
  }
}

function renderTable() {
  if (!savedConnections.length) {
    tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">尚無儲存的連線</td></tr>`;
    return;
  }
  tableBody.innerHTML = savedConnections
    .map(
      conn => `
      <tr data-id="${conn.id}">
        <td>${conn.name}</td>
        <td>${conn.host}</td>
        <td>${conn.port}</td>
        <td>${conn.username}</td>
        <td>${conn.authType === 'password'
          ? '密碼'
          : conn.certificate?.encryptedKey
            ? '憑證 (已儲存)'
            : '憑證'
        }</td>
        <td>
          <div class="btn-list flex-nowrap">
            <button class="btn btn-primary" data-action="connect">
              <i class="ti ti-plug-connected"></i>
              連線
            </button>
            <button class="btn btn-outline-secondary" data-action="edit">
              <i class="ti ti-edit"></i>
              編輯
            </button>
          </div>
        </td>
      </tr>`
    )
    .join('');
}


function toggleCredentialFields(authType) {
  credentialPasswordBlock.classList.toggle('active', authType === 'password');
  credentialCertificateBlock.classList.toggle('active', authType === 'certificate');
  if (authType !== 'certificate' && credentialKeyInputs.storedKeyHint) {
    credentialKeyInputs.storedKeyHint.classList.add('d-none');
    credentialKeyInputs.keyTextarea?.classList.remove('d-none');
    credentialKeyInputs.fileInput?.classList.remove('d-none');
  }
}

function openCredentialModal(connection) {
  currentConnection = connection;
  credentialForm.reset();
  credentialFileInput.value = '';
  toggleCredentialFields(connection.authType);
  credentialForm.privateKeyText.value = '';
  credentialForm.passphrase.value = '';
  credentialForm.dataset.hasStoredKey = connection.certificate?.encryptedKey ? 'true' : 'false';
  if (connection.authType === 'certificate' && credentialKeyInputs.storedKeyHint) {
    const hasStored = Boolean(connection.certificate?.encryptedKey);
    credentialKeyInputs.storedKeyHint.classList.toggle('d-none', !hasStored);
    credentialKeyInputs.keyTextarea?.classList.toggle('d-none', hasStored);
    credentialKeyInputs.fileInput?.classList.toggle('d-none', hasStored);
  }
  clearCredentialError();

  credentialModal.classList.add('show');
  credentialModal.style.display = 'block';
  credentialModal.removeAttribute('aria-hidden');
  document.body.classList.add('modal-open');
  modalBackdrop = document.createElement('div');
  modalBackdrop.className = 'modal-backdrop fade show';
  document.body.appendChild(modalBackdrop);
}

function closeCredentialModal() {
  credentialModal.classList.remove('show');
  credentialModal.style.display = 'none';
  credentialModal.setAttribute('aria-hidden', 'true');
  document.body.classList.remove('modal-open');
  if (modalBackdrop) {
    modalBackdrop.remove();
    modalBackdrop = null;
  }
}

async function startSession(connection, credentials, { propagateError = false } = {}) {
  showAlert('');
  try {
    // Use shared ssh-manager to create the session
    const session = await createSession(connection, credentials);

    // Register the socket for UI interaction
    registerSessionSocket(connection, session);

    showAlert('SSH 連線已建立', 'success');
  } catch (error) {
    console.error(error);
    if (propagateError) {
      throw error;
    }
    showAlert(error.message, 'danger');
  }
}

function emitResize() {
  const info = getCurrentSessionInfo();
  if (!info || !info.socket.connected) return;
  info.socket.emit('resize', {
    cols: term.cols,
    rows: term.rows,
    width: terminalWrapper.clientWidth,
    height: terminalWrapper.clientHeight,
  });
}


// Event bindings
addConnectionBtn.addEventListener('click', () => {
  resetForm();
  showView('editor');
});

connectionAuthTypeSelect.addEventListener('change', updateConnectionAuthFields);
updateConnectionAuthFields();
setKeyBlurred(false);

revealKeyBtn?.addEventListener('click', async () => {
  if (!editingId) {
    showAlert('請先選擇要編輯的連線', 'info');
    return;
  }
  const connection = savedConnections.find(conn => conn.id === editingId);
  if (!connection?.certificate?.encryptedKey) {
    showAlert('此連線尚未儲存私鑰', 'info');
    return;
  }
  const passphrase = connectionPassphraseField.value.trim();
  if (!passphrase) {
    showAlert('請輸入私鑰密碼以顯示內容', 'warning');
    return;
  }
  try {
    const decrypted = await decryptPrivateKeyFromStorage(connection.certificate.encryptedKey, passphrase);
    connectionKeyTextField.value = decrypted;
    setKeyBlurred(false);
  } catch (error) {
    console.error('[client] decrypt stored key failed', error);
    showAlert('密碼錯誤或私鑰已損毀，無法顯示', 'danger');
  }
});

clearKeyBtn?.addEventListener('click', () => {
  connectionForm.dataset.clearStoredKey = 'true';
  connectionKeyTextField.value = '';
  connectionKeyFileInput.value = '';
  connectionPassphraseField.value = '';
  setKeyBlurred(false);
  showAlert('儲存後會刪除已儲存的私鑰', 'warning');
});

refreshConnectionsBtn.addEventListener('click', () => loadConnections(true));

cancelEditBtn.addEventListener('click', () => {
  resetForm();
  showView('list');
});

connectionForm.addEventListener('submit', async event => {
  event.preventDefault();
  try {
    console.log('[client] submit connection form', { editingId });
    const formData = new FormData(connectionForm);
    const payload = {
      name: formData.get('name').trim(),
      host: formData.get('host').trim(),
      port: formData.get('port') ? Number(formData.get('port')) : 22,
      username: formData.get('username').trim(),
      authType: formData.get('authType'),
    };
    if (editingId) {
      payload.id = editingId;
    }
    if (payload.authType === 'certificate') {
      let keyText = connectionKeyTextField.value.trim();
      if (!keyText && connectionKeyFileInput.files.length) {
        keyText = await extractFileContent(connectionKeyFileInput);
        connectionKeyTextField.value = keyText;
      }
      const passphrase = connectionPassphraseField.value.trim();
      const existing = editingId ? savedConnections.find(conn => conn.id === editingId) : null;
      const removingStoredKey = connectionForm.dataset.clearStoredKey === 'true';
      if (keyText) {
        if (!passphrase) {
          showAlert('請輸入私鑰密碼才能儲存', 'warning');
          return;
        }
        const encryptedKey = await encryptPrivateKeyForStorage(keyText, passphrase);
        payload.certificate = { encryptedKey };
        setKeyBlurred(true);
        connectionKeyTextField.value = '';
        connectionKeyFileInput.value = '';
        connectionForm.dataset.clearStoredKey = 'false';
      } else if (existing?.certificate?.encryptedKey && !removingStoredKey) {
        payload.certificate = existing.certificate;
        setKeyBlurred(true);
      } else if (removingStoredKey) {
        payload.certificate = null;
        setKeyBlurred(false);
        connectionForm.dataset.clearStoredKey = 'false';
      } else {
        delete payload.certificate;
        setKeyBlurred(false);
      }
    } else {
      delete payload.certificate;
      setKeyBlurred(false);
      connectionForm.dataset.clearStoredKey = 'false';
    }
    const { connections } = saveConnection(payload, savedConnections);
    savedConnections = connections;
    showAlert('連線設定已儲存', 'success');
    showView('list');
    resetForm();
    loadConnections();
  } catch (error) {
    console.error('[client] submit handler error', error);
    showAlert(error.message || '儲存失敗', 'danger');
  }
});

tableBody.addEventListener('click', event => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const action = button.dataset.action;
  const row = button.closest('tr[data-id]');
  if (!row) return;
  const connection = savedConnections.find(conn => conn.id === row.dataset.id);
  if (!connection) return;

  if (action === 'edit') {
    fillForm(connection);
    showView('editor');
  } else if (action === 'connect') {
    openCredentialModal(connection);
  }
});

tableBody.addEventListener('contextmenu', event => {
  const row = event.target.closest('tr[data-id]');
  if (!row) return;
  event.preventDefault();
  contextMenuTargetId = row.dataset.id;
  contextMenu.style.left = `${event.clientX}px`;
  contextMenu.style.top = `${event.clientY}px`;
  contextMenu.classList.remove('d-none');
});

contextMenu.addEventListener('click', event => {
  const action = event.target.closest('button')?.dataset.action;
  if (action === 'delete' && contextMenuTargetId) {
    savedConnections = deleteConnection(contextMenuTargetId);
    renderTable();
    showAlert('連線已刪除', 'success');
  }
  contextMenu.classList.add('d-none');
});

document.addEventListener('click', event => {
  if (!contextMenu.contains(event.target)) {
    contextMenu.classList.add('d-none');
  }
});

activeSessionListEl?.addEventListener('click', event => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const sessionId = button.dataset.sessionId;
  if (!sessionId) return;
  if (button.dataset.action === 'resume-session') {
    switchToSession(sessionId);
  } else if (button.dataset.action === 'terminate-session') {
    terminateSession(sessionId);
  }
});

credentialForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (!currentConnection) return;
  clearCredentialError();
  const payload = {};
  if (currentConnection.authType === 'password') {
    payload.password = credentialForm.password.value;
    if (!payload.password) {
      showCredentialError('請輸入密碼');
      return;
    }
  } else {
    let keyText = credentialForm.privateKeyText.value.trim();
    if (!keyText && credentialForm.privateKeyFile.files.length) {
      keyText = await extractFileContent(credentialFileInput);
      credentialForm.privateKeyText.value = keyText;
    }
    if (!keyText && currentConnection.certificate?.encryptedKey) {
      const storedPassphrase = credentialForm.passphrase.value.trim();
      if (!storedPassphrase) {
        showCredentialError('請輸入私鑰密碼');
        return;
      }
      try {
        keyText = await decryptPrivateKeyFromStorage(currentConnection.certificate.encryptedKey, storedPassphrase);
        payload.passphrase = storedPassphrase;
      } catch (error) {
        console.error('[client] decrypt stored key for connect failed', error);
        showCredentialError('密碼錯誤或私鑰已損毀，請重新輸入');
        return;
      }
    }
    if (keyText) {
      payload.privateKey = keyText;
      if (credentialForm.passphrase.value.trim() && !payload.passphrase) {
        payload.passphrase = credentialForm.passphrase.value.trim();
      }
    } else {
      showCredentialError('請提供私鑰內容或上傳檔案');
      return;
    }
  }
  try {
    await startSession(currentConnection, payload, { propagateError: true });
    closeCredentialModal();
  } catch (error) {
    showCredentialError(error.message || '連線失敗，請確認驗證資訊');
  }
});

closeCredentialModalBtn.addEventListener('click', () => closeCredentialModal());

credentialModal.addEventListener('click', event => {
  if (event.target === credentialModal) {
    closeCredentialModal();
  }
});

backToListBtn.addEventListener('click', () => {
  if (currentSessionId) {
    currentSessionId = null;
    term.clear();
  }
  showView('list');
  renderActiveSessions();
  if (runningSessions.size) {
    showAlert('連線仍在背景執行中', 'info');
  }
});

terminalFullscreenBtn.addEventListener('click', () => {
  terminalCard.classList.toggle('terminal-fullscreen');
  const icon = terminalCard.classList.contains('terminal-fullscreen')
    ? 'ti-arrows-minimize'
    : 'ti-arrows-maximize';
  terminalFullscreenBtn.innerHTML = `<i class="ti ${icon}"></i>`;
  fitAddon.fit();
  emitResize();
});

resumeSessionBtn?.addEventListener('click', () => {
  if (currentSessionId) return;
  const first = runningSessions.keys().next().value;
  if (first) {
    switchToSession(first);
  }
});

disconnectSessionBtn?.addEventListener('click', () => {
  const target = currentSessionId ?? (runningSessions.keys().next().value || null);
  if (target) {
    terminateSession(target);
  }
});

window.addEventListener('resize', () => {
  fitAddon.fit();
  emitResize();
});

loadConnections();
renderActiveSessions();
