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
const cancelEditBtn = document.getElementById('cancel-edit-btn');
const editorTitle = document.getElementById('editor-title');
const alertBox = document.getElementById('global-alert');
const connectionFileInput = connectionForm.querySelector('input[name="privateKeyFile"]');
const storedPrivateKeyField = connectionForm.querySelector('textarea[name="storedPrivateKey"]');
const storagePassphraseInput = connectionForm.querySelector('input[name="storagePassphrase"]');
const savedKeyStatusBadge = document.getElementById('saved-key-status');
const clearStoredKeyBtn = document.getElementById('clear-stored-key-btn');
connectionForm.dataset.removeStoredKey = 'false';

const credentialModal = document.getElementById('credential-modal');
const credentialForm = document.getElementById('credential-form');
const credentialPasswordBlock = credentialForm.querySelector('.credential-password-field');
const credentialCertificateBlock = credentialForm.querySelector('.credential-certificate-field');
const credentialFileInput = credentialForm.querySelector('input[name="privateKeyFile"]');
const certificateKeyInputs = credentialForm.querySelector('.certificate-key-inputs');
const closeCredentialModalBtn = document.getElementById('close-credential-modal');

const contextMenu = document.getElementById('context-menu');
const backToListBtn = document.getElementById('back-to-list-btn');
const terminalFullscreenBtn = document.getElementById('terminal-fullscreen-btn');
const terminalCard = document.getElementById('view-terminal');
const terminalWrapper = terminalCard.querySelector('.terminal-wrapper');
const terminalNameEl = document.getElementById('terminal-connection-name');
const terminalHostEl = document.getElementById('terminal-connection-host');
const activeSessionBanner = document.getElementById('active-session-banner');
const activeSessionNameEl = document.getElementById('active-session-name');
const activeSessionHostEl = document.getElementById('active-session-host');
const resumeSessionBtn = document.getElementById('resume-session-btn');
const disconnectSessionBtn = document.getElementById('disconnect-session-btn');

const term = new Terminal({
  convertEol: true,
  cursorBlink: true,
  theme: { background: '#05070d' },
});
const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(document.getElementById('terminal'));
fitAddon.fit();

let savedConnections = [];
let editingId = null;
let contextMenuTargetId = null;
let currentConnection = null;
let socket = null;
let onDataDisposable = null;
let modalBackdrop = null;
let activeSession = null;
let terminalMinimized = false;

const resizeObserver = new ResizeObserver(() => {
  fitAddon.fit();
  emitResize();
});
resizeObserver.observe(terminalWrapper);

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const DEFAULT_KDF_PARAMS = {
  memoryCost: 19456,
  iterations: 2,
  parallelism: 1,
  hashLength: 32,
};
const PBKDF2_PARAMS = {
  iterations: 210000,
  hash: 'SHA-256',
};
const ARGON2_TIMEOUT_MS = 5000;

const argon2Ready = new Promise((resolve, reject) => {
  if (window.argon2) {
    resolve(window.argon2);
    return;
  }
  const script =
    document.querySelector('script[data-argon2]') ||
    Array.from(document.querySelectorAll('script')).find(el =>
      (el.getAttribute('src') || '').includes('argon2'),
    );
  if (!script) {
    reject(new Error('Argon2 script tag not found'));
    return;
  }
  const handleLoad = () => {
    script.removeEventListener('load', handleLoad);
    script.removeEventListener('error', handleError);
    if (window.argon2) {
      resolve(window.argon2);
    } else {
      reject(new Error('Argon2 library did not initialize'));
    }
  };
  const handleError = () => {
    script.removeEventListener('load', handleLoad);
    script.removeEventListener('error', handleError);
    reject(new Error('Failed to load Argon2 script'));
  };
  script.addEventListener('load', handleLoad);
  script.addEventListener('error', handleError);
});

async function ensureArgon2() {
  const argon2 = await argon2Ready;
  if (!argon2) {
    throw new Error('Argon2 library not loaded');
  }
  return argon2;
}

function toBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function fromBase64(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function deriveEncryptionKey(passphrase, salt, params = DEFAULT_KDF_PARAMS) {
  try {
    const argon2 = await ensureArgon2();
    const hash = await Promise.race([
      argon2.hash({
        pass: passphrase,
        salt,
        type: argon2.ArgonType.Argon2id,
        memoryCost: params.memoryCost,
        time: params.iterations,
        parallelism: params.parallelism,
        hashLen: params.hashLength,
        raw: true,
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('argon2-timeout')), ARGON2_TIMEOUT_MS),
      ),
    ]);
    const key = await crypto.subtle.importKey('raw', hash.hash, { name: 'AES-GCM' }, false, [
      'encrypt',
      'decrypt',
    ]);
    return { key, kdf: 'argon2id', params };
  } catch (error) {
    console.warn('[client] Argon2 derive failed, falling back to PBKDF2', error?.message || error);
    const key = await deriveKeyPBKDF2(passphrase, salt);
    return { key, kdf: 'pbkdf2', params: PBKDF2_PARAMS };
  }
}

async function deriveKeyPBKDF2(passphrase, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_PARAMS.iterations,
      hash: PBKDF2_PARAMS.hash,
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptPrivateKeyClientside(privateKey, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  console.log('[client] encrypting private key via Argon2id', { salt: toBase64(salt) });
  const { key, kdf, params } = await deriveEncryptionKey(passphrase, salt, DEFAULT_KDF_PARAMS);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    textEncoder.encode(privateKey),
  );
  return {
    algorithm: 'AES-GCM',
    kdf,
    kdfParams: params,
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptStoredKeyClientside(storedKey, passphrase) {
  console.log('[client] decrypting stored key', { connectionId: storedKey.connectionId });
  const salt = fromBase64(storedKey.salt);
  const iv = fromBase64(storedKey.iv);
  const ciphertext = fromBase64(storedKey.ciphertext || storedKey.encrypted);
  const params = storedKey.kdfParams ?? DEFAULT_KDF_PARAMS;
  let key;
  if (storedKey.kdf === 'pbkdf2') {
    key = await deriveKeyPBKDF2(passphrase, salt);
  } else {
    key = await deriveEncryptionKey(passphrase, salt, params).then(result => result.key);
  }
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext,
  );
  return textDecoder.decode(plaintext);
}

async function fetchStoredKey(connectionId) {
  console.log('[client] fetching stored key for', connectionId);
  const response = await fetch(`/api/connections/${connectionId}/key`);
  if (!response.ok) {
    throw new Error('無法讀取已儲存的私鑰');
  }
  const body = await response.json();
  body.connectionId = connectionId;
  return body;
}

function showAlert(message, type = 'info') {
  if (!message) {
    alertBox.className = 'alert d-none';
    alertBox.textContent = '';
    return;
  }
  alertBox.textContent = message;
  alertBox.className = `alert alert-${type}`;
}

function updateStoredKeyStatus(hasStoredKey) {
  if (hasStoredKey) {
    savedKeyStatusBadge.classList.remove('d-none');
    clearStoredKeyBtn.classList.remove('d-none');
  } else {
    savedKeyStatusBadge.classList.add('d-none');
    clearStoredKeyBtn.classList.add('d-none');
  }
}

function showView(name) {
  Object.entries(views).forEach(([key, element]) => {
    element.classList.toggle('d-none', key !== name);
  });
}

function resetForm() {
  editingId = null;
  connectionIdInput.value = '';
  connectionForm.reset();
  connectionForm.port.value = 22;
  storedPrivateKeyField.value = '';
  storagePassphraseInput.value = '';
  connectionForm.dataset.removeStoredKey = 'false';
  updateStoredKeyStatus(false);
  editorTitle.textContent = '新增連線';
}

function fillForm(connection) {
  editingId = connection.id;
  connectionIdInput.value = connection.id;
  connectionForm.name.value = connection.name;
  connectionForm.host.value = connection.host;
  connectionForm.port.value = connection.port;
  connectionForm.username.value = connection.username;
  connectionForm.authType.value = connection.authType;
  storedPrivateKeyField.value = '';
  storagePassphraseInput.value = '';
  connectionForm.dataset.removeStoredKey = 'false';
  updateStoredKeyStatus(connection.hasStoredKey);
  editorTitle.textContent = `編輯：${connection.name}`;
}

async function loadConnections() {
  tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">載入中...</td></tr>`;
  showAlert('');
  try {
    console.log('[client] fetching /api/connections');
    const response = await fetch('/api/connections');
    if (!response.ok) throw new Error('無法取得連線清單');
    savedConnections = await response.json();
    console.log('[client] loaded connections', savedConnections);
    renderTable();
    showAlert('連線清單已更新', 'info');
  } catch (error) {
    console.error(error);
    showAlert(error.message, 'danger');
    tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">${error.message}</td></tr>`;
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
        <td>${
          conn.authType === 'password' ? '密碼' : conn.hasStoredKey ? '憑證 (已儲存)' : '憑證'
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

async function saveConnection(payload) {
  showAlert('');
  try {
    console.log('[client] saving connection', payload);
    const response = await fetch('/api/connections', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: '儲存失敗' }));
      throw new Error(error.error || '儲存失敗');
    }
    const body = await response.json();
    console.log('[client] connection saved', body);
    showAlert('連線設定已儲存', 'success');
    await loadConnections();
    showView('list');
    resetForm();
  } catch (error) {
    console.error(error);
    showAlert(error.message, 'danger');
  }
}

async function deleteConnection(id) {
  showAlert('');
  try {
    const response = await fetch(`/api/connections/${id}`, { method: 'DELETE' });
    if (!response.ok) throw new Error('刪除失敗');
    savedConnections = savedConnections.filter(conn => conn.id !== id);
    renderTable();
    showAlert('連線已刪除', 'success');
  } catch (error) {
    console.error(error);
    showAlert(error.message, 'danger');
  }
}

function toggleCredentialFields(authType, options = {}) {
  const { hideKeyInputs = false } = options;
  credentialPasswordBlock.classList.toggle('active', authType === 'password');
  credentialCertificateBlock.classList.toggle('active', authType === 'certificate');
  if (authType === 'certificate') {
    credentialCertificateBlock.classList.remove('d-none');
    certificateKeyInputs.classList.toggle('d-none', hideKeyInputs);
  } else {
    certificateKeyInputs.classList.remove('d-none');
  }
}

function openCredentialModal(connection) {
  currentConnection = connection;
  credentialForm.reset();
  credentialFileInput.value = '';
  const hideKeyInputs = connection.authType === 'certificate' && connection.hasStoredKey;
  toggleCredentialFields(connection.authType, { hideKeyInputs });
  credentialForm.privateKeyText.value = '';
  credentialForm.dataset.requiresStoredKey = connection.hasStoredKey ? 'true' : 'false';

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

async function startSession(connection, credentials) {
  showAlert('');
  try {
    if (socket) {
      socket.disconnect();
    }
    const payload = {
      host: connection.host,
      port: connection.port,
      username: connection.username,
      authType: connection.authType,
    };
    if (connection.authType === 'password') {
      payload.password = credentials.password;
    } else {
      if (credentials.privateKey) {
        payload.privateKey = credentials.privateKey;
    } else if ((connection.hasStoredKey || credentials.connectionId) && credentials.storagePassphrase) {
      payload.connectionId = credentials.connectionId || connection.id;
      payload.storagePassphrase = credentials.storagePassphrase;
    } else {
      throw new Error('缺少私鑰內容');
    }
      if (credentials.passphrase) {
        payload.passphrase = credentials.passphrase;
      } else if (credentials.storagePassphrase && !payload.passphrase) {
        payload.passphrase = credentials.storagePassphrase;
      }
    }
    console.log('[client] starting session', { connection: connection.id, authType: connection.authType, hasKey: Boolean(payload.privateKey) });
    const response = await fetch('/api/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: '連線建立失敗' }));
      throw new Error(error.error || '連線建立失敗');
    }
    const session = await response.json();
    openTerminal(connection, session);
    showAlert('SSH 連線已建立', 'success');
  } catch (error) {
    console.error(error);
    showAlert(error.message, 'danger');
  }
}

function openTerminal(connection, session) {
  terminalNameEl.textContent = connection.name;
  terminalHostEl.textContent = `${connection.username}@${connection.host}:${connection.port}`;
  activeSession = { connection };
  terminalMinimized = false;
  updateActiveSessionBanner();
  showView('terminal');
  initSocket(session);
  setTimeout(() => {
    term.focus();
    emitResize();
  }, 0);
}

function cleanupTerminalDisplay() {
  if (onDataDisposable) {
    onDataDisposable.dispose();
    onDataDisposable = null;
  }
  socket = null;
  term.clear();
  terminalCard.classList.remove('terminal-fullscreen');
  terminalFullscreenBtn.innerHTML = '<i class="ti ti-arrows-maximize"></i>';
}

function updateActiveSessionBanner() {
  if (activeSession && terminalMinimized) {
    activeSessionNameEl.textContent = activeSession.connection.name;
    activeSessionHostEl.textContent = `${activeSession.connection.username}@${activeSession.connection.host}:${activeSession.connection.port}`;
    activeSessionBanner.classList.remove('d-none');
  } else {
    activeSessionBanner.classList.add('d-none');
  }
}

function endActiveSession(message) {
  cleanupTerminalDisplay();
  activeSession = null;
  terminalMinimized = false;
  updateActiveSessionBanner();
  showView('list');
  if (message) {
    showAlert(message, 'info');
  }
}

function initSocket(session) {
  if (socket) {
    socket.disconnect();
  }
  socket = io('/ssh', {
    path: '/ws',
    auth: {
      sessionId: session.sessionId,
      socketToken: session.socketToken,
    },
  });
  socket.on('connect', () => {
    term.write('\r\n*** 已連線至遠端主機 ***\r\n');
    emitResize();
  });
  socket.on('data', chunk => term.write(chunk));
  socket.on('status', message => term.write(`\r\n*** ${message} ***\r\n`));
  socket.on('error', message => showAlert(message || 'Socket 錯誤', 'danger'));
  socket.on('disconnect', () => {
    term.write('\r\n*** 連線結束 ***\r\n');
    endActiveSession();
  });
  if (onDataDisposable) onDataDisposable.dispose();
  onDataDisposable = term.onData(data => socket.emit('data', data));
}

function emitResize() {
  if (!socket || !socket.connected) return;
  socket.emit('resize', {
    cols: term.cols,
    rows: term.rows,
    width: terminalWrapper.clientWidth,
    height: terminalWrapper.clientHeight,
  });
}

async function extractFileContent(input) {
  const file = input.files[0];
  if (!file) return '';
  const text = await file.text();
  input.value = '';
  return text.trim();
}

// Event bindings
addConnectionBtn.addEventListener('click', () => {
  resetForm();
  showView('editor');
});

refreshConnectionsBtn.addEventListener('click', () => loadConnections());

cancelEditBtn.addEventListener('click', () => {
  resetForm();
  showView('list');
});

connectionFileInput.addEventListener('change', async () => {
  const content = await extractFileContent(connectionFileInput);
  if (content) {
    storedPrivateKeyField.value = content;
    showAlert('已從檔案載入私鑰內容', 'info');
    connectionForm.dataset.removeStoredKey = 'false';
  }
});

clearStoredKeyBtn.addEventListener('click', () => {
  connectionForm.dataset.removeStoredKey = 'true';
  updateStoredKeyStatus(false);
  storedPrivateKeyField.value = '';
  storagePassphraseInput.value = '';
  showAlert('儲存後會清除已儲存的私鑰', 'warning');
});

connectionForm.addEventListener('submit', async event => {
  event.preventDefault();
  try {
    console.log('[client] submit connection form', { editingId });
    const formData = new FormData(connectionForm);
    let privateKey = storedPrivateKeyField.value.trim();
    if (connectionFileInput.files.length) {
      privateKey = await extractFileContent(connectionFileInput);
      storedPrivateKeyField.value = privateKey;
    }
    const storagePassphrase = storagePassphraseInput.value.trim();
    const removingStoredKey = connectionForm.dataset.removeStoredKey === 'true';
    let encryptedStoredKey = null;
    if (privateKey && storagePassphrase) {
      try {
        console.log('[client] encrypting key for storage');
        encryptedStoredKey = await encryptPrivateKeyClientside(privateKey, storagePassphrase);
        console.log('[client] key encrypted for storage');
      } catch (error) {
        console.error(error);
        showAlert('無法加密私鑰，請確認瀏覽器支援 WebCrypto/Argon2', 'danger');
        return;
      }
    }

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
      if (removingStoredKey) {
        payload.storedKey = null;
      } else if (encryptedStoredKey) {
        payload.storedKey = encryptedStoredKey;
      } else if (privateKey && !storagePassphrase) {
        console.warn('[client] passphrase missing, key will not be stored');
      }
    }
    console.log('[client] final payload before save', payload);
    await saveConnection(payload);
    connectionForm.dataset.removeStoredKey = 'false';
  } catch (error) {
    console.error('[client] submit handler error', error);
    showAlert(error.message || '儲存失敗', 'danger');
  }
});

tableBody.addEventListener('click', event => {
  const action = event.target.dataset.action;
  if (!action) return;
  const row = event.target.closest('tr[data-id]');
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
    deleteConnection(contextMenuTargetId);
  }
  contextMenu.classList.add('d-none');
});

document.addEventListener('click', event => {
  if (!contextMenu.contains(event.target)) {
    contextMenu.classList.add('d-none');
  }
});

credentialForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (!currentConnection) return;
  const payload = {};
  if (currentConnection.authType === 'password') {
    payload.password = credentialForm.password.value;
    if (!payload.password) {
      showAlert('請輸入密碼', 'warning');
      return;
    }
  } else {
    let keyText = credentialForm.privateKeyText.value.trim();
    if (!keyText && credentialForm.privateKeyFile.files.length) {
      keyText = await extractFileContent(credentialFileInput);
      credentialForm.privateKeyText.value = keyText;
    }
    if (keyText) {
      payload.privateKey = keyText;
      if (credentialForm.passphrase.value) {
        payload.passphrase = credentialForm.passphrase.value;
      }
    } else if (currentConnection.hasStoredKey) {
      const passphrase = credentialForm.passphrase.value.trim();
      if (!passphrase) {
        showAlert('請輸入 passphrase 以使用已儲存的私鑰', 'warning');
        return;
      }
      try {
        const storedKey = await fetchStoredKey(currentConnection.id);
        payload.privateKey = await decryptStoredKeyClientside(storedKey, passphrase);
        payload.passphrase = passphrase;
      } catch (error) {
        console.error(error);
        showAlert('無法解密已儲存的私鑰，請確認 passphrase', 'danger');
        return;
      }
    } else {
      showAlert('請提供私鑰內容或上傳檔案', 'warning');
      return;
    }
  }
  closeCredentialModal();
  await startSession(currentConnection, payload);
});

closeCredentialModalBtn.addEventListener('click', () => closeCredentialModal());

credentialModal.addEventListener('click', event => {
  if (event.target === credentialModal) {
    closeCredentialModal();
  }
});

backToListBtn.addEventListener('click', () => {
  if (!activeSession) {
    showView('list');
    return;
  }
  terminalMinimized = true;
  showView('list');
  updateActiveSessionBanner();
  showAlert('連線仍在背景執行中', 'info');
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

resumeSessionBtn.addEventListener('click', () => {
  if (!activeSession) return;
  terminalMinimized = false;
  showView('terminal');
  updateActiveSessionBanner();
  fitAddon.fit();
  emitResize();
  term.focus();
});

disconnectSessionBtn.addEventListener('click', () => {
  if (!activeSession) return;
  if (socket) {
    socket.disconnect();
  } else {
    endActiveSession('連線已中斷');
  }
});

window.addEventListener('resize', () => {
  fitAddon.fit();
  emitResize();
});

loadConnections();
