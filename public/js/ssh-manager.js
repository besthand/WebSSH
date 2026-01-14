// public/js/ssh-manager.js
import { textEncoder, textDecoder, bufferToBase64, base64ToBuffer } from './utils.js';

const LOCAL_STORAGE_KEY = 'webssh_connections';

// --- Crypto Functions ---

async function deriveStorageKey(passphrase, salt) {
    const baseKey = await crypto.subtle.importKey('raw', textEncoder.encode(passphrase), 'PBKDF2', false, [
        'deriveKey',
    ]);
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations: 210000,
            hash: 'SHA-256',
        },
        baseKey,
        {
            name: 'AES-GCM',
            length: 256,
        },
        false,
        ['encrypt', 'decrypt'],
    );
}

export async function encryptPrivateKeyForStorage(privateKey, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveStorageKey(passphrase, salt);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        textEncoder.encode(privateKey),
    );
    return {
        salt: bufferToBase64(salt),
        iv: bufferToBase64(iv),
        ciphertext: bufferToBase64(ciphertext),
    };
}

export async function decryptPrivateKeyFromStorage(record, passphrase) {
    const salt = base64ToBuffer(record.salt);
    const iv = base64ToBuffer(record.iv);
    const ciphertext = base64ToBuffer(record.ciphertext);
    const key = await deriveStorageKey(passphrase, salt);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return textDecoder.decode(plaintext);
}

// --- Connection Storage ---

export function getStoredConnections() {
    try {
        const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
        if (!raw) return [];
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return [];
        return parsed.map(connection => {
            // Clean up legacy potential leaks if any (though we handle this in save)
            if (connection?.certificate?.privateKey) {
                delete connection.certificate.privateKey;
                delete connection.certificate.passphrase;
            }
            return connection;
        });
    } catch (error) {
        console.error('[ssh-manager] failed to read local connections', error);
        return [];
    }
}

export function persistConnections(connections) {
    try {
        localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(connections));
    } catch (error) {
        console.error('[ssh-manager] failed to persist connections', error);
        throw new Error('無法寫入瀏覽器儲存空間');
    }
}

export function saveConnection(payload, currentConnections = null) {
    const connections = currentConnections || getStoredConnections();
    let target = payload;
    let newConnections = [...connections];

    if (payload.id) {
        const idx = newConnections.findIndex(conn => conn.id === payload.id);
        if (idx === -1) {
            throw new Error('找不到要編輯的連線');
        }
        newConnections[idx] = { ...newConnections[idx], ...payload };
        target = newConnections[idx];
    } else {
        target = {
            ...payload,
            id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
        };
        newConnections.push(target);
    }

    persistConnections(newConnections);
    return { target, connections: newConnections };
}

export function deleteConnection(id) {
    const connections = getStoredConnections().filter(conn => conn.id !== id);
    persistConnections(connections);
    return connections;
}

// --- Session API ---

export async function createSession(connection, credentials) {
    const payload = {
        host: connection.host,
        port: connection.port,
        username: connection.username,
        authType: connection.authType,
    };

    if (connection.authType === 'password') {
        payload.password = credentials.password;
    } else {
        if (!credentials.privateKey) {
            throw new Error('缺少私鑰內容');
        }
        payload.privateKey = credentials.privateKey;
        if (credentials.passphrase) {
            payload.passphrase = credentials.passphrase;
        }
    }

    console.log('[ssh-manager] creating session', { connection: connection.id, authType: connection.authType });

    const response = await fetch('/api/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: '連線建立失敗' }));
        throw new Error(error.error || '連線建立失敗');
    }

    return await response.json(); // { sessionId, socketToken, expiresIn }
}
