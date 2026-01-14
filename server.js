import express from 'express';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { Client as SSHClient } from 'ssh2';
import cors from 'cors';
import helmet from 'helmet';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import ppkConverterPkg from 'ppk-to-openssh';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT ?? 8080);
const ALLOW_ANY_ORIGIN = process.env.ALLOW_ANY_ORIGIN === 'true';

const DEFAULT_ALLOWED_ORIGINS = [
  `http://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`,
  `http://[::1]:${PORT}`,
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
];

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : DEFAULT_ALLOWED_ORIGINS;

function isOriginAllowed(origin) {
  // Allow requests with no origin (like curl, Postman, same-origin)
  if (!origin) {
    console.log('[cors] allowing request with no origin header');
    return true;
  }

  // Allow all origins if explicitly configured
  if (ALLOW_ANY_ORIGIN) {
    console.log('[cors] allowing origin (ALLOW_ANY_ORIGIN=true):', origin);
    return true;
  }

  // Check explicit allowed origins list
  if (ALLOWED_ORIGINS.includes(origin)) {
    console.log('[cors] allowing origin (in allowed list):', origin);
    return true;
  }

  // In production, allow same-origin requests
  // This handles cases where the app is deployed to Railway, Vercel, etc.
  try {
    const originUrl = new URL(origin);
    const requestHost = originUrl.host;

    // If PUBLIC_URL is set (common in production), check against it
    if (process.env.PUBLIC_URL) {
      const publicUrl = new URL(process.env.PUBLIC_URL);
      if (requestHost === publicUrl.host) {
        console.log('[cors] allowing origin (matches PUBLIC_URL):', origin);
        return true;
      }
    }

    // Allow Railway deployment URLs
    if (requestHost.endsWith('.railway.app') || requestHost.endsWith('.up.railway.app')) {
      console.log('[cors] allowing origin (Railway domain):', origin);
      return true;
    }

    // Allow common deployment platforms
    if (requestHost.endsWith('.vercel.app') ||
      requestHost.endsWith('.netlify.app') ||
      requestHost.endsWith('.render.com')) {
      console.log('[cors] allowing origin (trusted platform):', origin);
      return true;
    }
  } catch (e) {
    console.warn('[cors] invalid origin URL:', origin);
  }

  console.warn('[cors] REJECTING origin:', origin);
  return false;
}

const corsOriginHandler = (origin, callback) => {
  if (isOriginAllowed(origin)) {
    return callback(null, true);
  }
  console.error('[cors] Origin not allowed:', origin);
  return callback(new Error('Origin not allowed by CORS policy'));
};

const ppkConverter = ppkConverterPkg?.default ?? ppkConverterPkg;
const parsePPK = ppkConverter?.parseFromString ?? ppkConverter?.convert;

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  path: '/ws',
  cors: {
    origin: corsOriginHandler,
    credentials: true,
  },
});

app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(cors({
  origin: corsOriginHandler,
  credentials: true,
}));
app.use(express.json({ limit: '512kb' }));

// Serve static files with proper MIME types
const staticDir = path.join(__dirname, 'public');
app.use(express.static(staticDir, {
  setHeaders: (res, filePath) => {
    // Ensure proper MIME types for ES modules
    if (filePath.endsWith('.js')) {
      res.setHeader('Content-Type', 'application/javascript; charset=UTF-8');
    } else if (filePath.endsWith('.mjs')) {
      res.setHeader('Content-Type', 'application/javascript; charset=UTF-8');
    } else if (filePath.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css; charset=UTF-8');
    }
  },
  // Disable directory listing
  index: false,
  // Add fallback for development
  fallthrough: true,
}));

// Explicitly serve index.html for root path
app.get('/', (req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'));
});

// Serve agent.html
app.get('/agent', (req, res) => {
  res.sendFile(path.join(staticDir, 'agent.html'));
});

const sessions = new Map();
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS ?? 1000 * 60 * 10); // 10 minutes

function wipeBuffer(buf) {
  if (Buffer.isBuffer(buf)) {
    buf.fill(0);
  }
}

function destroySession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return;
  sessions.delete(sessionId);
  try {
    session.shellStream?.close();
  } catch (_) {
    // ignore
  }
  session.ssh?.end();
  wipeBuffer(session.privateKey);
}

function looksLikePPK(keyText) {
  return typeof keyText === 'string' && /PuTTY-User-Key-File-\d/i.test(keyText);
}

function looksLikePEM(keyText) {
  return typeof keyText === 'string' && /-----BEGIN [\s\w-]*PRIVATE KEY-----/i.test(keyText);
}

async function normalizePrivateKey(rawKey, passphrase = '') {
  if (!rawKey || typeof rawKey !== 'string') {
    throw new Error('Private key content is empty');
  }

  const trimmed = rawKey.trim();
  if (!trimmed) {
    throw new Error('Private key content is empty');
  }

  if (looksLikePPK(trimmed)) {
    if (!parsePPK) {
      throw new Error('PPK conversion is not available');
    }
    const result = await parsePPK(trimmed, passphrase ?? '');
    return Buffer.from(result.privateKey, 'utf8');
  }

  if (looksLikePEM(trimmed)) {
    return Buffer.from(trimmed, 'utf8');
  }

  // Try treating the input as base64 encoded PEM content
  try {
    const decoded = Buffer.from(trimmed, 'base64').toString('utf8').trim();
    if (looksLikePEM(decoded)) {
      return Buffer.from(decoded, 'utf8');
    }
  } catch (error) {
    // ignore base64 decoding errors and fall through
  }

  throw new Error('Unsupported private key format. Please provide PEM, OpenSSH, or PuTTY PPK content.');
}

function validateRequestBody(body) {
  const errors = [];
  const { host, port, username, authType, password, privateKey } = body;
  if (!host) errors.push('host is required');
  if (!username) errors.push('username is required');
  if (!authType || !['password', 'certificate'].includes(authType)) {
    errors.push('authType must be password or certificate');
  }
  if (port && (Number.isNaN(Number(port)) || Number(port) <= 0)) {
    errors.push('port must be a positive number');
  }
  if (authType === 'password' && !password) {
    errors.push('password is required for password auth');
  }
  if (authType === 'certificate' && !privateKey) {
    errors.push('privateKey is required for certificate auth');
  }
  return errors;
}

app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', sessions: sessions.size });
});

app.post('/api/session', async (req, res) => {
  console.log('[session] request', {
    host: req.body?.host,
    username: req.body?.username,
    authType: req.body?.authType,
    hasKey: Boolean(req.body?.privateKey),
  });
  const errors = validateRequestBody(req.body ?? {});
  if (errors.length) {
    console.warn('[session] validation failed', errors);
    return res.status(400).json({ error: errors.join(', ') });
  }

  const {
    host,
    port = 22,
    username,
    authType,
    password,
    privateKey,
    passphrase,
  } = req.body;

  const sessionId = crypto.randomUUID();
  const socketToken = crypto.randomBytes(24).toString('hex');
  const ssh = new SSHClient();
  let privateKeyBuffer = null;

  if (authType === 'certificate') {
    if (!privateKey) {
      console.warn('[session] certificate auth missing privateKey');
      return res.status(400).json({ error: 'privateKey is required for certificate auth' });
    }
    try {
      privateKeyBuffer = await normalizePrivateKey(privateKey, passphrase);
    } catch (error) {
      console.warn('[session] failed to normalize private key', error.message);
      return res.status(400).json({ error: error.message });
    }
  }

  let responded = false;

  const timeoutHandle = setTimeout(() => {
    if (!responded) {
      responded = true;
      destroySession(sessionId);
      res.status(504).json({ error: 'SSH connection timed out' });
    }
  }, Number(process.env.CONNECT_TIMEOUT_MS ?? 1000 * 15));

  ssh
    .on('ready', () => {
      if (responded) {
        return;
      }
      responded = true;
      clearTimeout(timeoutHandle);
      sessions.set(sessionId, {
        ssh,
        socketToken,
        createdAt: Date.now(),
        privateKey: privateKeyBuffer,
      });
      res.json({ sessionId, socketToken, expiresIn: SESSION_TTL_MS });
    })
    .on('error', err => {
      if (responded) {
        return;
      }
      console.error('[session] ssh error', err);
      responded = true;
      clearTimeout(timeoutHandle);
      destroySession(sessionId);
      res.status(502).json({ error: err.message });
    })
    .on('close', () => {
      console.log('[session] ssh connection closed');
      destroySession(sessionId);
    });

  ssh.connect({
    host,
    port: Number(port),
    username,
    password: authType === 'password' ? password : undefined,
    privateKey: privateKeyBuffer ?? undefined,
    passphrase,
    readyTimeout: Number(process.env.READY_TIMEOUT_MS ?? 1000 * 15),
    keepaliveInterval: 5000,
    keepaliveCountMax: 3,
    tryKeyboard: true,
  });
});

io.of('/ssh').use((socket, next) => {
  const { sessionId, socketToken } = socket.handshake.auth ?? {};
  if (!sessionId || !socketToken) {
    return next(new Error('Missing sessionId or socketToken'));
  }
  const session = sessions.get(sessionId);
  if (!session || session.socketToken !== socketToken) {
    return next(new Error('Invalid session'));
  }
  if (Date.now() - session.createdAt > SESSION_TTL_MS) {
    destroySession(sessionId);
    return next(new Error('Session expired'));
  }
  socket.data.sessionId = sessionId;
  return next();
});

io.of('/ssh').on('connection', socket => {
  const sessionId = socket.data.sessionId;
  const session = sessions.get(sessionId);
  if (!session) {
    socket.emit('error', 'Session not found');
    socket.disconnect(true);
    return;
  }

  session.ssh.shell({ term: 'xterm-color' }, (err, stream) => {
    if (err) {
      socket.emit('error', err.message);
      socket.disconnect(true);
      destroySession(sessionId);
      return;
    }

    session.shellStream = stream;

    stream.on('data', chunk => {
      socket.emit('data', chunk.toString('utf8'));
    });
    stream.stderr.on('data', chunk => {
      socket.emit('data', chunk.toString('utf8'));
    });
    stream.on('close', () => {
      socket.emit('status', 'SSH session closed');
      socket.disconnect(true);
      destroySession(sessionId);
    });

    socket.on('data', data => {
      stream.write(data);
    });

    socket.on('resize', size => {
      if (!size) return;
      try {
        stream.setWindow(size.rows ?? 24, size.cols ?? 80, size.height ?? 480, size.width ?? 640);
      } catch (_) {
        // ignore resize errors
      }
    });

    socket.on('disconnect', () => {
      destroySession(sessionId);
    });
  });
});

setInterval(() => {
  const now = Date.now();
  for (const [sessionId, session] of sessions.entries()) {
    if (now - session.createdAt > SESSION_TTL_MS) {
      destroySession(sessionId);
    }
  }
}, 60000);

server.listen(PORT, () => {
  console.log(`WebSSH server listening on http://localhost:${PORT}`);
});
