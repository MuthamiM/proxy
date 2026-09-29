const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');
const dbHelper = require('./db');

const app = express();
const PORT = process.env.PORT || 3050;
const PASSWD_FILE = '/etc/squid/proxy_users';
const LOG_FILE = '/var/log/squid/access.log';

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(session({
  secret: 'usa-proxy-penguin-super-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Serve static assets from public
app.use(express.static(path.join(__dirname, 'public')));

// -------------------------------------------------------------
// Cloudflare Tunnel Management
// -------------------------------------------------------------
let cloudflareTunnelUrl = null;
let tunnelProcess = null;

function startCloudflareTunnel() {
  try {
    console.log('[Cloudflare] Starting quick tunnel on port ' + PORT + '...');
    tunnelProcess = spawn('cloudflared', ['tunnel', '--url', `http://127.0.0.1:${PORT}`]);
    
    const handleOutput = (data) => {
      const text = data.toString();
      const match = text.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/);
      if (match) {
        cloudflareTunnelUrl = match[0];
        console.log('[Cloudflare] Live Tunnel URL:', cloudflareTunnelUrl);
      }
    };

    tunnelProcess.stdout.on('data', handleOutput);
    tunnelProcess.stderr.on('data', handleOutput);

    tunnelProcess.on('close', (code) => {
      console.log(`[Cloudflare] Tunnel exited (code ${code}). Restarting in 10s...`);
      cloudflareTunnelUrl = null;
      setTimeout(startCloudflareTunnel, 10000);
    });
  } catch (err) {
    console.error('[Cloudflare] Tunnel start error:', err.message);
  }
}

startCloudflareTunnel();

// -------------------------------------------------------------
// Background Log Ingester -> SQLite Database
// -------------------------------------------------------------
let lastReadByte = 0;

function syncSquidLogsToDb() {
  try {
    if (!fs.existsSync(LOG_FILE)) return;

    const stats = fs.statSync(LOG_FILE);
    if (stats.size < lastReadByte) {
      // Log was rotated or cleared
      lastReadByte = 0;
    }

    const stream = fs.createReadStream(LOG_FILE, {
      start: lastReadByte,
      end: stats.size,
      encoding: 'utf8'
    });

    let buffer = '';
    stream.on('data', (chunk) => {
      buffer += chunk;
    });

    stream.on('end', async () => {
      lastReadByte = stats.size;
      const lines = buffer.split('\n').filter(Boolean);

      for (const line of lines) {
        const tokens = line.trim().split(/\s+/);
        if (tokens.length >= 7) {
          const epoch = parseFloat(tokens[0]);
          const dateStr = !isNaN(epoch) ? new Date(epoch * 1000).toLocaleString() : 'Recent';
          const clientIp = tokens[2];
          const statusToken = tokens[3] || '';
          const statusCode = statusToken.includes('/') ? statusToken.split('/')[1] : statusToken;
          const bytes = parseInt(tokens[4], 10) || 0;
          const method = tokens[5];
          const url = tokens[6];
          const user = tokens[7] && tokens[7] !== '-' ? tokens[7] : 'cantroll';
          const destination = tokens[8] || '';

          let domain = url;
          try {
            if (url.startsWith('http://') || url.startsWith('https://')) {
              domain = new URL(url).hostname;
            } else {
              domain = url.split(':')[0];
            }
          } catch (e) {
            domain = url;
          }

          await dbHelper.insertTrafficLog({
            timestamp: epoch,
            date: dateStr,
            clientIp,
            status: statusCode,
            bytes,
            method,
            url,
            domain,
            user,
            destination,
            raw: line.trim()
          });
        }
      }
    });
  } catch (err) {
    console.error('[LogSync] Error syncing logs to DB:', err.message);
  }
}

// Ingest logs every 3 seconds into SQLite
setInterval(syncSquidLogsToDb, 3000);
syncSquidLogsToDb();

// -------------------------------------------------------------
// Auth Middleware & Helpers
// -------------------------------------------------------------
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized. Please login.' });
}

function runCmd(cmd) {
  return new Promise((resolve) => {
    exec(cmd, { timeout: 10000 }, (error, stdout, stderr) => {
      if (error) {
        return resolve({ success: false, error: stderr || error.message, stdout: stdout ? stdout.trim() : '' });
      }
      resolve({ success: true, stdout: stdout.trim(), stderr: stderr.trim() });
    });
  });
}

// -------------------------------------------------------------
// Authentication Endpoints
// -------------------------------------------------------------
app.get('/api/me', (req, res) => {
  if (req.session && req.session.authenticated) {
    return res.json({ authenticated: true, username: req.session.username });
  }
  res.json({ authenticated: false });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  // Accept admin / cantroll with proxy password
  if ((username === 'cantroll' || username === 'admin') && (password === 'proxy2024' || password === '23748124')) {
    req.session.authenticated = true;
    req.session.username = username;
    return res.json({ success: true, username });
  }

  // Check against squid proxy_users file
  if (fs.existsSync(PASSWD_FILE)) {
    const content = fs.readFileSync(PASSWD_FILE, 'utf8');
    const lines = content.split('\n').filter(Boolean);
    const userLine = lines.find(l => l.startsWith(`${username}:`));
    if (userLine) {
      req.session.authenticated = true;
      req.session.username = username;
      return res.json({ success: true, username });
    }
  }

  return res.status(401).json({ error: 'Invalid username or password' });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// -------------------------------------------------------------
// Status & Metrics API
// -------------------------------------------------------------
app.get('/api/status', requireAuth, async (req, res) => {
  try {
    const squidCheck = await runCmd('systemctl is-active squid');
    const isSquidActive = squidCheck.stdout === 'active';

    let ipInfo = { ip: '172.238.221.236', city: 'Miami', region: 'Florida', country: 'US', org: 'Linode / Akamai' };
    const curlIp = await runCmd('curl -s --max-time 3 https://ipinfo.io/json');
    if (curlIp.success && curlIp.stdout) {
      try { ipInfo = JSON.parse(curlIp.stdout); } catch (e) {}
    }

    let tailscaleInfo = { running: false, selfIp: '100.87.92.72', hostname: 'technoblade', dnsName: 'technoblade.tail953a25.ts.net' };
    const tsCheck = await runCmd('tailscale status --json');
    if (tsCheck.success && tsCheck.stdout) {
      try {
        const tsJson = JSON.parse(tsCheck.stdout);
        tailscaleInfo = {
          running: tsJson.BackendState === 'Running',
          selfIp: (tsJson.Self && tsJson.Self.TailscaleIPs && tsJson.Self.TailscaleIPs[0]) || '100.87.92.72',
          hostname: (tsJson.Self && tsJson.Self.HostName) || 'technoblade',
          dnsName: (tsJson.Self && tsJson.Self.DNSName) || 'technoblade.tail953a25.ts.net',
          deviceCount: (tsJson.Peer ? Object.keys(tsJson.Peer).length : 0) + 1
        };
      } catch (e) {}
    }

    let userCount = 0;
    if (fs.existsSync(PASSWD_FILE)) {
      const usersData = fs.readFileSync(PASSWD_FILE, 'utf8');
      userCount = usersData.split('\n').filter(l => l.trim() && !l.startsWith('#')).length;
    }

    const logStats = await dbHelper.getLogStats();

    res.json({
      squid: {
        active: isSquidActive,
        port: 3128,
        anonymity: 'Elite (L1) Undetectable',
        uptime: 'Always On (Systemd)'
      },
      geo: ipInfo,
      tailscale: tailscaleInfo,
      cloudflare: {
        tunnelUrl: cloudflareTunnelUrl || 'Initializing...',
        active: !!cloudflareTunnelUrl
      },
      userCount,
      stats: logStats
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Database-Backed Logs API
// -------------------------------------------------------------
app.get('/api/logs', requireAuth, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 100;
    const search = req.query.search || '';

    // First ensure latest lines in access.log are pushed
    syncSquidLogsToDb();

    const logs = await dbHelper.getTrafficLogs({ limit, search });
    const formatted = logs.map(l => ({
      ...l,
      formattedBytes: formatBytes(l.bytes)
    }));

    res.json({ logs: formatted, total: formatted.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/log-stats', requireAuth, async (req, res) => {
  try {
    const stats = await dbHelper.getLogStats();
    res.json({
      ...stats,
      formattedTotalBytes: formatBytes(stats.totalBytes || 0)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// -------------------------------------------------------------
// Network Certificates Database API
// -------------------------------------------------------------
app.get('/api/certs', requireAuth, async (req, res) => {
  try {
    const certs = await dbHelper.getCerts();
    res.json({ certs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/certs/:id/download', requireAuth, async (req, res) => {
  try {
    const cert = await dbHelper.getCertById(req.params.id);
    if (!cert) return res.status(404).send('Certificate not found');

    const filename = `${cert.name.toLowerCase().replace(/[^a-z0-9_-]/g, '_')}.crt`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/x-x509-ca-cert');
    res.send(cert.cert_pem);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.post('/api/certs', requireAuth, async (req, res) => {
  try {
    const { name, type, domain, cert_pem, key_pem, expires_at } = req.body;
    if (!name || !cert_pem) {
      return res.status(400).json({ error: 'Name and certificate content (PEM) are required' });
    }

    // Extract fingerprint if possible
    let fingerprint = 'MANUAL-ENTRY';
    try {
      const tmpPath = `/tmp/cert_${Date.now()}.pem`;
      fs.writeFileSync(tmpPath, cert_pem);
      const fpResult = await runCmd(`openssl x509 -noout -fingerprint -sha256 -in ${tmpPath}`);
      if (fpResult.success) {
        fingerprint = fpResult.stdout.replace('SHA256 Fingerprint=', '').trim();
      }
      fs.unlinkSync(tmpPath);
    } catch (e) {}

    const result = await dbHelper.addCert({
      name,
      type: type || 'Custom TLS',
      domain: domain || 'General',
      cert_pem,
      key_pem: key_pem || '',
      fingerprint,
      expires_at: expires_at || 'Custom'
    });

    res.json({ success: true, id: result.id, message: 'Certificate saved to database.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/certs/:id', requireAuth, async (req, res) => {
  try {
    await dbHelper.deleteCert(req.params.id);
    res.json({ success: true, message: 'Certificate removed from database.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Proxy Users Management API
// -------------------------------------------------------------
app.get('/api/users', requireAuth, (req, res) => {
  try {
    if (!fs.existsSync(PASSWD_FILE)) {
      return res.json({ users: [] });
    }
    const content = fs.readFileSync(PASSWD_FILE, 'utf8');
    const users = content
      .split('\n')
      .filter(l => l.trim() && !l.startsWith('#'))
      .map(line => {
        const parts = line.split(':');
        return {
          username: parts[0],
          status: 'Active',
          type: 'HTTP/HTTPS Proxy'
        };
      });
    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users', requireAuth, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    return res.status(400).json({ error: 'Username can only contain alphanumeric characters, underscores, and dashes.' });
  }

  const cmd = `sudo /usr/bin/htpasswd -b ${PASSWD_FILE} "${username}" "${password}"`;
  const result = await runCmd(cmd);
  if (!result.success) {
    return res.status(500).json({ error: result.error || 'Failed to add user' });
  }

  res.json({ success: true, message: `User '${username}' saved successfully!` });
});

app.delete('/api/users/:username', requireAuth, async (req, res) => {
  const username = req.params.username;
  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }

  const cmd = `sudo /usr/bin/htpasswd -D ${PASSWD_FILE} "${username}"`;
  const result = await runCmd(cmd);
  if (!result.success) {
    return res.status(500).json({ error: result.error || 'Failed to delete user' });
  }

  res.json({ success: true, message: `User '${username}' deleted.` });
});

// -------------------------------------------------------------
// Tailscale Peers API
// -------------------------------------------------------------
app.get('/api/tailscale-peers', requireAuth, async (req, res) => {
  try {
    const tsCmd = await runCmd('tailscale status --json');
    if (!tsCmd.success || !tsCmd.stdout) {
      return res.json({ self: null, peers: [] });
    }

    const data = JSON.parse(tsCmd.stdout);
    const self = {
      hostname: (data.Self && data.Self.HostName) || 'Current Host',
      dnsName: (data.Self && data.Self.DNSName) || '',
      ip: (data.Self && data.Self.TailscaleIPs && data.Self.TailscaleIPs[0]) || '',
      os: (data.Self && data.Self.OS) || 'linux',
      isSelf: true,
      online: true
    };

    const peers = [];
    if (data.Peer) {
      for (const [key, peer] of Object.entries(data.Peer)) {
        peers.push({
          id: key,
          hostname: peer.HostName || 'Device',
          dnsName: peer.DNSName || '',
          ip: (peer.TailscaleIPs && peer.TailscaleIPs[0]) || '',
          os: peer.OS || 'unknown',
          online: peer.Online !== false,
          active: peer.Active || false,
          lastSeen: peer.LastSeen || null,
          user: data.User && data.User[peer.UserID] ? data.User[peer.UserID].LoginName : ''
        });
      }
    }

    res.json({ self, peers });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Proxy Service Control API
// -------------------------------------------------------------
app.post('/api/proxy/restart', requireAuth, async (req, res) => {
  const result = await runCmd('sudo /usr/bin/systemctl restart squid');
  if (!result.success) {
    return res.status(500).json({ error: result.error || 'Failed to restart Squid' });
  }
  res.json({ success: true, message: 'Squid proxy restarted successfully.' });
});

// Catch-all
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`=======================================================`);
  console.log(` USA Elite Proxy Dashboard with SQLite DB & Cloudflare`);
  console.log(` Local:      http://localhost:${PORT}`);
  console.log(` Tailscale:  http://100.87.92.72:${PORT}`);
  console.log(` SQLite DB:  /home/cantroll/proxy/data/proxy.db`);
  console.log(`=======================================================`);
});
