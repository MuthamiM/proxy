const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');

const DB_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

const DB_PATH = path.join(DB_DIR, 'proxy.db');
const db = new sqlite3.Database(DB_PATH);

// Initialize DB Tables
db.serialize(() => {
  // Traffic logs table
  db.run(`
    CREATE TABLE IF NOT EXISTS traffic_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      epoch REAL,
      date_str TEXT,
      client_ip TEXT,
      status TEXT,
      bytes INTEGER,
      method TEXT,
      url TEXT,
      domain TEXT,
      user TEXT,
      destination TEXT,
      raw TEXT UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Index for fast search
  db.run(`CREATE INDEX IF NOT EXISTS idx_logs_domain ON traffic_logs(domain)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_logs_user ON traffic_logs(user)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_logs_epoch ON traffic_logs(epoch DESC)`);

  // Network Certificates table
  db.run(`
    CREATE TABLE IF NOT EXISTS network_certs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      domain TEXT,
      cert_pem TEXT NOT NULL,
      key_pem TEXT,
      fingerprint TEXT,
      expires_at TEXT,
      active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Seed default Root CA and Cloudflare cert if empty
  db.get(`SELECT COUNT(*) as count FROM network_certs`, (err, row) => {
    if (!err && row && row.count === 0) {
      seedInitialCerts();
    }
  });
});

function seedInitialCerts() {
  console.log('[DB] Seeding initial certificates...');
  try {
    const certsDir = path.join(__dirname, '..', 'certs');
    if (!fs.existsSync(certsDir)) fs.mkdirSync(certsDir, { recursive: true });

    const caKey = path.join(certsDir, 'usa-proxy-ca.key');
    const caCert = path.join(certsDir, 'usa-proxy-ca.crt');

    if (!fs.existsSync(caCert)) {
      // Generate standard 2048-bit RSA self-signed Root CA cert for the proxy
      execSync(`openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
        -subj "/C=US/ST=Florida/L=Miami/O=USA Elite Proxy/CN=USA-Proxy-Root-CA" \
        -keyout "${caKey}" -out "${caCert}" 2>/dev/null`);
    }

    if (fs.existsSync(caCert)) {
      const certContent = fs.readFileSync(caCert, 'utf8');
      const keyContent = fs.existsSync(caKey) ? fs.readFileSync(caKey, 'utf8') : '';
      const fingerprint = execSync(`openssl x509 -noout -fingerprint -sha256 -in "${caCert}"`)
        .toString().replace('SHA256 Fingerprint=', '').trim();

      insertCert({
        name: 'USA Proxy Root CA',
        type: 'Squid Root CA',
        domain: '172.238.221.236 / technoblade.tail953a25.ts.net',
        cert_pem: certContent,
        key_pem: keyContent,
        fingerprint: fingerprint,
        expires_at: '10 Years (2036)'
      });
    }

    // Check Cloudflare cert in ~/.cloudflared/cert.pem
    const cfCertPath = path.join(process.env.HOME || '/home/cantroll', '.cloudflared', 'cert.pem');
    if (fs.existsSync(cfCertPath)) {
      const cfCertContent = fs.readFileSync(cfCertPath, 'utf8');
      insertCert({
        name: 'Cloudflare Tunnel Origin Certificate',
        type: 'Cloudflare Edge',
        domain: '*.mftechnologies.org',
        cert_pem: cfCertContent,
        key_pem: '(Managed by Cloudflared)',
        fingerprint: 'CF-TUNNEL-ORIGIN',
        expires_at: 'Active Origin'
      });
    }
  } catch (err) {
    console.error('[DB] Error seeding certs:', err.message);
  }
}

function insertCert(cert) {
  const sql = `INSERT INTO network_certs (name, type, domain, cert_pem, key_pem, fingerprint, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)`;
  db.run(sql, [cert.name, cert.type, cert.domain, cert.cert_pem, cert.key_pem, cert.fingerprint, cert.expires_at]);
}

// -------------------------------------------------------------
// Database Query Helpers
// -------------------------------------------------------------

function insertTrafficLog(log) {
  return new Promise((resolve) => {
    const sql = `INSERT OR IGNORE INTO traffic_logs 
      (epoch, date_str, client_ip, status, bytes, method, url, domain, user, destination, raw)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(sql, [
      log.timestamp || 0,
      log.date || '',
      log.clientIp || '',
      log.status || '',
      log.bytes || 0,
      log.method || '',
      log.url || '',
      log.domain || '',
      log.user || 'cantroll',
      log.destination || '',
      log.raw || ''
    ], function(err) {
      resolve({ success: !err, inserted: this ? this.changes : 0 });
    });
  });
}

function getTrafficLogs(options = {}) {
  return new Promise((resolve, reject) => {
    const limit = options.limit || 100;
    const search = options.search ? `%${options.search.toLowerCase()}%` : null;

    let sql = `SELECT * FROM traffic_logs`;
    const params = [];

    if (search) {
      sql += ` WHERE LOWER(domain) LIKE ? OR LOWER(user) LIKE ? OR client_ip LIKE ? OR LOWER(method) LIKE ? OR status LIKE ?`;
      params.push(search, search, search, search, search);
    }

    sql += ` ORDER BY epoch DESC LIMIT ?`;
    params.push(limit);

    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function getLogStats() {
  return new Promise((resolve, reject) => {
    const sql = `
      SELECT 
        COUNT(*) as totalRequests,
        SUM(bytes) as totalBytes,
        COUNT(DISTINCT domain) as uniqueDomains,
        COUNT(DISTINCT user) as activeUsers
      FROM traffic_logs
    `;
    db.get(sql, [], (err, row) => {
      if (err) return reject(err);
      resolve(row || { totalRequests: 0, totalBytes: 0, uniqueDomains: 0, activeUsers: 0 });
    });
  });
}

function getCerts() {
  return new Promise((resolve, reject) => {
    db.all(`SELECT id, name, type, domain, fingerprint, expires_at, active, created_at, cert_pem FROM network_certs ORDER BY id DESC`, [], (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function getCertById(id) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM network_certs WHERE id = ?`, [id], (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function addCert(data) {
  return new Promise((resolve, reject) => {
    const sql = `INSERT INTO network_certs (name, type, domain, cert_pem, key_pem, fingerprint, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`;
    db.run(sql, [data.name, data.type, data.domain, data.cert_pem, data.key_pem || '', data.fingerprint || '', data.expires_at || ''], function(err) {
      if (err) return reject(err);
      resolve({ id: this.lastID });
    });
  });
}

function deleteCert(id) {
  return new Promise((resolve, reject) => {
    db.run(`DELETE FROM network_certs WHERE id = ?`, [id], function(err) {
      if (err) return reject(err);
      resolve({ deleted: this.changes > 0 });
    });
  });
}

module.exports = {
  db,
  insertTrafficLog,
  getTrafficLogs,
  getLogStats,
  getCerts,
  getCertById,
  addCert,
  deleteCert
};
