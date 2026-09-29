#!/usr/bin/env python3
"""
SPY - Minimalist Proxy Architecture
Backend: Python (Flask + SQLite3)
Features:
 - Access Code Registration (Access Code: 11858077)
 - Automatic 3-day expiration watchdog (disables proxy & prompts Contact Admin)
 - Cloudflare Live URL Proxy Portal & PAC File Generator
 - SQLite Database Persistence for Logs, Certificates, Users, and Open API Keys
 - Monochrome Apple macOS / iOS SF typography styling
"""

import os
import sys
import time
import json
import re
import secrets
import sqlite3
import subprocess
import threading
from urllib.parse import urlparse
from datetime import datetime, timedelta

from dotenv import load_dotenv
from flask import Flask, request, jsonify, session, send_from_directory, Response

# Load environment configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

PUBLIC_DIR = os.path.join(BASE_DIR, 'web', 'public')
DATA_DIR = os.path.join(BASE_DIR, 'data')
CERTS_DIR = os.path.join(BASE_DIR, 'certs')
DB_PATH = os.path.join(DATA_DIR, 'proxy.db')
PASSWD_FILE = os.environ.get('PASSWD_FILE', '/etc/squid/proxy_users')
LOG_FILE = os.environ.get('LOG_FILE', '/var/log/squid/access.log')
PORT = int(os.environ.get('PORT', 3050))
SQUID_PORT = int(os.environ.get('SQUID_PORT', 3128))

# Access Code & Expiration
DEFAULT_ACCESS_CODE = os.environ.get('ACCESS_CODE', '11858077')
EXPIRY_DAYS = int(os.environ.get('ACCESS_CODE_EXPIRY_DAYS', 3))
ADMIN_CONTACT = os.environ.get('ADMIN_CONTACT', 'Admin')

DEFAULT_API_KEY = os.environ.get('SPY_API_KEY', 'spy_' + secrets.token_hex(16))
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CERTS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=PUBLIC_DIR)
app.secret_key = SECRET_KEY

cloudflare_tunnel_url = 'https://proxy.mftechnologies.org'

# ==============================================================================
# Database Initialization
# ==============================================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # 1. Traffic Logs Table
    cursor.execute("""
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
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain ON traffic_logs(domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_epoch ON traffic_logs(epoch DESC)")

    # 2. Network Certificates Table
    cursor.execute("""
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
    """)

    # 3. Open API Keys Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_name TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used_at DATETIME
        )
    """)

    # 4. Proxy Users & Expiration Metadata Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS proxy_users_meta (
            username TEXT PRIMARY KEY,
            access_code TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            status TEXT DEFAULT 'active',
            is_admin INTEGER DEFAULT 0,
            notes TEXT
        )
    """)

    # Seed Admin User in metadata if not present
    cursor.execute("SELECT username FROM proxy_users_meta WHERE username = 'cantroll'")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT OR IGNORE INTO proxy_users_meta (username, access_code, expires_at, status, is_admin, notes)
            VALUES (?, ?, NULL, 'active', 1, 'Primary Admin Operator (Permanent)')
        """, ('cantroll', 'ADMIN'))

    # Seed default Open API key
    cursor.execute("SELECT COUNT(*) as count FROM api_keys")
    if cursor.fetchone()['count'] == 0:
        cursor.execute("INSERT OR IGNORE INTO api_keys (key_name, api_key) VALUES (?, ?)", 
                       ("Primary Operator Key", DEFAULT_API_KEY))

    conn.commit()
    conn.close()

# ==============================================================================
# Background Expiration Watchdog Worker
# ==============================================================================

def expiration_watchdog_worker():
    """
    Monitors user expiration timestamps every 20 seconds.
    When a user expires (after 3 days):
     1. Disables user credentials from /etc/squid/proxy_users.
     2. Updates status to 'expired'.
     3. Prompts Contact Admin on next client inquiry.
    """
    print(f"[Watchdog] Initialized. Monitoring user 3-day expirations (Access Code: {DEFAULT_ACCESS_CODE}).")
    while True:
        try:
            conn = get_db()
            cursor = conn.cursor()
            now_iso = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

            cursor.execute("""
                SELECT username, expires_at FROM proxy_users_meta
                WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?
            """, (now_iso,))
            expired_users = cursor.fetchall()

            for user in expired_users:
                uname = user['username']
                print(f"[Watchdog] Access expired for user '{uname}'. Disabling proxy...")

                # Remove from Squid password file to disable proxy
                try:
                    subprocess.run(['sudo', '/usr/bin/htpasswd', '-D', PASSWD_FILE, uname],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
                    print(f"[Watchdog] Error removing from htpasswd: {e}")

                # Mark expired in database
                cursor.execute("""
                    UPDATE proxy_users_meta SET status = 'expired' WHERE username = ?
                """, (uname,))
                conn.commit()
                print(f"[Watchdog] User '{uname}' proxy access DISABLED. Required action: Contact Admin.")

            conn.close()
        except Exception as e:
            print(f"[Watchdog] Error: {e}", file=sys.stderr)
        time.sleep(20)

# ==============================================================================
# Background Log Ingestion & Cloudflare Workers
# ==============================================================================

def log_ingestion_worker():
    last_pos = 0
    while True:
        try:
            if os.path.exists(LOG_FILE):
                size = os.path.getsize(LOG_FILE)
                if size < last_pos:
                    last_pos = 0

                if size > last_pos:
                    with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(last_pos)
                        lines = f.readlines()
                        last_pos = f.tell()

                    if lines:
                        conn = get_db()
                        cursor = conn.cursor()
                        for line in lines:
                            line_str = line.strip()
                            if not line_str:
                                continue
                            parts = line_str.split()
                            if len(parts) >= 7:
                                try:
                                    epoch = float(parts[0])
                                    date_str = datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')
                                except:
                                    epoch = time.time()
                                    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                                client_ip = parts[2]
                                status_token = parts[3]
                                status = status_token.split('/')[1] if '/' in status_token else status_token
                                try:
                                    bytes_cnt = int(parts[4])
                                except:
                                    bytes_cnt = 0
                                method = parts[5]
                                url = parts[6]
                                user = parts[7] if len(parts) > 7 and parts[7] != '-' else 'operator'
                                dest = parts[8] if len(parts) > 8 else ''

                                domain = url
                                try:
                                    if url.startswith(('http://', 'https://')):
                                        domain = urlparse(url).hostname or url
                                    else:
                                        domain = url.split(':')[0]
                                except:
                                    pass

                                cursor.execute("""
                                    INSERT OR IGNORE INTO traffic_logs
                                    (epoch, date_str, client_ip, status, bytes, method, url, domain, user, destination, raw)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (epoch, date_str, client_ip, status, bytes_cnt, method, url, domain, user, dest, line_str))
                        conn.commit()
                        conn.close()
        except Exception as e:
            print(f"[LogSync] Error: {e}", file=sys.stderr)
        time.sleep(2.0)

def cloudflare_tunnel_worker():
    global cloudflare_tunnel_url
    cloudflare_tunnel_url = 'https://proxy.mftechnologies.org'
    print(f"[Cloudflare Tunnel] Live Domain: {cloudflare_tunnel_url}")
    while True:
        try:
            res = subprocess.run(['systemctl', 'is-active', '--quiet', 'cloudflared'])
            if res.returncode == 0:
                cloudflare_tunnel_url = 'https://proxy.mftechnologies.org'
            else:
                proc = subprocess.Popen(
                    ['cloudflared', 'tunnel', '--url', f'http://127.0.0.1:{PORT}'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                for line in proc.stdout:
                    m = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
                    if m:
                        cloudflare_tunnel_url = m.group(0)
                        print(f"[Tunnel] Live Public URL: {cloudflare_tunnel_url}")
                proc.wait()
        except Exception as e:
            print(f"[Tunnel] Error: {e}", file=sys.stderr)
        time.sleep(30)

def format_bytes(b):
    if not b or b == 0:
        return '0 B'
    sizes = ['B', 'KB', 'MB', 'GB']
    i = 0
    num = float(b)
    while num >= 1024.0 and i < len(sizes) - 1:
        num /= 1024.0
        i += 1
    return f"{num:.1f} {sizes[i]}"

def verify_token_or_session():
    if session.get('authenticated'):
        return True

    api_key = request.headers.get('X-API-Key')
    if not api_key:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            api_key = auth_header[7:].strip()
    if not api_key:
        api_key = request.args.get('api_key')

    if api_key:
        if api_key in (DEFAULT_API_KEY, DEFAULT_ACCESS_CODE, '11858077'):
            return True
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM api_keys WHERE api_key = ?", (api_key,))
        row = cursor.fetchone()
        if row:
            cursor.execute("UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?", (row['id'],))
            conn.commit()
            conn.close()
            return True
        conn.close()

    return False

def require_auth():
    return verify_token_or_session()

def ensure_wireguard_routing():
    try:
        out = subprocess.check_output(['ip', 'rule', 'list'], stderr=subprocess.DEVNULL).decode()
        if 'from 10.2.0.2 lookup 51927' not in out:
            subprocess.run(['sudo', 'ip', 'rule', 'add', 'from', '10.2.0.2', 'table', '51927', 'priority', '80'], check=False)
        check_nat = subprocess.run(['sudo', 'iptables', '-t', 'nat', '-C', 'POSTROUTING', '-o', 'proton-us', '-j', 'MASQUERADE'], stderr=subprocess.DEVNULL)
        if check_nat.returncode != 0:
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'proton-us', '-j', 'MASQUERADE'], check=False)
    except Exception as e:
        print(f"[WireGuard] Warning ensuring routing: {e}")

# ==============================================================================
# Access Code Registration & Expiration APIs
# ==============================================================================

@app.route('/api/access/register', methods=['POST'])
def api_access_register():
    """
    Public Endpoint: New users enter Access Code (11858077).
    Grants 3-day access, adds user to Squid proxy, and tracks expiration.
    """
    data = request.get_json() or {}
    code = data.get('access_code', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not code or not username or not password:
        return jsonify({'error': 'Access Code, Username, and Password are required.'}), 400

    if code != DEFAULT_ACCESS_CODE:
        return jsonify({'error': 'Invalid Access Code. Contact Admin for a valid code.'}), 403

    if not re.match(r'^[a-zA-Z0-9_-]{3,24}$', username):
        return jsonify({'error': 'Username must be 3-24 alphanumeric characters or underscores.'}), 400

    conn = get_db()
    cursor = conn.cursor()

    # Check if user already exists
    cursor.execute("SELECT username, status, expires_at FROM proxy_users_meta WHERE username = ?", (username,))
    existing = cursor.fetchone()

    now = datetime.utcnow()
    expires_at = now + timedelta(days=EXPIRY_DAYS)
    expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')

    if existing:
        if existing['status'] == 'expired':
            conn.close()
            return jsonify({
                'error': f"User '{username}' has EXPIRED. Please contact Admin ({ADMIN_CONTACT}) to reactivate."
            }), 403
        else:
            conn.close()
            return jsonify({'error': f"Username '{username}' is already registered."}), 409

    # Add user to Squid htpasswd file
    proc = subprocess.run(['sudo', '/usr/bin/htpasswd', '-b', PASSWD_FILE, username, password],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        conn.close()
        return jsonify({'error': proc.stderr or 'Failed to provision proxy credentials.'}), 500

    # Save to database
    cursor.execute("""
        INSERT INTO proxy_users_meta (username, access_code, expires_at, status, is_admin, notes)
        VALUES (?, ?, ?, 'active', 0, ?)
    """, (username, code, expires_at_str, f'Registered via Access Code {code} - 3 Days Valid'))
    conn.commit()
    conn.close()

    # Return connection details
    return jsonify({
        'success': True,
        'username': username,
        'status': 'active',
        'expires_at': expires_at_str,
        'valid_days': EXPIRY_DAYS,
        'message': f"Access granted for {EXPIRY_DAYS} days! Proxy active until {expires_at_str}.",
        'connection': {
            'proxy_host': '172.238.221.236',
            'proxy_lan': '192.168.1.158',
            'proxy_tailscale': '100.87.92.72',
            'port': SQUID_PORT,
            'pac_url': f"{(cloudflare_tunnel_url or 'http://localhost:3050')}/proxy.pac?u={username}"
        }
    })

@app.route('/api/access/verify', methods=['POST'])
def api_access_verify():
    """
    Checks remaining time on a user's 3-day access.
    If expired, returns prompt to contact admin.
    """
    data = request.get_json() or {}
    username = data.get('username', '').strip()

    if not username:
        return jsonify({'error': 'Username required.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, status, expires_at, is_admin FROM proxy_users_meta WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found.'}), 404

    if user['status'] == 'expired':
        return jsonify({
            'username': username,
            'status': 'expired',
            'message': f"Access Expired. Your {EXPIRY_DAYS}-day proxy pass has ended. Contact Admin ({ADMIN_CONTACT}) to reactivate."
        })

    if not user['expires_at']:
        return jsonify({
            'username': username,
            'status': 'active',
            'expires_at': 'Permanent',
            'remaining_seconds': None
        })

    exp = datetime.strptime(user['expires_at'], '%Y-%m-%d %H:%M:%S')
    remaining = (exp - datetime.utcnow()).total_seconds()

    if remaining <= 0:
        return jsonify({
            'username': username,
            'status': 'expired',
            'message': f"Access Expired. Your {EXPIRY_DAYS}-day proxy pass has ended. Contact Admin ({ADMIN_CONTACT}) to reactivate."
        })

    hours = int(remaining // 3600)
    minutes = int((remaining % 3600) // 60)
    return jsonify({
        'username': username,
        'status': 'active',
        'expires_at': user['expires_at'],
        'remaining_formatted': f"{hours}h {minutes}m remaining"
    })

@app.route('/proxy.pac')
def serve_pac():
    """
    Proxy Auto-Config (PAC) file for automated browser/phone proxy configuration.
    Any device can enter this URL in 'Automatic Proxy Configuration'.
    """
    # If client is local or Tailscale
    pac_content = f"""function FindProxyForURL(url, host) {{
    // SPY Proxy Routing Gateway
    if (shExpMatch(host, "*.local") || isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") || isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")) {{
        return "DIRECT";
    }}
    return "PROXY 100.87.92.72:3128; PROXY 192.168.1.158:3128; PROXY 172.238.221.236:3128; DIRECT";
}}"""
    return Response(pac_content, mimetype="application/x-ns-proxy-autoconfig")

# ==============================================================================
# Admin Controls for User Expiration
# ==============================================================================

@app.route('/api/admin/users/<username>/extend', methods=['POST'])
def api_admin_extend_user(username):
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()
    new_exp = (datetime.utcnow() + timedelta(days=EXPIRY_DAYS)).strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute("""
        UPDATE proxy_users_meta SET expires_at = ?, status = 'active' WHERE username = ?
    """, (new_exp, username))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'expires_at': new_exp, 'message': f"User '{username}' extended by {EXPIRY_DAYS} days."})

# ==============================================================================
# General Routes & Static Files
# ==============================================================================

@app.route('/')
@app.route('/<path:path>')
def serve_static(path='index.html'):
    full = os.path.join(PUBLIC_DIR, path)
    if os.path.exists(full) and os.path.isfile(full):
        return send_from_directory(PUBLIC_DIR, path)
    return send_from_directory(PUBLIC_DIR, 'index.html')

@app.route('/api/me')
def api_me():
    if verify_token_or_session():
        user = session.get('username') or 'api_operator'
        return jsonify({'authenticated': True, 'username': user})
    return jsonify({'authenticated': False})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    key_or_user = data.get('username', '').strip()
    password = data.get('password', '').strip()

    # 0. Passcode login (11858077 or configured ACCESS_CODE)
    if key_or_user in (DEFAULT_ACCESS_CODE, '11858077') or password in (DEFAULT_ACCESS_CODE, '11858077'):
        session['authenticated'] = True
        session['username'] = 'operator'
        return jsonify({'success': True, 'username': 'operator'})

    # 1. Direct API Key check
    if key_or_user.startswith('spy_') and not password:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT key_name FROM api_keys WHERE api_key = ?", (key_or_user,))
        row = cursor.fetchone()
        conn.close()
        if row or key_or_user == DEFAULT_API_KEY:
            session['authenticated'] = True
            session['username'] = row['key_name'] if row else 'api_operator'
            return jsonify({'success': True, 'username': session['username']})

    # 2. Check if password is an API key
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT key_name FROM api_keys WHERE api_key = ?", (password,))
    key_row = cursor.fetchone()
    conn.close()
    if key_row or password == DEFAULT_API_KEY:
        session['authenticated'] = True
        session['username'] = key_or_user or 'operator'
        return jsonify({'success': True, 'username': session['username']})

    # 3. Check against proxy_users_meta
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, status, expires_at FROM proxy_users_meta WHERE username = ?", (key_or_user,))
    user_meta = cursor.fetchone()
    conn.close()

    if user_meta and user_meta['status'] == 'expired':
        return jsonify({
            'error': f"Access Expired. Your 3-day proxy pass has ended. Contact Admin ({ADMIN_CONTACT}) to reactivate."
        }), 403

    # Check htpasswd
    if os.path.exists(PASSWD_FILE) and key_or_user:
        try:
            with open(PASSWD_FILE, 'r') as f:
                for line in f:
                    if line.startswith(f"{key_or_user}:"):
                        session['authenticated'] = True
                        session['username'] = key_or_user
                        return jsonify({'success': True, 'username': key_or_user})
        except:
            pass

    return jsonify({'error': 'Invalid credentials or API Key.'}), 401

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/status')
def api_status():
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    squid_active = False
    try:
        out = subprocess.check_output(['systemctl', 'is-active', 'squid']).decode().strip()
        squid_active = (out == 'active')
    except:
        pass

    ip_info = {'ip': '155.117.189.107', 'city': 'Secaucus', 'region': 'NJ', 'country': 'US'}
    try:
        out = subprocess.check_output(['curl', '-s', '--max-time', '2', '--interface', '10.2.0.2', 'https://ipinfo.io/json']).decode()
        ip_info = json.loads(out)
    except:
        try:
            out = subprocess.check_output(['curl', '-s', '--max-time', '2', 'https://ipinfo.io/json']).decode()
            ip_info = json.loads(out)
        except:
            pass

    tailscale_info = {'running': False, 'selfIp': '100.87.92.72', 'hostname': 'technoblade', 'deviceCount': 0}
    try:
        out = subprocess.check_output(['tailscale', 'status', '--json']).decode()
        ts_json = json.loads(out)
        self_node = ts_json.get('Self', {})
        tailscale_info = {
            'running': ts_json.get('BackendState') == 'Running',
            'selfIp': (self_node.get('TailscaleIPs') or ['100.87.92.72'])[0],
            'hostname': self_node.get('HostName', 'technoblade'),
            'deviceCount': len(ts_json.get('Peer', {})) + 1
        }
    except:
        pass

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as totalUsers FROM proxy_users_meta WHERE status = 'active'")
    users_row = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) as totalRequests, SUM(bytes) as totalBytes, COUNT(DISTINCT domain) as uniqueDomains FROM traffic_logs")
    stats_row = cursor.fetchone()
    conn.close()

    return jsonify({
        'squid': {
            'active': squid_active,
            'port': SQUID_PORT,
            'anonymity': 'Elite L1',
            'restrictions': 'None'
        },
        'access_code': {
            'active_code': DEFAULT_ACCESS_CODE,
            'valid_days': EXPIRY_DAYS
        },
        'geo': ip_info,
        'tailscale': tailscale_info,
        'cloudflare': {
            'tunnelUrl': cloudflare_tunnel_url or '',
            'active': bool(cloudflare_tunnel_url)
        },
        'userCount': users_row['totalUsers'] if users_row else 0,
        'stats': {
            'totalRequests': stats_row['totalRequests'] if stats_row else 0,
            'totalBytes': stats_row['totalBytes'] if stats_row and stats_row['totalBytes'] else 0,
            'uniqueDomains': stats_row['uniqueDomains'] if stats_row else 0
        }
    })

# Console Endpoint
@app.route('/api/console/execute', methods=['POST'])
def api_console_execute():
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    command = data.get('command', '').strip()

    if not command:
        return jsonify({'output': ''})

    parts = command.split()
    cmd = parts[0].lower()

    if cmd == 'help':
        output = (
            "SPY Terminal Commands:\n"
            "  status       Check proxy status, ports, and egress IP\n"
            "  test         Execute external egress IP verification\n"
            "  code         Display current Access Code & duration\n"
            "  logs [N]     Display last N log lines (default: 15)\n"
            "  users        List all active and expired users\n"
            "  keys         List all active Open API keys\n"
            "  restart      Restart Squid proxy service\n"
            "  clear        Clear console screen"
        )
    elif cmd == 'code':
        output = f"[Access Code] {DEFAULT_ACCESS_CODE} (Duration: {EXPIRY_DAYS} Days before expiration)"
    elif cmd == 'status':
        try:
            sq = subprocess.check_output(['systemctl', 'is-active', 'squid']).decode().strip()
            ts = subprocess.check_output(['tailscale', 'ip', '-4']).decode().strip()
            output = (
                f"[SPY Engine]       Squid {sq.upper()}\n"
                f"[Proxy Port]       {SQUID_PORT}\n"
                f"[Tailscale IP]     {ts}\n"
                f"[Access Code]      {DEFAULT_ACCESS_CODE} ({EXPIRY_DAYS} Days Expiry)\n"
                f"[Cloudflare Live]  {cloudflare_tunnel_url or 'Connecting'}"
            )
        except Exception as e:
            output = f"Status query error: {e}"
    elif cmd == 'test':
        try:
            test_out = subprocess.check_output(['curl', '-s', '--max-time', '4', 'https://ifconfig.me']).decode().strip()
            output = f"Egress Test OK. Public IP: {test_out} (Miami, FL)"
        except Exception as e:
            output = f"Egress test failed: {e}"
    elif cmd == 'logs':
        limit = 15
        if len(parts) > 1 and parts[1].isdigit():
            limit = min(int(parts[1]), 50)
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT date_str, client_ip, method, domain, status FROM traffic_logs ORDER BY epoch DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        lines = [f"{r['date_str']} | {r['client_ip']} | {r['method']} {r['domain']} [{r['status']}]" for r in rows]
        output = "\n".join(lines) if lines else "No traffic logs recorded yet."
    elif cmd == 'users':
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username, status, expires_at FROM proxy_users_meta")
        rows = cursor.fetchall()
        conn.close()
        lines = [f"- {r['username']} [{r['status'].upper()}] (Expires: {r['expires_at'] or 'Permanent'})" for r in rows]
        output = "Registered Users:\n  " + "\n  ".join(lines)
    elif cmd == 'keys':
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT key_name, api_key FROM api_keys")
        keys = cursor.fetchall()
        conn.close()
        lines = [f"- {k['key_name']}: {k['api_key']}" for k in keys]
        output = "Active Open API Keys:\n" + "\n".join(lines)
    elif cmd == 'restart':
        try:
            subprocess.run(['sudo', '/usr/bin/systemctl', 'restart', 'squid'], check=True)
            output = "[OK] Squid service restarted."
        except Exception as e:
            output = f"[ERROR] Failed to restart: {e}"
    else:
        output = f"Command not recognized: {cmd}. Type 'help' for options."

    return jsonify({'output': output})

# Users API with Expiration Information
@app.route('/api/users')
def api_users():
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT username, access_code, created_at, expires_at, status, is_admin, notes
        FROM proxy_users_meta ORDER BY is_admin DESC, created_at DESC
    """)
    users = []
    now = datetime.utcnow()
    for row in cursor.fetchall():
        exp_str = row['expires_at']
        remaining_str = 'Permanent'
        if exp_str:
            try:
                exp_dt = datetime.strptime(exp_str, '%Y-%m-%d %H:%M:%S')
                diff = (exp_dt - now).total_seconds()
                if diff <= 0:
                    remaining_str = 'EXPIRED'
                else:
                    d = int(diff // 86400)
                    h = int((diff % 86400) // 3600)
                    remaining_str = f"{d}d {h}h left"
            except:
                remaining_str = exp_str

        users.append({
            'username': row['username'],
            'access_code': row['access_code'] or 'DIRECT',
            'created_at': row['created_at'],
            'expires_at': exp_str or 'Permanent',
            'remaining': remaining_str,
            'status': row['status'],
            'is_admin': bool(row['is_admin'])
        })
    conn.close()
    return jsonify({'users': users, 'default_access_code': DEFAULT_ACCESS_CODE, 'expiry_days': EXPIRY_DAYS})

@app.route('/api/users', methods=['POST'])
def api_add_user():
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    is_permanent = data.get('permanent', False)

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return jsonify({'error': 'Invalid username format'}), 400

    proc = subprocess.run(['sudo', '/usr/bin/htpasswd', '-b', PASSWD_FILE, username, password],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        return jsonify({'error': proc.stderr or 'Error adding user'}), 500

    exp_str = None if is_permanent else (datetime.utcnow() + timedelta(days=EXPIRY_DAYS)).strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO proxy_users_meta (username, access_code, expires_at, status, is_admin)
        VALUES (?, ?, ?, 'active', 0)
    """, (username, 'ADMIN-ADDED', exp_str))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': f"User '{username}' provisioned."})

@app.route('/api/users/<username>', methods=['DELETE'])
def api_delete_user(username):
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    proc = subprocess.run(['sudo', '/usr/bin/htpasswd', '-D', PASSWD_FILE, username],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM proxy_users_meta WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Open API Keys API
@app.route('/api/api-keys')
def api_get_keys():
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, key_name, api_key, created_at, last_used_at FROM api_keys ORDER BY id DESC")
    keys = [dict(k) for k in cursor.fetchall()]
    conn.close()
    return jsonify({'keys': keys})

@app.route('/api/api-keys', methods=['POST'])
def api_create_key():
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json() or {}
    name = data.get('name', '').strip() or 'Default Key'
    new_key = 'spy_' + secrets.token_hex(16)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO api_keys (key_name, api_key) VALUES (?, ?)", (name, new_key))
    key_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'id': key_id, 'api_key': new_key, 'name': name})

@app.route('/api/api-keys/<int:key_id>', methods=['DELETE'])
def api_delete_key(key_id):
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Traffic Logs Query
@app.route('/api/logs')
def api_logs():
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    limit = min(int(request.args.get('limit', 100)), 500)
    search = request.args.get('search', '').strip().lower()

    conn = get_db()
    cursor = conn.cursor()
    if search:
        p = f"%{search}%"
        cursor.execute("""
            SELECT * FROM traffic_logs
            WHERE LOWER(domain) LIKE ? OR LOWER(user) LIKE ? OR client_ip LIKE ? OR LOWER(method) LIKE ? OR status LIKE ?
            ORDER BY epoch DESC LIMIT ?
        """, (p, p, p, p, p, limit))
    else:
        cursor.execute("SELECT * FROM traffic_logs ORDER BY epoch DESC LIMIT ?", (limit,))

    rows = cursor.fetchall()
    conn.close()

    logs = []
    for r in rows:
        b = r['bytes'] or 0
        logs.append({
            'id': r['id'],
            'date': r['date_str'],
            'timestamp': r['epoch'],
            'clientIp': r['client_ip'],
            'status': r['status'],
            'bytes': b,
            'formattedBytes': format_bytes(b),
            'method': r['method'],
            'url': r['url'],
            'domain': r['domain'],
            'user': r['user']
        })

    return jsonify({'logs': logs, 'total': len(logs)})

# Certificates Database
@app.route('/api/certs')
def api_certs():
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, type, domain, fingerprint, expires_at, active, created_at, cert_pem FROM network_certs ORDER BY id DESC")
    certs = [dict(c) for c in cursor.fetchall()]
    conn.close()
    return jsonify({'certs': certs})

@app.route('/api/certs/<int:cert_id>/download')
def api_cert_download(cert_id):
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM network_certs WHERE id = ?", (cert_id,))
    cert = cursor.fetchone()
    conn.close()
    if not cert:
        return Response("Not found", status=404)
    name = re.sub(r'[^a-zA-Z0-9_-]', '_', cert['name'].lower())
    return Response(
        cert['cert_pem'],
        mimetype="application/x-x509-ca-cert",
        headers={"Content-Disposition": f"attachment;filename={name}.crt"}
    )

# Tailscale Devices
@app.route('/api/tailscale-peers')
def api_tailscale():
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        out = subprocess.check_output(['tailscale', 'status', '--json']).decode()
        data = json.loads(out)
        self_node = {
            'hostname': (data.get('Self') or {}).get('HostName', 'Local'),
            'ip': ((data.get('Self') or {}).get('TailscaleIPs') or [''])[0],
            'os': (data.get('Self') or {}).get('OS', 'linux'),
            'isSelf': True,
            'online': True
        }
        peers = []
        for key, p in (data.get('Peer') or {}).items():
            user = (data.get('User') or {}).get(str(p.get('UserID')), {}).get('LoginName', '')
            peers.append({
                'hostname': p.get('HostName', 'Peer'),
                'ip': (p.get('TailscaleIPs') or [''])[0],
                'os': p.get('OS', 'unknown'),
                'online': p.get('Online', True),
                'user': user
            })
        return jsonify({'self': self_node, 'peers': peers})
    except:
        return jsonify({'self': None, 'peers': []})

@app.route('/api/proxy/restart', methods=['POST'])
def api_proxy_restart():
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        subprocess.run(['sudo', '/usr/bin/systemctl', 'restart', 'squid'], check=True)
        return jsonify({'success': True, 'message': 'Squid restarted.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==============================================================================
# Entrypoint
# ==============================================================================

if __name__ == '__main__':
    print("=================================================================")
    print(" SPY - Minimalist Proxy Architecture")
    print(f" Port:             {PORT}")
    print(f" Access Code:      {DEFAULT_ACCESS_CODE} ({EXPIRY_DAYS} Days Validity)")
    print(f" Admin Contact:    {ADMIN_CONTACT}")
    print(f" Default API Key:  {DEFAULT_API_KEY}")
    print(f" Local URL:        http://localhost:{PORT}")
    print("=================================================================")

    init_db()
    ensure_wireguard_routing()
    threading.Thread(target=expiration_watchdog_worker, daemon=True).start()
    threading.Thread(target=log_ingestion_worker, daemon=True).start()
    threading.Thread(target=cloudflare_tunnel_worker, daemon=True).start()

    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
