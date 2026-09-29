// ========================================================
// SPY - Monochrome Frontend Controller
// Apple / macOS Typography, Open API Keys, Simple Console
// ========================================================

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const loginView = document.getElementById('login-view');
  const dashboardView = document.getElementById('dashboard-view');
  const loginForm = document.getElementById('login-form');
  const loginError = document.getElementById('login-error');
  const loginBtn = document.getElementById('login-btn');
  const btnLogout = document.getElementById('btn-logout');

  // Status Elements
  const valPublicIp = document.getElementById('val-public-ip');
  const valTailscaleIp = document.getElementById('val-tailscale-ip');
  const valCfStatus = document.getElementById('val-cf-status');
  const cfLiveUrl = document.getElementById('cf-live-url');
  const btnCopyCfUrl = document.getElementById('btn-copy-cf-url');
  const navServerStatus = document.getElementById('nav-server-status');
  const navUsername = document.getElementById('nav-username');
  const statGeoCity = document.getElementById('stat-geo-city');
  const statGeoCountry = document.getElementById('stat-geo-country');
  const statTsIp = document.getElementById('stat-ts-ip');
  const statTsHost = document.getElementById('stat-ts-host');
  const btnRestartProxy = document.getElementById('btn-restart-proxy');

  // Tabs
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  const userTabBadge = document.getElementById('user-tab-badge');
  const tailscaleTabBadge = document.getElementById('tailscale-tab-badge');
  const certsTabBadge = document.getElementById('certs-tab-badge');
  const keysTabBadge = document.getElementById('keys-tab-badge');

  // Simple Console
  const terminalBody = document.getElementById('terminal-body');
  const terminalInput = document.getElementById('terminal-input');
  const btnClearConsole = document.getElementById('btn-clear-console');

  // Open API Keys
  const createKeyForm = document.getElementById('create-key-form');
  const keyMsg = document.getElementById('key-msg');
  const keysTableBody = document.getElementById('keys-table-body');
  const btnRefreshKeys = document.getElementById('btn-refresh-keys');

  // Users Tab
  const addUserForm = document.getElementById('add-user-form');
  const addUserMsg = document.getElementById('add-user-msg');
  const usersTableBody = document.getElementById('users-table-body');
  const btnRefreshUsers = document.getElementById('btn-refresh-users');

  // Tailscale Tab
  const tailscaleTableBody = document.getElementById('tailscale-table-body');
  const btnRefreshTailscale = document.getElementById('btn-refresh-tailscale');

  // Certs Tab
  const certsTableBody = document.getElementById('certs-table-body');
  const btnRefreshCerts = document.getElementById('btn-refresh-certs');

  // Logs Tab
  const logsTableBody = document.getElementById('logs-table-body');
  const logSearchInput = document.getElementById('log-search-input');
  const autoRefreshToggle = document.getElementById('auto-refresh-toggle');
  const btnRefreshLogs = document.getElementById('btn-refresh-logs');
  const logCountVal = document.getElementById('log-count-val');

  // Device Guides
  const devicePills = document.querySelectorAll('.device-pill');
  const guideBoxes = document.querySelectorAll('.guide-box');

  let logPollInterval = null;
  let statusPollInterval = null;

  // Toast
  window.showToast = function(msg, duration = 3000) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.remove('hidden');
    setTimeout(() => {
      toast.classList.add('hidden');
    }, duration);
  };

  // Auth Check
  checkSession();

  async function checkSession() {
    try {
      const res = await fetch('/api/me');
      const data = await res.json();
      if (data.authenticated) {
        showDashboard(data.username);
      } else {
        showLogin();
      }
    } catch (e) {
      showLogin();
    }
  }

  function showLogin() {
    loginView.classList.add('active');
    dashboardView.classList.remove('active');
    clearInterval(logPollInterval);
    clearInterval(statusPollInterval);
  }

  function showDashboard(username) {
    loginView.classList.remove('active');
    dashboardView.classList.add('active');
    if (navUsername) navUsername.textContent = username || 'operator';

    fetchStatus();
    fetchKeys();
    fetchUsers();
    fetchTailscalePeers();
    fetchCerts();
    fetchLogs();

    statusPollInterval = setInterval(fetchStatus, 5000);
    setupLogPolling();
  }

  // Login Form
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginError.classList.add('hidden');
    loginBtn.disabled = true;
    loginBtn.innerHTML = '<span>Verifying...</span>';

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value.trim();

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        showDashboard(data.username);
        showToast(`Authenticated as ${data.username}`);
      } else {
        loginError.textContent = data.error || 'Authentication rejected.';
        loginError.classList.remove('hidden');
      }
    } catch (err) {
      loginError.textContent = 'Connection error.';
      loginError.classList.remove('hidden');
    } finally {
      loginBtn.disabled = false;
      loginBtn.innerHTML = '<span>Authenticate</span>';
    }
  });

  // Logout
  btnLogout.addEventListener('click', async () => {
    try {
      await fetch('/api/logout', { method: 'POST' });
    } catch (e) {}
    showToast('Signed out.');
    showLogin();
  });

  // Navigation Tabs
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add('active');

      if (targetId === 'tab-console') {
        if (terminalInput) terminalInput.focus();
      } else if (targetId === 'tab-api-keys') {
        fetchKeys();
      } else if (targetId === 'tab-users') {
        fetchUsers();
      } else if (targetId === 'tab-tailscale') {
        fetchTailscalePeers();
      } else if (targetId === 'tab-certs') {
        fetchCerts();
      } else if (targetId === 'tab-logs') {
        fetchLogs();
      }
    });
  });

  // Device Guides
  devicePills.forEach(pill => {
    pill.addEventListener('click', () => {
      devicePills.forEach(p => p.classList.remove('active'));
      guideBoxes.forEach(b => b.classList.add('hidden'));

      pill.classList.add('active');
      const guideId = pill.getAttribute('data-guide');
      const guideBox = document.getElementById(guideId);
      if (guideBox) guideBox.classList.remove('hidden');
    });
  });

  // Simple Console Logic
  if (terminalInput) {
    terminalInput.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter') {
        const cmd = terminalInput.value.trim();
        terminalInput.value = '';
        if (!cmd) return;

        if (cmd.toLowerCase() === 'clear') {
          terminalBody.textContent = '';
          return;
        }

        appendTerminalText(`spy@operator:~$ ${cmd}\n`);

        try {
          const res = await fetch('/api/console/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: cmd })
          });
          const data = await res.json();
          appendTerminalText((data.output || '') + '\n\n');
        } catch (err) {
          appendTerminalText('[ERROR] Console communication failure\n\n');
        }
      }
    });
  }

  function appendTerminalText(text) {
    if (!terminalBody) return;
    terminalBody.textContent += text;
    terminalBody.scrollTop = terminalBody.scrollHeight;
  }

  if (btnClearConsole) {
    btnClearConsole.addEventListener('click', () => {
      if (terminalBody) terminalBody.textContent = '';
    });
  }

  // System Status
  async function fetchStatus() {
    try {
      const res = await fetch('/api/status');
      if (!res.ok) return;
      const data = await res.json();

      const ip = data.geo?.ip || '172.238.221.236';
      if (valPublicIp) valPublicIp.textContent = ip;
      if (statGeoCity) statGeoCity.textContent = `${data.geo?.city || 'Miami'}, ${data.geo?.region || 'FL'}`;
      if (statGeoCountry) statGeoCountry.textContent = data.geo?.country || 'United States';

      const tsIp = data.tailscale?.selfIp || '100.87.92.72';
      if (valTailscaleIp) valTailscaleIp.textContent = tsIp;
      if (statTsIp) statTsIp.textContent = tsIp;
      if (statTsHost) statTsHost.textContent = data.tailscale?.hostname || 'technoblade';
      if (tailscaleTabBadge && data.tailscale?.deviceCount) {
        tailscaleTabBadge.textContent = data.tailscale.deviceCount;
      }

      if (data.cloudflare?.tunnelUrl && data.cloudflare.tunnelUrl.startsWith('http')) {
        if (cfLiveUrl) {
          cfLiveUrl.href = data.cloudflare.tunnelUrl;
          cfLiveUrl.textContent = data.cloudflare.tunnelUrl;
        }
        if (valCfStatus) valCfStatus.textContent = 'Active';
      } else {
        if (cfLiveUrl) cfLiveUrl.textContent = 'Connecting...';
        if (valCfStatus) valCfStatus.textContent = 'Tunnel Init';
      }

      if (navServerStatus) {
        navServerStatus.textContent = data.squid?.active ? 'Squid Online • Port 3128' : 'Squid Restarting';
      }

      if (userTabBadge && data.userCount !== undefined) {
        userTabBadge.textContent = data.userCount;
      }
    } catch (e) {}
  }

  if (btnCopyCfUrl) {
    btnCopyCfUrl.addEventListener('click', () => {
      if (cfLiveUrl && cfLiveUrl.href && cfLiveUrl.href.startsWith('http')) {
        navigator.clipboard.writeText(cfLiveUrl.href);
        showToast('Tunnel link copied.');
      }
    });
  }

  // Restart Proxy
  if (btnRestartProxy) {
    btnRestartProxy.addEventListener('click', async () => {
      btnRestartProxy.disabled = true;
      btnRestartProxy.innerHTML = '<span>Restarting...</span>';
      try {
        const res = await fetch('/api/proxy/restart', { method: 'POST' });
        const data = await res.json();
        showToast(data.success ? 'Squid proxy restarted.' : 'Restart failed.');
      } catch (err) {
        showToast('Server communication failure.');
      } finally {
        btnRestartProxy.disabled = false;
        btnRestartProxy.innerHTML = '<span>Restart</span>';
        fetchStatus();
      }
    });
  }

  // Open API Keys Management
  async function fetchKeys() {
    try {
      const res = await fetch('/api/api-keys');
      const data = await res.json();
      if (!data.keys) return;

      if (keysTabBadge) keysTabBadge.textContent = data.keys.length;

      if (data.keys.length === 0) {
        keysTableBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No Open API Keys found.</td></tr>`;
        return;
      }

      keysTableBody.innerHTML = data.keys.map(k => `
        <tr>
          <td><strong>${escapeHtml(k.key_name)}</strong></td>
          <td>
            <code class="copyable" onclick="copyText('${escapeHtml(k.api_key)}')">${escapeHtml(k.api_key)}</code>
          </td>
          <td><span style="font-size: 0.78rem; color: var(--text-dim);">${escapeHtml(k.created_at || 'Active')}</span></td>
          <td>
            <button class="btn btn-danger btn-xs" onclick="deleteKey(${k.id})">Revoke</button>
          </td>
        </tr>
      `).join('');
    } catch (e) {
      keysTableBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">Failed to load API keys.</td></tr>`;
    }
  }

  if (btnRefreshKeys) {
    btnRefreshKeys.addEventListener('click', fetchKeys);
  }

  if (createKeyForm) {
    createKeyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('key-name').value.trim();
      try {
        const res = await fetch('/api/api-keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name })
        });
        const data = await res.json();
        if (data.success) {
          showToast(`Open API Key created.`);
          createKeyForm.reset();
          fetchKeys();
        }
      } catch (err) {}
    });
  }

  window.deleteKey = async function(id) {
    if (!confirm('Revoke this Open API Key?')) return;
    try {
      const res = await fetch(`/api/api-keys/${id}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        showToast('API Key revoked.');
        fetchKeys();
      }
    } catch (e) {}
  };

  // Proxy Users
  async function fetchUsers() {
    try {
      const res = await fetch('/api/users');
      const data = await res.json();
      if (!data.users) return;

      if (userTabBadge) userTabBadge.textContent = data.users.length;

      if (data.users.length === 0) {
        usersTableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No proxy users configured.</td></tr>`;
        return;
      }

      usersTableBody.innerHTML = data.users.map((u, i) => `
        <tr>
          <td>${i + 1}</td>
          <td><span class="mono"><strong>${escapeHtml(u.username)}</strong></span></td>
          <td><span class="status-pill">${u.type || 'HTTP/HTTPS'}</span></td>
          <td><span class="status-pill">Active</span></td>
          <td>
            <button class="btn btn-danger btn-xs" onclick="deleteProxyUser('${escapeHtml(u.username)}')">Remove</button>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      usersTableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Failed to load users.</td></tr>`;
    }
  }

  if (btnRefreshUsers) {
    btnRefreshUsers.addEventListener('click', fetchUsers);
  }

  if (addUserForm) {
    addUserForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('new-username').value.trim();
      const password = document.getElementById('new-password').value.trim();
      const btn = document.getElementById('btn-save-user');

      btn.disabled = true;
      addUserMsg.classList.add('hidden');

      try {
        const res = await fetch('/api/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(`User '${username}' saved.`);
          addUserForm.reset();
          fetchUsers();
        } else {
          addUserMsg.textContent = data.error || 'Failed to save user.';
          addUserMsg.classList.remove('hidden');
        }
      } catch (e) {
        addUserMsg.textContent = 'Server communication error.';
        addUserMsg.classList.remove('hidden');
      } finally {
        btn.disabled = false;
      }
    });
  }

  window.deleteProxyUser = async function(username) {
    if (!confirm(`Delete user '${username}'?`)) return;
    try {
      const res = await fetch(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        showToast(`User '${username}' removed.`);
        fetchUsers();
      }
    } catch (e) {}
  };

  // Tailscale Peers
  async function fetchTailscalePeers() {
    try {
      const res = await fetch('/api/tailscale-peers');
      const data = await res.json();
      const all = [];
      if (data.self) all.push(data.self);
      if (data.peers) all.push(...data.peers);

      if (tailscaleTabBadge) tailscaleTabBadge.textContent = all.length;

      if (all.length === 0) {
        tailscaleTableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No peers detected.</td></tr>`;
        return;
      }

      tailscaleTableBody.innerHTML = all.map(node => `
        <tr>
          <td>
            <strong>${escapeHtml(node.hostname)}</strong>
            ${node.isSelf ? '<span class="status-pill" style="margin-left: 6px;">Local Node</span>' : ''}
          </td>
          <td><span class="status-pill">${escapeHtml(node.os || 'linux')}</span></td>
          <td><code class="copyable" onclick="copyText('${escapeHtml(node.ip)}')">${escapeHtml(node.ip)}</code></td>
          <td><span style="font-size: 0.8rem; color: var(--text-dim);">${escapeHtml(node.user || 'Mesh Member')}</span></td>
          <td><span class="status-pill">${node.online ? 'Online' : 'Offline'}</span></td>
        </tr>
      `).join('');
    } catch (e) {
      tailscaleTableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Failed to load Tailscale peers.</td></tr>`;
    }
  }

  if (btnRefreshTailscale) {
    btnRefreshTailscale.addEventListener('click', fetchTailscalePeers);
  }

  // Network Certificates
  async function fetchCerts() {
    try {
      const res = await fetch('/api/certs');
      const data = await res.json();
      if (!data.certs) return;

      if (certsTabBadge) certsTabBadge.textContent = data.certs.length;

      if (data.certs.length === 0) {
        certsTableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No certificates stored.</td></tr>`;
        return;
      }

      certsTableBody.innerHTML = data.certs.map(c => `
        <tr>
          <td>
            <strong>${escapeHtml(c.name)}</strong>
            <div style="font-size: 0.72rem; color: var(--text-dim);">${escapeHtml(c.domain || 'All Hosts')}</div>
          </td>
          <td><span class="status-pill">${escapeHtml(c.type || 'SSL/TLS')}</span></td>
          <td>
            <code style="font-size: 0.7rem;" class="mono text-muted">
              ${escapeHtml(c.fingerprint || 'Stored')}
            </code>
          </td>
          <td><span style="font-size: 0.78rem; color: var(--text-dim);">${escapeHtml(c.expires_at || 'Permanent')}</span></td>
          <td>
            <a href="/api/certs/${c.id}/download" class="btn btn-secondary btn-xs" target="_blank">Download .crt</a>
          </td>
        </tr>
      `).join('');
    } catch (e) {
      certsTableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Error loading certificates.</td></tr>`;
    }
  }

  if (btnRefreshCerts) {
    btnRefreshCerts.addEventListener('click', fetchCerts);
  }

  // Traffic Logs
  async function fetchLogs() {
    try {
      const query = (logSearchInput ? logSearchInput.value.trim() : '');
      const res = await fetch(`/api/logs?limit=100&search=${encodeURIComponent(query)}`);
      const data = await res.json();
      if (!data.logs) return;

      if (logCountVal) logCountVal.textContent = `${data.total} requests`;

      if (data.logs.length === 0) {
        logsTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No traffic recorded yet.</td></tr>`;
        return;
      }

      logsTableBody.innerHTML = data.logs.map(l => `
        <tr>
          <td style="font-size: 0.75rem; color: var(--text-dim); white-space: nowrap;">${l.date || 'Recent'}</td>
          <td><span class="mono" style="font-weight: 500;">${escapeHtml(l.user || 'operator')}</span></td>
          <td><span class="mono" style="font-size: 0.78rem;">${escapeHtml(l.clientIp)}</span></td>
          <td><span class="method-tag">${escapeHtml(l.method || 'GET')}</span></td>
          <td>
            <div style="font-weight: 500; color: #fff;">${escapeHtml(l.domain)}</div>
            <div style="font-size: 0.72rem; color: var(--text-dim); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              ${escapeHtml(l.url)}
            </div>
          </td>
          <td><span class="status-badge">${l.status || '200'}</span></td>
          <td><span class="mono" style="font-size: 0.78rem;">${l.formattedBytes || '0 B'}</span></td>
        </tr>
      `).join('');
    } catch (e) {}
  }

  function setupLogPolling() {
    clearInterval(logPollInterval);
    if (autoRefreshToggle && autoRefreshToggle.checked) {
      logPollInterval = setInterval(fetchLogs, 2500);
    }
  }

  if (autoRefreshToggle) {
    autoRefreshToggle.addEventListener('change', setupLogPolling);
  }

  if (btnRefreshLogs) {
    btnRefreshLogs.addEventListener('click', fetchLogs);
  }

  if (logSearchInput) {
    let timer;
    logSearchInput.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(fetchLogs, 300);
    });
  }

  // Utilities
  window.copyText = function(text) {
    navigator.clipboard.writeText(text);
    showToast(`Copied: ${text}`);
  };

  window.copyCurlCmd = function() {
    const cmd = document.getElementById('code-curl-cmd')?.textContent || '';
    navigator.clipboard.writeText(cmd);
    showToast('cURL command copied.');
  };

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
});
