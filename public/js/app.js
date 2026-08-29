/**
 * ZeroVault Frontend Application
 *
 * Security notes:
 * - Master password is NEVER stored in localStorage, sessionStorage, or DOM attributes
 * - Passwords are cleared from input fields immediately after use
 * - No secrets are logged to console
 * - All secrets received from server are already redacted
 * - Raw credential passwords are only shown when user explicitly clicks "Reveal"
 */

'use strict';

// =============================================
// NAVIGATION
// =============================================

function navigate(viewId) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
  const view = document.getElementById(`view-${viewId}`);
  const nav = document.getElementById(`nav-${viewId}`);
  if (view) view.classList.add('active');
  if (nav) nav.classList.add('active');
}

document.querySelectorAll('.nav-links a').forEach(link => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const viewId = e.currentTarget.getAttribute('data-view');
    navigate(viewId);
    // If navigating to vault, refresh the list
    if (viewId === 'vault') loadCredentials();
  });
});

// =============================================
// TOAST NOTIFICATIONS
// =============================================

function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  // Sanitize message to prevent XSS from API error messages
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}

// =============================================
// CONFIRM MODAL
// =============================================

function showConfirm(title, message) {
  return new Promise((resolve) => {
    document.getElementById('confirm-title').textContent = title;
    document.getElementById('confirm-message').textContent = message;
    const modal = document.getElementById('confirm-modal');
    modal.style.display = 'flex';
    document.getElementById('confirm-ok').onclick = () => { modal.style.display = 'none'; resolve(true); };
    document.getElementById('confirm-cancel').onclick = () => { modal.style.display = 'none'; resolve(false); };
  });
}

// =============================================
// VAULT STATUS & LOCKING
// =============================================

async function updateStatus() {
  try {
    const status = await window.api.get('/vault/status');
    const indicator = document.getElementById('vault-status');
    const lockBtn = document.getElementById('lock-btn');

    if (status.locked) {
      indicator.innerHTML = '<span class="dot red"></span> Locked';
      lockBtn.style.display = 'none';
      // Force user to unlock screen if on protected views
      const activeView = document.querySelector('.view.active')?.id;
      if (['view-dashboard', 'view-vault', 'view-audit'].includes(activeView)) {
        navigate('unlock');
      }
    } else {
      indicator.innerHTML = '<span class="dot green"></span> Unlocked';
      lockBtn.style.display = 'block';
    }
  } catch (e) {
    // Silently ignore status check failures (server may be restarting)
  }
}

setInterval(updateStatus, 5000);

// Lock button
document.getElementById('lock-btn').addEventListener('click', async () => {
  try {
    await window.api.post('/vault/lock', {});
    showToast('Vault locked successfully', 'success');
    updateStatus();
    navigate('unlock');
    // Clear vault list in memory
    document.getElementById('vault-items-list').innerHTML = '';
  } catch (err) {
    showToast(err.message, 'error');
  }
});

// =============================================
// UNLOCK & CREATE VAULT
// =============================================

document.getElementById('form-unlock').addEventListener('submit', async (e) => {
  e.preventDefault();
  const path = document.getElementById('unlock-path').value.trim();
  const pwdInput = document.getElementById('unlock-password');
  const pwd = pwdInput.value;

  if (!path || !pwd) return showToast('Path and password are required', 'error');

  const btn = document.getElementById('btn-unlock');
  btn.disabled = true;
  btn.textContent = 'Unlocking...';

  try {
    const res = await window.api.post('/vault/unlock', { vaultPath: path, password: pwd });
    pwdInput.value = ''; // Immediately clear from DOM
    showToast('Vault unlocked successfully');
    await updateStatus();
    document.getElementById('dash-total-items').textContent = res.itemCount;
    navigate('dashboard');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock Vault';
    pwdInput.value = ''; // Ensure cleared even on error
  }
});

document.getElementById('btn-create-vault').addEventListener('click', async () => {
  const path = document.getElementById('unlock-path').value.trim();
  const pwdInput = document.getElementById('unlock-password');
  const pwd = pwdInput.value;

  if (!path || !pwd) return showToast('Path and password are required', 'error');

  const confirmed = await showConfirm('Create New Vault', `Create a new vault at "${path}"? Existing data at this path will be overwritten.`);
  if (!confirmed) return;

  try {
    await window.api.post('/vault/create', { vaultPath: path, password: pwd });
    pwdInput.value = ''; // Clear immediately
    showToast('New vault created and unlocked');
    await updateStatus();
    navigate('dashboard');
  } catch (err) {
    showToast(err.message, 'error');
    pwdInput.value = '';
  }
});

// =============================================
// CREDENTIAL CRUD
// =============================================

async function loadCredentials() {
  const list = document.getElementById('vault-items-list');
  const emptyState = document.getElementById('vault-empty-state');
  const loadingState = document.getElementById('vault-loading-state');

  loadingState.style.display = 'block';
  emptyState.style.display = 'none';
  list.innerHTML = '';

  try {
    const data = await window.api.get('/entries');
    loadingState.style.display = 'none';

    if (!data.entries || data.entries.length === 0) {
      emptyState.style.display = 'block';
      document.getElementById('dash-total-items').textContent = '0';
      return;
    }

    document.getElementById('dash-total-items').textContent = data.entries.length;

    data.entries.forEach(entry => {
      const item = document.createElement('div');
      item.className = 'credential-item';
      item.dataset.id = entry.id;
      // Note: listEntries() only returns summary (no password)
      item.innerHTML = `
        <div class="credential-info">
          <div class="credential-service">${escapeHtml(entry.service)}</div>
          <div class="credential-username text-muted">${escapeHtml(entry.username || '—')}</div>
        </div>
        <div class="credential-actions">
          <button class="btn-icon btn-reveal" data-id="${entry.id}" title="View credential">👁️</button>
          <button class="btn-icon btn-edit" data-id="${entry.id}" title="Edit credential">✏️</button>
          <button class="btn-icon btn-delete text-danger" data-id="${entry.id}" title="Delete credential">🗑️</button>
        </div>
      `;
      list.appendChild(item);
    });

    // Bind action buttons
    list.querySelectorAll('.btn-reveal').forEach(btn => btn.addEventListener('click', handleReveal));
    list.querySelectorAll('.btn-edit').forEach(btn => btn.addEventListener('click', handleEdit));
    list.querySelectorAll('.btn-delete').forEach(btn => btn.addEventListener('click', handleDelete));

  } catch (err) {
    loadingState.style.display = 'none';
    if (err.message.includes('locked')) {
      navigate('unlock');
    } else {
      showToast('Failed to load credentials: ' + err.message, 'error');
    }
  }
}

async function handleReveal(e) {
  const id = e.currentTarget.dataset.id;
  try {
    const data = await window.api.get(`/entries/${id}`);
    const entry = data.entry;
    const revealed = await showConfirm(
      `🔐 ${escapeHtml(entry.service)}`,
      `Username: ${entry.username || '—'}\nPassword: ${entry.password || '—'}\nNotes: ${entry.notes || '—'}`
    );
    // We only show it in the confirm modal — no logging or DOM persistence
  } catch (err) {
    showToast('Could not retrieve credential: ' + err.message, 'error');
  }
}

async function handleEdit(e) {
  const id = e.currentTarget.dataset.id;
  try {
    const data = await window.api.get(`/entries/${id}`);
    const entry = data.entry;
    showCredentialForm(entry);
  } catch (err) {
    showToast('Could not load credential for editing: ' + err.message, 'error');
  }
}

async function handleDelete(e) {
  const id = e.currentTarget.dataset.id;
  const item = document.querySelector(`.credential-item[data-id="${id}"]`);
  const service = item?.querySelector('.credential-service')?.textContent || 'this credential';

  const confirmed = await showConfirm('Delete Credential', `Permanently delete "${service}"? This cannot be undone.`);
  if (!confirmed) return;

  try {
    await window.api.delete(`/entries/${id}`);
    showToast('Credential deleted');
    loadCredentials();
  } catch (err) {
    showToast('Delete failed: ' + err.message, 'error');
  }
}

function showCredentialForm(entry = null) {
  const container = document.getElementById('credential-form-container');
  const title = document.getElementById('credential-form-title');
  container.style.display = 'block';
  container.scrollIntoView({ behavior: 'smooth' });

  if (entry) {
    title.textContent = 'Edit Credential';
    document.getElementById('credential-id').value = entry.id;
    document.getElementById('cred-service').value = entry.service || '';
    document.getElementById('cred-username').value = entry.username || '';
    document.getElementById('cred-password').value = entry.password || '';
    document.getElementById('cred-notes').value = entry.notes || '';
  } else {
    title.textContent = 'Add Credential';
    document.getElementById('credential-id').value = '';
    document.getElementById('form-credential').reset();
  }
}

function hideCredentialForm() {
  const container = document.getElementById('credential-form-container');
  container.style.display = 'none';
  document.getElementById('form-credential').reset();
  document.getElementById('credential-id').value = '';
  // Also clear the password field explicitly
  document.getElementById('cred-password').value = '';
}

document.getElementById('btn-add-item').addEventListener('click', () => showCredentialForm());
document.getElementById('btn-cancel-credential').addEventListener('click', hideCredentialForm);

document.getElementById('form-credential').addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = document.getElementById('credential-id').value;
  const payload = {
    service: document.getElementById('cred-service').value.trim(),
    username: document.getElementById('cred-username').value.trim(),
    password: document.getElementById('cred-password').value,
    notes: document.getElementById('cred-notes').value.trim()
  };

  if (!payload.service) return showToast('Service name is required', 'error');

  const saveBtn = document.getElementById('btn-save-credential');
  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving...';

  try {
    if (id) {
      await window.api.put(`/entries/${id}`, payload);
      showToast('Credential updated');
    } else {
      await window.api.post('/entries', payload);
      showToast('Credential added');
    }
    hideCredentialForm();
    loadCredentials();
  } catch (err) {
    showToast('Save failed: ' + err.message, 'error');
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save';
    // Ensure password is cleared from form after save/fail
    document.getElementById('cred-password').value = '';
  }
});

// Quick generate password into credential form
document.getElementById('btn-gen-for-cred').addEventListener('click', async () => {
  try {
    const res = await window.api.post('/generator/password', { length: 20 });
    document.getElementById('cred-password').value = res.password;
    showToast(`Generated ${res.entropyBits} bits entropy password`);
  } catch (err) {
    showToast('Generation failed: ' + err.message, 'error');
  }
});

// =============================================
// TOTP / AUTHENTICATOR
// =============================================

let totpTimerInterval = null;

document.getElementById('form-totp-verify').addEventListener('submit', async (e) => {
  e.preventDefault();
  const secretInput = document.getElementById('totp-secret');
  const secret = secretInput.value.trim();

  if (!secret) return showToast('TOTP secret is required', 'error');

  try {
    const res = await window.api.post('/totp/generate', { secret });
    const resultBox = document.getElementById('totp-result');
    const codeDisplay = document.getElementById('totp-code-display');

    resultBox.classList.remove('hidden');
    codeDisplay.textContent = res.token;

    // Timer countdown logic
    if (totpTimerInterval) clearInterval(totpTimerInterval);

    function updateTimer() {
      const seconds = Math.floor(Date.now() / 1000);
      const remaining = 30 - (seconds % 30);
      const pct = (remaining / 30) * 100;

      document.getElementById('totp-timer').textContent = `⏱ ${remaining} seconds remaining`;
      document.getElementById('totp-progress-bar').style.width = `${pct}%`;
      document.getElementById('totp-progress-bar').style.backgroundColor =
        remaining < 10 ? '#ef4444' : '#10b981';
    }

    updateTimer();
    totpTimerInterval = setInterval(updateTimer, 1000);

    // NOTE: We do NOT persist the secret anywhere after submit
  } catch (err) {
    showToast(err.message, 'error');
  }
});

document.getElementById('btn-copy-totp').addEventListener('click', () => {
  const code = document.getElementById('totp-code-display').textContent;
  navigator.clipboard.writeText(code).then(() => showToast('Code copied!'));
});

// =============================================
// GENERATOR
// =============================================

let currentGenType = 'password';
let lastGenResult = '';

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', (e) => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    e.target.classList.add('active');
    currentGenType = e.target.getAttribute('data-gen');
    document.getElementById('gen-result').textContent = 'Click generate...';
    document.getElementById('gen-entropy').textContent = '-- bits';
    document.getElementById('btn-copy-gen').style.display = 'none';
    lastGenResult = '';
  });
});

document.getElementById('btn-generate').addEventListener('click', async () => {
  const btn = document.getElementById('btn-generate');
  btn.disabled = true;
  btn.textContent = 'Generating...';

  try {
    let result = '';
    let entropy = '';

    if (currentGenType === 'password') {
      const res = await window.api.post('/generator/password', { length: 20 });
      result = res.password;
      entropy = `${res.entropyBits} bits`;
    } else if (currentGenType === 'passphrase') {
      const res = await window.api.post('/generator/passphrase', {});
      result = res.passphrase;
      entropy = `${res.entropyBits} bits`;
    } else {
      const res = await window.api.post('/generator/keys', {});
      result = res.hex;
      entropy = '256 bits';
    }

    lastGenResult = result;
    document.getElementById('gen-result').textContent = result;
    document.getElementById('gen-entropy').textContent = entropy;
    document.getElementById('btn-copy-gen').style.display = 'inline-block';

  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '⚡ Generate';
  }
});

document.getElementById('btn-copy-gen').addEventListener('click', () => {
  if (lastGenResult) {
    navigator.clipboard.writeText(lastGenResult).then(() => showToast('Copied to clipboard!'));
  }
});

// =============================================
// SECRET SCANNER
// =============================================

document.getElementById('form-scanner').addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = document.getElementById('scanner-input').value;
  const container = document.getElementById('scanner-results');

  if (!text.trim()) return showToast('Enter some text to scan', 'error');

  container.innerHTML = '<p class="text-muted">Scanning...</p>';

  try {
    const res = await window.api.post('/scanner/scan', { text });

    if (!res.findings || res.findings.length === 0) {
      container.innerHTML = '<div class="result-box success">✅ No secrets detected.</div>';
      return;
    }

    const severityIcon = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };

    let html = `<div class="finding-count">Found <strong>${res.findings.length}</strong> potential secret(s):</div>`;
    res.findings.forEach(f => {
      html += `
        <div class="finding-card severity-${f.severity.toLowerCase()}">
          <div class="finding-header">
            <span class="severity-badge">${severityIcon[f.severity] || '⚪'} ${escapeHtml(f.severity)}</span>
            <span class="finding-type">${escapeHtml(f.ruleName)}</span>
          </div>
          <div class="finding-body">
            <span class="finding-location">Line ${f.line}</span>
            <code class="finding-redacted">${escapeHtml(f.redactedValue)}</code>
          </div>
        </div>`;
    });
    container.innerHTML = html;

  } catch (err) {
    container.innerHTML = `<div class="result-box error">❌ ${escapeHtml(err.message)}</div>`;
  }
});

// =============================================
// SECURITY AUDIT
// =============================================

document.getElementById('form-audit-pwd').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pwdInput = document.getElementById('audit-pwd-input');
  const pwd = pwdInput.value;
  const container = document.getElementById('audit-result');

  if (!pwd) return showToast('Enter a password to audit', 'error');

  try {
    const res = await window.api.post('/audit/password', { password: pwd });
    pwdInput.value = ''; // Clear after submission

    const tierColor = { EXCELLENT: 'success', STRONG: 'success', MODERATE: 'warning', WEAK: 'danger', CRITICAL: 'danger' };
    const color = tierColor[res.tier] || 'warning';

    let html = `
      <div class="audit-score-card ${color}">
        <div class="audit-score">${res.score}<span>/100</span></div>
        <div class="audit-tier">${res.tier}</div>
        <div class="audit-meta text-muted">${res.entropyBits} bits entropy · ${res.length} chars</div>
      </div>`;

    if (res.breakdown?.details?.length > 0) {
      html += '<div class="audit-breakdown"><strong>Breakdown:</strong><ul>';
      res.breakdown.details.forEach(d => {
        html += `<li>${escapeHtml(d)}</li>`;
      });
      html += '</ul></div>';
    }

    if (res.remediations?.length > 0) {
      html += '<div class="audit-recs"><strong>Recommendations:</strong><ul>';
      res.remediations.forEach(r => {
        html += `<li>${escapeHtml(r)}</li>`;
      });
      html += '</ul></div>';
    }

    container.innerHTML = html;
  } catch (err) {
    pwdInput.value = '';
    showToast(err.message, 'error');
  }
});

document.getElementById('btn-audit-vault').addEventListener('click', async () => {
  const container = document.getElementById('vault-audit-result');
  const btn = document.getElementById('btn-audit-vault');

  btn.disabled = true;
  btn.textContent = 'Auditing...';
  container.innerHTML = '<p class="text-muted">Running audit...</p>';

  try {
    const res = await window.api.get('/audit/vault');

    const statusIcon = { HEALTHY: '✅', NEEDS_ATTENTION: '⚠️', AT_RISK: '❌' };
    const statusColor = { HEALTHY: 'success', NEEDS_ATTENTION: 'warning', AT_RISK: 'danger' };
    const color = statusColor[res.vaultStatus] || 'warning';

    let html = `
      <div class="audit-score-card ${color}">
        <div class="audit-score">${res.healthScore}<span>/100</span></div>
        <div class="audit-tier">${statusIcon[res.vaultStatus] || ''} ${res.vaultStatus}</div>
        <div class="audit-meta text-muted">${res.itemsAudited} items audited · ${res.issueCount} issue(s)</div>
      </div>`;

    if (res.duplicatePasswordCount > 0) {
      html += `<div class="finding-card severity-high"><p>⚠️ ${res.duplicatePasswordCount} duplicate password(s) detected</p></div>`;
    }

    if (res.issues?.length > 0) {
      html += '<div class="audit-breakdown"><strong>Issues Found:</strong>';
      res.issues.forEach(issue => {
        html += `
          <div class="finding-card mt-2">
            <div class="finding-header">
              <span class="severity-badge">${escapeHtml(issue.severity)}</span>
            </div>
            <div class="finding-body">
              <p>${escapeHtml(issue.issue)}</p>
              ${issue.remediations?.map(r => `<p class="text-muted">→ ${escapeHtml(r)}</p>`).join('') || ''}
            </div>
          </div>`;
      });
      html += '</div>';
    } else {
      html += '<p class="text-muted mt-2">No issues found. Keep up the good work!</p>';
    }

    container.innerHTML = html;
  } catch (err) {
    if (err.message.includes('locked')) {
      container.innerHTML = '<div class="result-box warning">🔒 Unlock the vault first to run an audit.</div>';
    } else {
      container.innerHTML = `<div class="result-box error">❌ ${escapeHtml(err.message)}</div>`;
    }
  } finally {
    btn.disabled = false;
    btn.textContent = '🛡️ Run Full Vault Audit';
  }
});

// =============================================
// HELPERS
// =============================================

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// =============================================
// INIT
// =============================================

document.addEventListener('DOMContentLoaded', () => {
  updateStatus();
});
