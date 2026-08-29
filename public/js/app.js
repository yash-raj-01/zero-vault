// Simple UI Toast System
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerText = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 3000);
}

// Navigation Router
document.querySelectorAll('.nav-links a').forEach(link => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const viewId = e.target.getAttribute('data-view');
    
    // Update active nav link
    document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
    e.target.classList.add('active');
    
    // Update active view
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(`view-${viewId}`).classList.add('active');
  });
});

// Generator Tabs
let currentGenType = 'password';
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', (e) => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    e.target.classList.add('active');
    currentGenType = e.target.getAttribute('data-gen');
    document.getElementById('gen-result').innerText = 'Click generate...';
    document.getElementById('gen-entropy').innerText = '-- bits';
  });
});

// Bind UI actions to API calls
document.addEventListener('DOMContentLoaded', () => {
  
  // Update vault status periodically
  async function updateStatus() {
    try {
      const status = await window.api.get('/vault/status');
      const ind = document.getElementById('vault-status');
      if (status.locked) {
        ind.innerHTML = '<span class="dot red"></span> Locked';
        document.getElementById('lock-btn').style.display = 'none';
        
        // Force navigate to unlock if trying to access secure areas
        const activeView = document.querySelector('.view.active').id;
        if (['view-dashboard', 'view-vault'].includes(activeView)) {
           document.querySelector('[data-view="unlock"]').click();
        }
      } else {
        ind.innerHTML = '<span class="dot green"></span> Unlocked';
        document.getElementById('lock-btn').style.display = 'block';
      }
    } catch(e) {}
  }
  
  setInterval(updateStatus, 5000);
  updateStatus();

  // Unlock Vault
  document.getElementById('form-unlock').addEventListener('submit', async (e) => {
    e.preventDefault();
    const path = document.getElementById('unlock-path').value;
    const pwd = document.getElementById('unlock-password').value;
    try {
      const res = await window.api.post('/vault/unlock', { vaultPath: path, password: pwd });
      showToast('Vault unlocked successfully');
      document.getElementById('unlock-password').value = '';
      updateStatus();
      document.querySelector('[data-view="dashboard"]').click();
      document.getElementById('dash-total-items').innerText = res.itemCount;
    } catch(err) {
      showToast(err.message, 'error');
    }
  });
  
  // Create Vault
  document.getElementById('btn-create-vault').addEventListener('click', async () => {
    const path = document.getElementById('unlock-path').value;
    const pwd = document.getElementById('unlock-password').value;
    if(!path || !pwd) return showToast('Path and password required', 'error');
    try {
      await window.api.post('/vault/create', { vaultPath: path, password: pwd });
      showToast('New vault created and unlocked');
      document.getElementById('unlock-password').value = '';
      updateStatus();
      document.querySelector('[data-view="dashboard"]').click();
    } catch(err) {
      showToast(err.message, 'error');
    }
  });

  // Lock Vault
  document.getElementById('lock-btn').addEventListener('click', async () => {
    try {
      await window.api.post('/vault/lock', {});
      showToast('Vault locked');
      updateStatus();
      document.querySelector('[data-view="unlock"]').click();
    } catch(err) {
      showToast(err.message, 'error');
    }
  });

  // Generator
  document.getElementById('btn-generate').addEventListener('click', async () => {
    try {
      if (currentGenType === 'password') {
        const res = await window.api.post('/generator/password', {});
        document.getElementById('gen-result').innerText = res.password;
        document.getElementById('gen-entropy').innerText = `${res.entropyBits} bits`;
      } else if (currentGenType === 'passphrase') {
        const res = await window.api.post('/generator/passphrase', {});
        document.getElementById('gen-result').innerText = res.passphrase;
        document.getElementById('gen-entropy').innerText = `${res.entropyBits} bits`;
      } else {
        const res = await window.api.post('/generator/keys', {});
        document.getElementById('gen-result').innerText = res.hex;
        document.getElementById('gen-entropy').innerText = `256 bits`;
      }
    } catch(err) {
      showToast(err.message, 'error');
    }
  });

  // Scanner
  document.getElementById('form-scanner').addEventListener('submit', async (e) => {
    e.preventDefault();
    const txt = document.getElementById('scanner-input').value;
    try {
      const res = await window.api.post('/scanner/scan', { text: txt });
      const container = document.getElementById('scanner-results');
      if (res.findings.length === 0) {
        container.innerHTML = '<div class="result-box">No secrets found!</div>';
      } else {
        let html = '<div class="result-box text-red"><strong>Secrets found:</strong><ul>';
        res.findings.forEach(f => {
          html += `<li>${f.ruleName} at line ${f.line} - Redacted: ${f.redactedValue}</li>`;
        });
        html += '</ul></div>';
        container.innerHTML = html;
      }
    } catch(err) {
      showToast(err.message, 'error');
    }
  });

  // TOTP
  document.getElementById('form-totp-verify').addEventListener('submit', async (e) => {
    e.preventDefault();
    const sec = document.getElementById('totp-secret').value;
    try {
      const res = await window.api.post('/totp/generate', { secret: sec });
      document.getElementById('totp-result').classList.remove('hidden');
      document.getElementById('totp-code-display').innerHTML = `<h2>${res.token}</h2>`;
    } catch(err) {
      showToast(err.message, 'error');
    }
  });

  // File Protection
  document.getElementById('btn-file-inspect').addEventListener('click', async () => {
    const path = document.getElementById('file-path-input').value;
    try {
      const res = await window.api.post('/file/permissions', { filePath: path });
      const box = document.getElementById('file-ops-result');
      box.classList.remove('hidden');
      box.innerHTML = `Mode: ${res.modeOctal} | Secure: ${res.secure ? 'Yes' : 'No'}`;
    } catch(err) { showToast(err.message, 'error'); }
  });
  
  document.getElementById('btn-file-secure').addEventListener('click', async () => {
    const path = document.getElementById('file-path-input').value;
    try {
      const res = await window.api.post('/file/secure', { filePath: path });
      showToast(`Secured to mode ${res.mode}`);
    } catch(err) { showToast(err.message, 'error'); }
  });

  // Audit
  document.getElementById('form-audit-pwd').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pwd = document.getElementById('audit-pwd-input').value;
    try {
      const res = await window.api.post('/audit/password', { password: pwd });
      document.getElementById('audit-result').innerHTML = `
        <div class="result-box">
          <h3>Score: ${res.score}/100 (${res.tier})</h3>
          <p>${res.breakdown.details.join('<br>')}</p>
        </div>
      `;
    } catch(err) { showToast(err.message, 'error'); }
  });

});
