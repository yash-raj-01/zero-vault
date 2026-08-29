import { readFileSync, writeFileSync } from 'node:fs';
import { createVault, unlockVault } from '../../vault/vault.js';
import { vaultState } from '../state.js';

export function registerVaultRoutes(router) {
  router.get('/api/vault/status', (req, res) => {
    res.json({
      locked: vaultState.locked,
      vaultPath: vaultState.vaultPath
    });
  });

  router.post('/api/vault/create', (req, res) => {
    const { password, vaultPath } = req.body;
    if (!password || !vaultPath) return res.json({ error: 'Missing password or vaultPath' }, 400);

    try {
      const emptySecrets = { items: [] };
      const vaultData = createVault(Buffer.from(password), emptySecrets);
      writeFileSync(vaultPath, vaultData);
      
      vaultState.unlock(vaultPath, emptySecrets);
      res.json({ success: true, vaultPath });
    } catch (err) {
      res.json({ error: err.message }, 500);
    }
  });

  router.post('/api/vault/unlock', (req, res) => {
    const { password, vaultPath } = req.body;
    if (!password || !vaultPath) return res.json({ error: 'Missing password or vaultPath' }, 400);

    try {
      const vaultData = readFileSync(vaultPath);
      const secrets = unlockVault(Buffer.from(password), vaultData);
      vaultState.unlock(vaultPath, secrets);
      res.json({ success: true, vaultPath, itemCount: secrets.items?.length || 0 });
    } catch (err) {
      res.json({ error: err.message }, 401);
    }
  });

  router.post('/api/vault/lock', (req, res) => {
    vaultState.lock();
    res.json({ success: true, locked: true });
  });

  router.get('/api/vault/items', (req, res) => {
    if (vaultState.locked) return res.json({ error: 'Vault is locked' }, 401);
    res.json({ items: vaultState.getSecrets().items || [] });
  });

  router.post('/api/vault/save', (req, res) => {
    if (vaultState.locked) return res.json({ error: 'Vault is locked' }, 401);
    const { password, items } = req.body;
    if (!password) return res.json({ error: 'Password required to save vault' }, 400);
    
    try {
      const secrets = { items };
      const vaultData = createVault(Buffer.from(password), secrets);
      writeFileSync(vaultState.vaultPath, vaultData);
      vaultState.secrets = secrets;
      res.json({ success: true });
    } catch (err) {
      res.json({ error: err.message }, 500);
    }
  });
}
