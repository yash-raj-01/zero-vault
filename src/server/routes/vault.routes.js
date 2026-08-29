import { vaultState } from '../state.js';

export function registerVaultRoutes(router) {
  // GET /api/vault/status
  router.get('/api/vault/status', (req, res) => {
    const manager = vaultState.getManager();
    if (!manager || !manager.isUnlocked()) {
      return res.json({ locked: true, vaultPath: null });
    }
    res.json({ locked: false, vaultPath: manager.filePath });
  });

  // POST /api/vault/create
  router.post('/api/vault/create', async (req, res) => {
    const { password, vaultPath } = req.body;
    if (!password || !vaultPath) return res.json({ error: 'Missing password or vaultPath' }, 400);

    try {
      vaultState.initManager(vaultPath);
      const manager = vaultState.getManager();
      
      const pwdBuf = Buffer.from(password);
      await manager.initializeVault(pwdBuf);
      manager.unlock(pwdBuf);
      pwdBuf.fill(0); // Defense in depth

      res.json({ success: true, vaultPath });
    } catch (err) {
      res.json({ error: 'Failed to create vault safely' }, 500);
    }
  });

  // POST /api/vault/unlock
  router.post('/api/vault/unlock', (req, res) => {
    const { password, vaultPath } = req.body;
    if (!password || !vaultPath) return res.json({ error: 'Missing password or vaultPath' }, 400);

    try {
      vaultState.initManager(vaultPath);
      const manager = vaultState.getManager();
      
      const pwdBuf = Buffer.from(password);
      manager.unlock(pwdBuf);
      pwdBuf.fill(0); // Defense in depth
      
      const itemCount = manager.listEntries().length;
      res.json({ success: true, vaultPath, itemCount });
    } catch (err) {
      // Safe generic error
      res.json({ error: 'Authentication failed or vault is corrupted' }, 401);
    }
  });

  // POST /api/vault/lock
  router.post('/api/vault/lock', (req, res) => {
    vaultState.clearManager();
    res.json({ success: true, locked: true });
  });

  // ==========================================
  // Credential CRUD Endpoints
  // ==========================================

  // GET /api/entries
  router.get('/api/entries', (req, res) => {
    const manager = vaultState.getManager();
    if (!manager || !manager.isUnlocked()) return res.json({ error: 'Vault is locked' }, 401);
    
    try {
      const entries = manager.listEntries();
      res.json({ entries });
    } catch (err) {
      res.json({ error: 'Failed to fetch entries' }, 500);
    }
  });

  // POST /api/entries
  router.post('/api/entries', (req, res) => {
    const manager = vaultState.getManager();
    if (!manager || !manager.isUnlocked()) return res.json({ error: 'Vault is locked' }, 401);
    
    try {
      const id = manager.createEntry(req.body);
      res.json({ success: true, id });
    } catch (err) {
      res.json({ error: 'Failed to create entry safely' }, 400);
    }
  });

  // GET /api/entries/:id
  // Note: the router.js handles dynamic segments like :id ? Wait, does it?
  // Let me check if Router supports params. Yes, the tests in `router.test.js` say "should extract URL parameters".
  router.get('/api/entries/:id', (req, res) => {
    const manager = vaultState.getManager();
    if (!manager || !manager.isUnlocked()) return res.json({ error: 'Vault is locked' }, 401);
    
    try {
      const entry = manager.getEntry(req.params.id);
      res.json({ entry });
    } catch (err) {
      res.json({ error: 'Entry not found' }, 404);
    }
  });

  // PUT /api/entries/:id
  router.put('/api/entries/:id', (req, res) => {
    const manager = vaultState.getManager();
    if (!manager || !manager.isUnlocked()) return res.json({ error: 'Vault is locked' }, 401);
    
    try {
      manager.updateEntry(req.params.id, req.body);
      res.json({ success: true });
    } catch (err) {
      res.json({ error: 'Failed to update entry safely' }, 400);
    }
  });

  // DELETE /api/entries/:id
  router.delete('/api/entries/:id', (req, res) => {
    const manager = vaultState.getManager();
    if (!manager || !manager.isUnlocked()) return res.json({ error: 'Vault is locked' }, 401);
    
    try {
      manager.deleteEntry(req.params.id);
      res.json({ success: true });
    } catch (err) {
      res.json({ error: 'Failed to delete entry safely' }, 400);
    }
  });
}
