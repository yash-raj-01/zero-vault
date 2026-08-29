import { vaultState } from '../state.js';
import { security } from '../../index.js';

export function registerAuditRoutes(router) {
  router.post('/api/audit/password', (req, res) => {
    try {
      const { password } = req.body;
      if (!password) return res.json({ error: 'Missing password' }, 400);

      const auditResult = security.auditPassword(password);
      res.json(auditResult);
    } catch (err) {
      res.json({ error: 'Failed to audit password' }, 500);
    }
  });

  router.get('/api/audit/vault', (req, res) => {
    try {
      const manager = vaultState.getManager();
      if (!manager || !manager.isUnlocked()) return res.json({ error: 'Vault is locked' }, 401);
      
      // Need full entries for audit (including passwords to check strength/reuse)
      // listEntries() only gives summaries. We must fetch full for the audit.
      const summaries = manager.listEntries();
      const fullEntries = summaries.map(s => manager.getEntry(s.id));
      
      const auditResult = security.auditVaultSecrets(fullEntries);
      res.json(auditResult);
    } catch (err) {
      res.json({ error: 'Failed to audit vault secrets' }, 500);
    }
  });
}
