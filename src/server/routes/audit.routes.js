import * as security from '../../security/index.js';
import { vaultState } from '../state.js';

export function registerAuditRoutes(router) {
  router.post('/api/audit/password', (req, res) => {
    try {
      const { password } = req.body;
      if (!password) return res.json({ error: 'Missing password' }, 400);
      const audit = security.auditPassword(password);
      res.json(audit);
    } catch (err) {
      res.json({ error: err.message }, 400);
    }
  });

  router.post('/api/audit/vault', (req, res) => {
    try {
      if (vaultState.locked) return res.json({ error: 'Vault is locked' }, 401);
      const items = vaultState.getSecrets().items || [];
      const report = security.auditVaultSecrets(items);
      res.json(report);
    } catch (err) {
      res.json({ error: err.message }, 400);
    }
  });
}
