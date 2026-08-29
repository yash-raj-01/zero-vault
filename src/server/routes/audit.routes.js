import { vaultState } from '../state.js';
import { security } from '../../index.js';

export function registerAuditRoutes(router) {
  router.post('/api/audit/password', (req, res) => {
    try {
      const { password } = req.body;
      if (!password || typeof password !== 'string') return res.json({ error: 'Missing or invalid password field' }, 400);

      const auditResult = security.auditPassword(password);
      // Do not echo the password back in the response
      res.json({
        score: auditResult.score,
        tier: auditResult.tier,
        entropyBits: auditResult.entropyBits,
        length: auditResult.length,
        breakdown: auditResult.breakdown,
        remediations: auditResult.remediations
      });
    } catch (err) {
      res.json({ error: 'Failed to audit password' }, 500);
    }
  });

  router.get('/api/audit/vault', (req, res) => {
    try {
      const manager = vaultState.getManager();
      if (!manager || !manager.isUnlocked()) return res.json({ error: 'Vault is locked' }, 401);

      // Get full entries for auditing (we need passwords to check strength/reuse)
      const summaries = manager.listEntries();
      // Map to the schema auditVaultSecrets expects: { id, title, value }
      // Note: 'value' is the field auditVaultSecrets uses for password scoring.
      //       Our VaultManager uses the 'password' field in credentials.
      const entriesForAudit = summaries.map(s => {
        const full = manager.getEntry(s.id);
        return {
          id: full.id,
          title: full.service,
          value: full.password,   // Map password → value for audit engine compatibility
          notes: full.notes
        };
      });

      const auditResult = security.auditVaultSecrets(entriesForAudit);
      // Strip any fields that may have been populated with raw credential data
      res.json({
        healthScore: auditResult.healthScore,
        vaultStatus: auditResult.vaultStatus,
        itemsAudited: auditResult.itemsAudited,
        issueCount: auditResult.issueCount,
        duplicatePasswordCount: auditResult.duplicatePasswordCount,
        issues: auditResult.issues.map(issue => ({
          itemId: issue.itemId,
          severity: issue.severity,
          issue: issue.issue,
          remediations: issue.remediations
        }))
      });
    } catch (err) {
      res.json({ error: 'Failed to audit vault secrets' }, 500);
    }
  });
}
