import * as security from '../../security/index.js';

export function registerScannerRoutes(router) {
  router.post('/api/scanner/scan', (req, res) => {
    try {
      const { text, options } = req.body;
      if (typeof text !== 'string') return res.json({ error: 'Missing or invalid text' }, 400);
      const findings = security.scanSecrets(text, options);
      res.json({ findings });
    } catch (err) {
      res.json({ error: err.message }, 400);
    }
  });

  router.post('/api/scanner/redact', (req, res) => {
    try {
      const { text } = req.body;
      if (typeof text !== 'string') return res.json({ error: 'Missing or invalid text' }, 400);
      const redacted = security.redactText(text);
      res.json({ redacted });
    } catch (err) {
      res.json({ error: err.message }, 400);
    }
  });
}
