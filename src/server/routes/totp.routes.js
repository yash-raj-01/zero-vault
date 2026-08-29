import * as security from '../../security/index.js';

export function registerTotpRoutes(router) {
  router.post('/api/totp/generate', (req, res) => {
    try {
      const { secret, options } = req.body;
      if (!secret) return res.json({ error: 'Missing secret' }, 400);
      const token = security.generateTOTP(secret, options);
      res.json({ token });
    } catch (err) {
      res.json({ error: err.message }, 400);
    }
  });

  router.post('/api/totp/verify', (req, res) => {
    try {
      const { token, secret, options } = req.body;
      if (!token || !secret) return res.json({ error: 'Missing token or secret' }, 400);
      const result = security.verifyTOTP(token, secret, options);
      res.json(result);
    } catch (err) {
      res.json({ error: err.message }, 400);
    }
  });

  router.post('/api/totp/parse-uri', (req, res) => {
    try {
      const { uri } = req.body;
      if (!uri) return res.json({ error: 'Missing URI' }, 400);
      const parsed = security.parseOtpauthUri(uri);
      res.json(parsed);
    } catch (err) {
      res.json({ error: err.message }, 400);
    }
  });

  router.post('/api/totp/generate-uri', (req, res) => {
    try {
      const options = req.body;
      const uri = security.generateOtpauthUri(options);
      res.json({ uri });
    } catch (err) {
      res.json({ error: err.message }, 400);
    }
  });
}
