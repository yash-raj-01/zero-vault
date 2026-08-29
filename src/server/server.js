import { createServer } from 'node:http';
import { join } from 'node:path';
import { Router } from './router.js';
import { serveStatic } from './static.js';

// Import Routes
import { registerVaultRoutes } from './routes/vault.routes.js';
import { registerGeneratorRoutes } from './routes/generator.routes.js';
import { registerTotpRoutes } from './routes/totp.routes.js';
import { registerScannerRoutes } from './routes/scanner.routes.js';
import { registerAuditRoutes } from './routes/audit.routes.js';
import { registerFileRoutes } from './routes/file.routes.js';

const publicDir = join(process.cwd(), 'public');

export function startServer(port = 3000) {
  const router = new Router();

  // Register API routes
  registerVaultRoutes(router);
  registerGeneratorRoutes(router);
  registerTotpRoutes(router);
  registerScannerRoutes(router);
  registerAuditRoutes(router);
  registerFileRoutes(router);

  const server = createServer(async (req, res) => {
    // 1. Try API Routes
    if (req.url.startsWith('/api/')) {
      const handled = await router.handle(req, res);
      if (!handled) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'API route not found' }));
      }
      return;
    }

    // 2. Fallback to Static File Serving
    const isStatic = serveStatic(req, res, publicDir);
    if (!isStatic) {
      // 3. Fallback to index.html for SPA routing
      if (req.method === 'GET' && !req.url.includes('.')) {
        serveStatic({ ...req, url: '/' }, res, publicDir);
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    }
  });

  server.listen(port, () => {
    console.log(`ZeroVault Server running at http://localhost:${port}`);
    console.log(`Serving static files from ${publicDir}`);
  });

  return server;
}
