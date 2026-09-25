import path from 'path';
import express from 'express';

async function startServer() {
  try {
    await import('tsx/esm');
  } catch {}

  const { createApiApp } = await import('./server/app');
  const app = createApiApp();
  const PORT = 3000;

  // Vite middleware for development vs static production serving
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AI Vulnerability Triage & Attack-Path Prioritizer server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
