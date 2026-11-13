import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function handleScanUrl(rawUrl: unknown, res: Response) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return res.status(400).json({
      success: false,
      error: '有効なURLを入力してください (例: https://example.com)',
    });
  }

  let parsedUrl: URL;
  try {
    let target = rawUrl.trim();
    if (!/^https?:\/\//i.test(target)) {
      target = `https://${target}`;
    }
    parsedUrl = new URL(target);
  } catch {
    return res.status(400).json({
      success: false,
      error: 'URLの形式が正しくありません。(例: https://example.com)',
    });
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return res.status(400).json({
      success: false,
      error: 'http:// または https:// で始まるURLを指定してください。',
    });
  }

  // SSRF Protection: Prevent accessing internal IP, loopback, or cloud metadata
  const hostname = parsedUrl.hostname.toLowerCase();
  if (
    hostname === 'localhost' ||
    hostname === '0.0.0.0' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname === '[::1]' ||
    hostname === '169.254.169.254' ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.startsWith('10.') ||
    hostname.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostname)
  ) {
    return res.status(403).json({
      success: false,
      error: 'ローカルアドレス・プライベートIPおよびメタデータアドレスへのスキャンは安全のため禁止されています。',
    });
  }

  const startTime = Date.now();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(parsedUrl.toString(), {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: controller.signal,
      redirect: 'follow',
    });

    clearTimeout(timeoutId);
    const latencyMs = Date.now() - startTime;

    // Extract all headers into normalized key-value object
    const headersObj: Record<string, string> = {};
    response.headers.forEach((val, key) => {
      headersObj[key] = val;
    });

    // Special handling for set-cookie if multiple
    const getSetCookieFn = (response.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
    const setCookie =
      typeof getSetCookieFn === 'function'
        ? getSetCookieFn.call(response.headers).join('; ')
        : response.headers.get('set-cookie') || '';

    const resolvedUrl = response.url || parsedUrl.toString();
    const isHttps = resolvedUrl.startsWith('https://');

    return res.json({
      success: true,
      targetUrl: parsedUrl.toString(),
      resolvedUrl,
      statusCode: response.status,
      statusText: response.statusText,
      isHttps,
      latencyMs,
      headers: headersObj,
      setCookie,
    });
  } catch (err: any) {
    const latencyMs = Date.now() - startTime;
    const isAbort = err?.name === 'AbortError';

    return res.status(502).json({
      success: false,
      error: isAbort
        ? 'リクエストがタイムアウトしました (8秒超過)。ホストが応答しないかアクセス制限されています。'
        : `対象ホストへの接続に失敗しました: ${err?.message || 'DNS解決エラーまたは接続拒否'}`,
      latencyMs,
    });
  }
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json());

  // API endpoint: Live URL Vulnerability & Security Header Scanner
  app.post('/api/scan-url', async (req, res) => {
    return handleScanUrl(req.body?.url, res);
  });

  app.get('/api/scan-url', async (req, res) => {
    return handleScanUrl(req.query?.url, res);
  });

  // Health check route
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Always return JSON for unknown /api/* routes
  app.all('/api/*', (req, res) => {
    res.status(404).json({
      success: false,
      error: `APIエンドポイントが見つかりません: ${req.method} ${req.originalUrl}`,
    });
  });

  // Always return JSON for API middleware errors (e.g. malformed JSON body)
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api/')) {
      return res.status(err?.status || 400).json({
        success: false,
        error: 'リクエストの形式が不正です。',
      });
    }
    return next(err);
  });

  // Vite middleware in dev or static serving in production
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CyberShield] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[CyberShield] Failed to start server:', err);
  process.exit(1);
});
