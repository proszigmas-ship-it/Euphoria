/**
 * EUPHORIA - Cloudflare Global Reverse Proxy Worker
 * 
 * Target Origin: https://euphoria-2s7d.onrender.com
 * Features:
 * - Bypasses Russian/Regional ISP blocks (РКН/ТСПУ) without VPN
 * - Works worldwide (Russia, Serbia, Europe, USA, CIS, Asia)
 * - Transparent Cookie & Session proxying (Flask session cookies)
 * - Automatic IP forwarding & SSL encryption
 * - High-speed Cloudflare CDN edge caching for static assets
 */

const ORIGIN = 'https://euphoria-2s7d.onrender.com';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const targetUrl = new URL(url.pathname + url.search, ORIGIN);

    // Clone headers and rewrite Host for Render
    const newHeaders = new Headers(request.headers);
    newHeaders.set('Host', new URL(ORIGIN).host);
    newHeaders.set('X-Forwarded-Host', url.host);
    newHeaders.set('X-Forwarded-Proto', url.protocol.replace(':', ''));
    
    const clientIP = request.headers.get('cf-connecting-ip') || request.headers.get('x-real-ip');
    if (clientIP) {
      newHeaders.set('X-Real-IP', clientIP);
      newHeaders.set('X-Forwarded-For', clientIP);
    }

    // Prepare fetch options
    const fetchOptions = {
      method: request.method,
      headers: newHeaders,
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
      redirect: 'manual',
    };

    try {
      const originResponse = await fetch(targetUrl.toString(), fetchOptions);

      // Clone response headers
      const responseHeaders = new Headers(originResponse.headers);

      // Rewrite redirects to worker domain
      const location = responseHeaders.get('Location');
      if (location) {
        try {
          const locUrl = new URL(location, ORIGIN);
          if (locUrl.host === new URL(ORIGIN).host) {
            locUrl.host = url.host;
            locUrl.protocol = url.protocol;
            responseHeaders.set('Location', locUrl.toString());
          }
        } catch (e) {}
      }

      // Rewrite Set-Cookie domains so Flask session works smoothly on worker domain
      const rawCookies = originResponse.headers.getSetCookie 
        ? originResponse.headers.getSetCookie() 
        : [originResponse.headers.get('Set-Cookie')].filter(Boolean);

      if (rawCookies.length > 0) {
        responseHeaders.delete('Set-Cookie');
        for (const cookie of rawCookies) {
          // Remove domain constraint so cookie binds to the current worker domain
          const cleanCookie = cookie
            .replace(/Domain=[^;]+;?/gi, '')
            .replace(/SameSite=None/gi, 'SameSite=Lax');
          responseHeaders.append('Set-Cookie', cleanCookie);
        }
      }

      // Security and CDN headers
      responseHeaders.set('X-Proxy-By', 'Euphoria-Global-CDN');

      return new Response(originResponse.body, {
        status: originResponse.status,
        statusText: originResponse.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      return new Response(
        `<html><body style="background:#070913;color:#fff;font-family:sans-serif;text-align:center;padding:50px">
          <h2>EUPHORIA CDN Gateway</h2>
          <p style="color:#94a3b8">Подключение к серверу... Пожалуйста, обновите страницу через 5 секунд.</p>
        </body></html>`,
        {
          status: 502,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        }
      );
    }
  },
};
