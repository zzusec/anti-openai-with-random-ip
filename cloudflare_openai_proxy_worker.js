
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const targetUrl = url.searchParams.get('url');
    
    // 1. 地区过滤：排除中国地区 (CN, HK, MO)
    const country = request.cf.country;
    const blockedRegions = ['CN', 'HK', 'MO'];
    
    if (blockedRegions.includes(country)) {
      return new Response(`Access Denied: Your region (${country}) is not allowed.`, { status: 403 });
    }

    // 2. 特殊功能：获取当前 Worker 的出口 IP
    if (url.pathname === '/ip' || url.searchParams.has('get_my_ip')) {
      const resp = await fetch('https://api.ipify.org?format=json');
      const data = await resp.json();
      data.worker_country = country;
      return new Response(JSON.stringify(data), {
        headers: { 
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'X-IP-Rotation': Math.random().toString(36).substring(7)
        }
      });
    }

    // 3. 核心转发逻辑
    if (!targetUrl) {
      return new Response('Usage: ?url=https://auth.openai.com/...', { status: 400 });
    }

    try {
      // 随机化 X-Forwarded-For 诱导边缘节点切换
      const randomIp = () => Array.from({length: 4}, () => Math.floor(Math.random() * 255)).join('.');
      
      const modifiedHeaders = new Headers(request.headers);
      modifiedHeaders.set('X-Forwarded-For', randomIp());
      modifiedHeaders.set('X-Real-IP', randomIp());
      modifiedHeaders.delete('cf-connecting-ip');
      
      const modifiedRequest = new Request(targetUrl, {
        method: request.method,
        headers: modifiedHeaders,
        body: request.body,
        redirect: 'follow'
      });

      const response = await fetch(modifiedRequest);
      const newResponse = new Response(response.body, response);
      
      newResponse.headers.set('Access-Control-Allow-Origin', '*');
      newResponse.headers.set('X-Worker-Region', country);
      newResponse.headers.set('Cache-Control', 'no-store');
      
      return newResponse;
    } catch (e) {
      return new Response('Proxy Error: ' + e.message, { status: 500 });
    }
  }
}
