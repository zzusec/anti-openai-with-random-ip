
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const targetUrl = url.searchParams.get('url');
    
    // 1. 地区过滤：排除中国地区 (CN, HK, MO)
    const country = request.cf.country;
    const blockedRegions = ['CN', 'HK', 'MO'];
    
    if (blockedRegions.includes(country)) {
      return new Response(`Access Denied: Your region (${country}) is not allowed for OpenAI registration.`, { 
        status: 403,
        headers: { 'Content-Type': 'text/plain' }
      });
    }

    // 2. 特殊功能：获取当前 Worker 的出口 IP
    if (url.pathname === '/ip' || url.searchParams.has('get_my_ip')) {
      const resp = await fetch('https://api.ipify.org?format=json');
      const data = await resp.json();
      data.worker_country = country;
      return new Response(JSON.stringify(data), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 3. 核心转发逻辑
    if (!targetUrl) {
      return new Response('Usage: ?url=https://auth.openai.com/...', { status: 400 });
    }

    try {
      const modifiedRequest = new Request(targetUrl, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: 'follow'
      });

      // 清理可能导致拦截的 Header
      modifiedRequest.headers.delete('cf-connecting-ip');
      modifiedRequest.headers.delete('x-real-ip');
      modifiedRequest.headers.delete('forwarded');

      const response = await fetch(modifiedRequest);
      const newResponse = new Response(response.body, response);
      
      // 允许跨域
      newResponse.headers.set('Access-Control-Allow-Origin', '*');
      newResponse.headers.set('X-Worker-Region', country);
      
      return newResponse;
    } catch (e) {
      return new Response('Proxy Error: ' + e.message, { status: 500 });
    }
  }
}
