
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url);
  // 目标 OpenAI API 地址
  const targetUrl = `https://auth.openai.com${url.pathname}${url.search}`;

  // 复制原始请求，但修改 URL
  const newRequest = new Request(targetUrl, {
    method: request.method,
    headers: request.headers,
    body: request.body,
    redirect: 'follow' // 遵循重定向
  });

  // 发送请求到 OpenAI
  const response = await fetch(newRequest);

  // 复制响应，可以根据需要修改响应头等
  const newResponse = new Response(response.body, response);
  newResponse.headers.set('Access-Control-Allow-Origin', '*'); // 允许跨域访问
  return newResponse;
}
