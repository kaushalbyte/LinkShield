const { test } = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const protobuf = require('protobufjs');
const path = require('node:path');
const realFetch = global.fetch;
const ResponseType = protobuf.loadSync(path.join(__dirname, '../safe-browsing.proto')).lookupType('SearchUrlsResponse');
const cleanBytes = Buffer.from('120308ac02', 'hex');
const encode = data => ResponseType.encode(ResponseType.fromObject(data)).finish();
const binary = bytes => new Response(bytes, { headers: { 'Content-Type': 'application/x-protobuf' } });

test('deployment backend', async t => {
  process.env.SAFE_BROWSING_API_KEY = 'unit-test-placeholder';
  process.env.ALLOWED_ORIGINS = '';
  delete process.env.TRUST_PROXY;
  const errorLogs = [];
  t.mock.method(console, 'error', (...args) => errorLogs.push(args));
  let upstream;
  let calls;
  global.fetch = async (address, options) => {
    calls++;
    assert.equal(address.origin + address.pathname, 'https://safebrowsing.googleapis.com/v5/urls:search');
    assert.equal(address.searchParams.get('key'), 'unit-test-placeholder');
    assert.ok(address.searchParams.get('urls').startsWith('http'));
    assert.equal(options.headers.Accept, 'application/x-protobuf');
    return upstream(address, options);
  };
  t.after(() => { global.fetch = realFetch; });

  async function start(t) {
    calls = 0;
    upstream = () => binary(cleanBytes);
    delete require.cache[require.resolve('../server')];
    const app = require('../server');
    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise(resolve => server.close(resolve)));
    const base = `http://127.0.0.1:${server.address().port}`;
    return {
      base,
      async scan(url, options = {}) {
        const response = await realFetch(base + '/api/check-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
          body: options.body === undefined ? JSON.stringify({ url }) : options.body,
        });
        assert.match(response.headers.get('content-type'), /application\/json/);
        return { status: response.status, data: await response.json(), headers: response.headers };
      }
    };
  }

  await t.test('valid URL, decoded response, cache hit and expiry', async t => {
    const { scan } = await start(t);
    let now = Date.now();
    t.mock.method(Date, 'now', () => now);
    const first = await scan('https://example.com');
    assert.equal(first.status, 200);
    assert.deepEqual(first.data.threats, []);
    assert.equal(first.data.url, 'https://example.com/');
    assert.equal(first.data.isThreat, false);
    assert.equal(first.data.expiresAt, now + 300000);
    assert.equal(first.headers.get('cache-control'), 'no-store');
    await scan('https://example.com');
    assert.equal(calls, 1);
    now += 300001;
    await scan('https://example.com');
    assert.equal(calls, 2);
  });

  await t.test('positive verdict and 30-minute freshness cap', async t => {
    const { scan } = await start(t);
    upstream = () => binary(encode({ threats: [{ url: 'example.com/', threatTypes: ['MALWARE'] }], cacheDuration: { seconds: 7200 } }));
    const result = await scan('https://example.com');
    assert.equal(result.status, 200);
    assert.equal(result.data.isThreat, true);
    assert.deepEqual(result.data.threats[0].threatTypes, ['MALWARE']);
    assert.ok(result.data.expiresAt <= Date.now() + 1800000);
  });

  await t.test('HTTP/IP URL accepted; submitted address is never fetched', async t => {
    const { scan } = await start(t);
    const result = await scan('http://127.0.0.1:9999/verify-account');
    assert.equal(result.status, 200);
    assert.equal(calls, 1);
  });

  await t.test('invalid inputs are rejected before any Google request', async t => {
    const { scan } = await start(t);
    for (const url of ['', 'hello world', 'ftp://example.com', 'javascript:alert(1)', 'https://user:password@example.com', 'https://example.com/' + 'a'.repeat(4096), 123, null]) {
      const result = await scan(url);
      assert.equal(result.status, 400);
      assert.equal(result.data.success, false);
      assert.equal(result.data.isThreat, null);
      assert.equal(result.data.code, 'INVALID_URL');
    }
    assert.equal(calls, 0);
  });

  await t.test('body limits and malformed JSON return JSON errors', async t => {
    const { scan } = await start(t);
    assert.equal((await scan(null, { body: '{' })).status, 400);
    const large = await scan(null, { body: JSON.stringify({ url: 'https://example.com', padding: 'x'.repeat(9000) }) });
    assert.equal(large.status, 413);
    assert.equal(large.data.success, false);
    assert.equal(calls, 0);
  });

  await t.test('Google failures never become successful verdicts or cache entries', async t => {
    const { scan } = await start(t);
    const failures = [
      [() => new Response('no access', { status: 403 }), 502, 'UPSTREAM_FAILED'],
      [() => new Response('<html>unavailable</html>', { status: 503 }), 502, 'UPSTREAM_FAILED'],
      [() => binary(Buffer.from([18, 255])), 502, 'UPSTREAM_INVALID_RESPONSE'],
      [() => binary(new Uint8Array()), 502, 'UPSTREAM_INVALID_RESPONSE'],
      [() => new Response('<html>oops</html>', { headers: { 'Content-Type': 'text/html' } }), 502, 'UPSTREAM_INVALID_RESPONSE'],
      [() => { throw new DOMException('test', 'TimeoutError'); }, 504, 'UPSTREAM_TIMEOUT'],
      [() => { throw new Error('unit-test-placeholder'); }, 502, 'UPSTREAM_UNAVAILABLE']
    ];
    for (const [handler, status, code] of failures) {
      upstream = handler;
      const result = await scan('https://example.com');
      assert.equal(result.status, status);
      assert.equal(result.data.code, code);
      assert.equal(result.data.isThreat, null);
      assert.equal(result.data.success, false);
    }
    upstream = () => binary(cleanBytes);
    assert.equal((await scan('https://example.com')).status, 200);
    assert.equal(calls, failures.length + 1);
    assert.ok(!JSON.stringify(errorLogs).includes('unit-test-placeholder'));
  });

  await t.test('missing API key is not a clean scan', async t => {
    const { scan } = await start(t);
    delete process.env.SAFE_BROWSING_API_KEY;
    try {
      const result = await scan('https://example.com');
      assert.equal(result.status, 503);
      assert.equal(result.data.code, 'NOT_CONFIGURED');
      assert.equal(calls, 0);
    } finally { process.env.SAFE_BROWSING_API_KEY = 'unit-test-placeholder'; }
  });

  await t.test('30-per-minute limit applies before parsing and ignores spoofed IP headers', async t => {
    const { scan } = await start(t);
    for (let index = 0; index < 30; index++) {
      assert.equal((await scan('', { headers: { 'X-Forwarded-For': `198.51.100.${index + 1}` } })).status, 400);
    }
    const denied = await scan('https://example.com', { headers: { 'X-Forwarded-For': '203.0.113.50' } });
    assert.equal(denied.status, 429);
    assert.equal(denied.data.code, 'RATE_LIMITED');
    assert.ok(Number(denied.headers.get('retry-after')) > 0);
    assert.equal(calls, 0);
  });

  await t.test('same-origin and explicit CORS allowlist', async t => {
    process.env.ALLOWED_ORIGINS = 'https://frontend.example';
    const { scan, base } = await start(t);
    try {
      assert.equal((await scan('https://example.com', { headers: { Origin: base } })).status, 200);
      const allowed = await scan('https://example.com', { headers: { Origin: 'https://frontend.example' } });
      assert.equal(allowed.headers.get('access-control-allow-origin'), 'https://frontend.example');
      assert.equal((await scan('https://example.com', { headers: { Origin: 'https://untrusted.example' } })).status, 403);
      const preflight = await realFetch(base + '/api/check-url', { method: 'OPTIONS', headers: { Origin: 'https://frontend.example' } });
      assert.equal(preflight.status, 204);
    } finally { process.env.ALLOWED_ORIGINS = ''; }
  });

  await t.test('health and frontend served; backend files never served', async t => {
    const { base } = await start(t);
    assert.deepEqual(await (await realFetch(base + '/health')).json(), { status: 'ok' });
    for (const route of ['/', '/index.html', '/css/style.css', '/js/app.js', '/js/analyzer.js']) {
      const response = await realFetch(base + route);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('x-powered-by'), null);
    }
    for (const route of ['/backend/.env', '/.env', '/backend/server.js', '/backend/package.json', '/node_modules/express/package.json']) {
      assert.equal((await realFetch(base + route)).status, 404);
    }
    const unknown = await realFetch(base + '/api/unknown');
    assert.equal(unknown.status, 404);
    assert.equal((await unknown.json()).success, false);
  });
});
