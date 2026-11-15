const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const project = path.join(__dirname, '../..');
const html = fs.readFileSync(path.join(project, 'index.html'), 'utf8');

function page(apiBase = '') {
  const elements = {};
  for (const match of html.matchAll(/id="([^"]+)"/g)) {
    elements[match[1]] = { value: '', textContent: '', hidden: false, style: {}, children: [],
      addEventListener(event, handler) { this[event] = handler; },
      appendChild(child) { this.children.push(child); },
      set innerHTML(value) { this.children = []; }
    };
  }
  const alerts = [];
  const requests = [];
  const timers = new Map();
  let timerId = 0;
  const context = vm.createContext({
    URL, AbortController, Date,
    document: {
      getElementById: id => elements[id],
      querySelector: () => ({ content: apiBase }),
      createElement: () => ({ textContent: '' })
    },
    alert: text => alerts.push(text),
    console: { log() {} },
    setTimeout(callback, ms) { timers.set(++timerId, { callback, ms }); return timerId; },
    clearTimeout(id) { timers.delete(id); },
    fetch(destination, options) {
      return new Promise((resolve, reject) => requests.push({ destination, options, resolve, reject }));
    }
  });
  vm.runInContext(fs.readFileSync(path.join(project, 'js/analyzer.js'), 'utf8'), context);
  vm.runInContext(fs.readFileSync(path.join(project, 'js/app.js'), 'utf8'), context);
  return { elements, alerts, requests, timers,
    scan(value) { elements.urlInput.value = value; return elements.scanbtn.click(); }
  };
}

function verdict(url, threat = false) {
  return { success: true, url: new URL(url).href, isThreat: threat,
    threats: threat ? [{ url, threatTypes: ['MALWARE'] }] : [], expiresAt: Date.now() + 300000 };
}
const response = (data, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => data });

test('normal frontend keeps heuristic results and receives a successful database check', async () => {
  const p = page();
  const done = p.scan('https://example.com');
  assert.equal(p.elements.result.hidden, false);
  assert.equal(p.elements.riskScore.textContent, 'Risk Score: 0/100');
  assert.match(p.elements.apiStatus.textContent, /Checking/);
  assert.equal(p.requests[0].destination, '/api/check-url');
  assert.equal(JSON.parse(p.requests[0].options.body).url, 'https://example.com/');
  p.requests[0].resolve(response(verdict('https://example.com')));
  await done;
  assert.match(p.elements.apiStatus.textContent, /No known threat match/);
  assert.match(p.elements.apiStatus.textContent, /not guaranteed/);
  assert.equal(p.elements.googleAttribution.hidden, true);
});

test('older successful response cannot overwrite latest scan even when abort is ignored', async () => {
  const p = page();
  const old = p.scan('http://192.168.1.10/verify-account');
  assert.equal(p.elements.riskScore.textContent, 'Risk Score: 60/100');
  const latest = p.scan('https://example.com');
  assert.equal(p.requests[0].options.signal.aborted, true);
  p.requests[1].resolve(response(verdict('https://example.com')));
  await latest;
  p.requests[0].resolve(response(verdict('http://192.168.1.10/verify-account', true)));
  await old;
  assert.equal(p.elements.resultURL.textContent, 'https://example.com/');
  assert.equal(p.elements.resultTitle.textContent, '');
  assert.match(p.elements.apiStatus.textContent, /No known threat match/);
});

test('older failure cannot overwrite latest positive verdict', async () => {
  const p = page();
  const old = p.scan('https://first.example');
  const latest = p.scan('https://second.example');
  p.requests[1].resolve(response(verdict('https://second.example', true)));
  await latest;
  p.requests[0].reject(new TypeError('network error'));
  await old;
  assert.match(p.elements.apiStatus.textContent, /potentially harmful/);
  assert.equal(p.elements.googleAttribution.hidden, false);
});

test('race during response JSON decoding is ignored', async () => {
  const p = page();
  let finishJSON;
  let markJSONStarted;
  const jsonStarted = new Promise(resolve => { markJSONStarted = resolve; });
  const old = p.scan('https://first.example');
  p.requests[0].resolve({ ok: true, status: 200, json: () => new Promise(resolve => { finishJSON = resolve; markJSONStarted(); }) });
  await jsonStarted;
  const latest = p.scan('https://second.example');
  p.requests[1].resolve(response(verdict('https://second.example')));
  await latest;
  finishJSON(verdict('https://first.example', true));
  await old;
  assert.equal(p.elements.resultTitle.textContent, '');
  assert.equal(p.elements.resultURL.textContent, 'https://second.example/');
});

test('invalid next input cancels outstanding scan and keeps result hidden', async () => {
  const p = page();
  const old = p.scan('https://example.com');
  await p.scan('hello world');
  p.requests[0].resolve(response(verdict('https://example.com', true)));
  await old;
  assert.equal(p.requests.length, 1);
  assert.equal(p.elements.result.hidden, true);
  assert.match(p.alerts[0], /Invalid URL/);
});

test('invalid input, unsupported protocol and embedded credentials never contact backend', async () => {
  const p = page();
  for (const url of ['', 'hello world', 'ftp://example.com', 'https://user:password@example.com']) await p.scan(url);
  assert.equal(p.alerts.length, 4);
  assert.equal(p.requests.length, 0);
});

test('network, external service, rate-limit and backend-format errors are distinct', async () => {
  for (const [status, expected] of [[502, /external threat service/], [503, /external threat service/], [504, /external threat service/], [429, /Too many scans/], [400, /backend rejected/], [413, /too large/], [403, /configuration error/], [404, /configuration error/]]) {
    const p = page();
    const done = p.scan('https://example.com');
    p.requests[0].resolve(response({ success: false }, status));
    await done;
    assert.match(p.elements.apiStatus.textContent, expected);
    assert.doesNotMatch(p.elements.apiStatus.textContent, /No known threat match/);
    assert.equal(p.elements.googleAttribution.hidden, true);
  }
  const p = page();
  const done = p.scan('https://example.com');
  p.requests[0].reject(new TypeError('network error'));
  await done;
  assert.match(p.elements.apiStatus.textContent, /Cannot connect to the backend/);
});

test('malformed or unsuccessful 200 response cannot claim a clean check', async () => {
  for (const data of [null, {}, { success: false }, { ...verdict('https://example.com'), isThreat: undefined }, verdict('https://wrong.example')]) {
    const p = page();
    const done = p.scan('https://example.com');
    p.requests[0].resolve(response(data));
    await done;
    assert.match(p.elements.apiStatus.textContent, /invalid response/);
  }
  const p = page();
  const done = p.scan('https://example.com');
  p.requests[0].resolve({ ok: true, status: 200, json: async () => { throw new SyntaxError('bad JSON'); } });
  await done;
  assert.match(p.elements.apiStatus.textContent, /invalid response/);
});

test('frontend timeout has no successful verdict', async () => {
  const p = page();
  const done = p.scan('https://example.com');
  [...p.timers.values()].find(timer => timer.ms === 90000).callback();
  assert.equal(p.requests[0].options.signal.aborted, true);
  p.requests[0].reject(new DOMException('aborted', 'AbortError'));
  await done;
  assert.match(p.elements.apiStatus.textContent, /timed out/);
});

test('Google warning expires without changing local scoring', async () => {
  const p = page();
  const done = p.scan('https://example.com');
  p.requests[0].resolve(response(verdict('https://example.com', true)));
  await done;
  assert.equal(p.elements.googleAttribution.hidden, false);
  assert.equal(p.timers.size, 1);
  [...p.timers.values()][0].callback();
  assert.equal(p.elements.googleAttribution.hidden, true);
  assert.equal(p.elements.resultTitle.textContent, '');
  assert.match(p.elements.apiStatus.textContent, /expired/);
  assert.equal(p.elements.riskScore.textContent, 'Risk Score: 0/100');
});

test('configurable API origin and Google attribution are present', async () => {
  const p = page('https://api.example/');
  const done = p.scan('https://example.com');
  assert.equal(p.requests[0].destination, 'https://api.example/api/check-url');
  p.requests[0].resolve(response(verdict('https://example.com')));
  await done;
  assert.match(html, /Advisory provided by Google/);
});

test('Enter submits a scan without reloading the page', async () => {
  const p = page();
  p.elements.urlInput.value = 'https://example.com';
  let prevented = false;
  p.elements.urlForm.submit({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(p.requests.length, 1);
  p.requests[0].resolve(response(verdict('https://example.com')));
  await new Promise(resolve => setImmediate(resolve));
  assert.match(p.elements.apiStatus.textContent, /No known threat match/);
});
