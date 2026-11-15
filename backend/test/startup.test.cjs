const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const path = require('node:path');
const os = require('node:os');
const packageInfo = require('../package.json');

test('production entry point honors PORT and starts from another working directory', async t => {
  assert.equal(packageInfo.scripts.start, 'node server.js');
  const reserve = net.createServer();
  reserve.listen(0, '127.0.0.1');
  await once(reserve, 'listening');
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));
  const child = spawn(process.execPath, [path.join(__dirname, '../server.js')], {
    cwd: os.tmpdir(),
    env: { ...process.env, PORT: String(port), SAFE_BROWSING_API_KEY: 'startup-test-placeholder', ALLOWED_ORIGINS: '', TRUST_PROXY: '' },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  t.after(async () => {
    if (child.exitCode === null) {
      const exited = once(child, 'exit');
      child.kill();
      await exited;
    }
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Startup timed out')), 10000);
    child.once('error', () => { clearTimeout(timer); reject(new Error('Startup failed')); });
    child.once('exit', () => { clearTimeout(timer); reject(new Error('Server exited before readiness')); });
    child.stdout.on('data', chunk => {
      if (chunk.toString().includes(`Server listening on port ${port}`)) { clearTimeout(timer); resolve(); }
    });
  });
  const response = await fetch(`http://127.0.0.1:${port}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok' });
});
