const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

test('frontend build publishes only public assets and validates the API origin', t => {
  const project = path.join(__dirname, '../..');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'linkshield-build-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const files = ['index.html', 'privacy.html', 'css/style.css', 'js/app.js', 'js/analyzer.js', 'scripts/build-frontend.cjs'];
  for (const file of files) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.copyFileSync(path.join(project, file), path.join(root, file));
  }
  fs.mkdirSync(path.join(root, 'backend'));
  fs.writeFileSync(path.join(root, 'backend/.env'), 'PRIVATE_TEST_MARKER=not-for-public-build');
  const build = value => spawnSync(process.execPath, ['scripts/build-frontend.cjs'], {
    cwd: root, env: { ...process.env, API_BASE_URL: value }, encoding: 'utf8', windowsHide: true
  });
  for (const value of ['', 'http://api.example', 'https://user:pass@api.example', 'https://api.example/api', 'https://api.example/?secret=x']) {
    assert.equal(build(value).status, 1);
    assert.equal(fs.existsSync(path.join(root, 'dist')), false);
  }
  assert.equal(build('https://api.example/').status, 0);
  const publicFiles = fs.readdirSync(path.join(root, 'dist'), { recursive: true })
    .filter(file => fs.statSync(path.join(root, 'dist', file)).isFile()).map(file => file.replaceAll('\\', '/')).sort();
  assert.deepEqual(publicFiles, files.filter(file => !file.startsWith('scripts/')).sort());
  assert.match(fs.readFileSync(path.join(root, 'dist/index.html'), 'utf8'), /content="https:\/\/api.example"/);
  assert.match(fs.readFileSync(path.join(root, 'index.html'), 'utf8'), /name="api-base-url" content=""/);
  for (const file of publicFiles) assert.doesNotMatch(fs.readFileSync(path.join(root, 'dist', file), 'utf8'), /PRIVATE_TEST_MARKER/);
  fs.writeFileSync(path.join(root, 'dist/unexpected.txt'), 'stale file');
  assert.equal(build('https://api.example').status, 0);
  assert.equal(fs.existsSync(path.join(root, 'dist/unexpected.txt')), false);
});

test('original heuristic test cases retain their scores and warnings', () => {
  const vm = require('node:vm');
  const context = vm.createContext({ URL });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../../js/analyzer.js'), 'utf8'), context);
  for (const [url, score, count] of [
    ['https://example.com', 0, 0],
    ['http://example.com', 15, 1],
    ['http://192.168.1.10/verify-account', 60, 3],
    ['https://example.com/reset-password', 20, 1],
    ['https://a.b.c.d.example.com', 10, 1]
  ]) {
    const result = context.analyzeSecurity(new URL(url));
    assert.equal(result.score, score);
    assert.equal(result.warnings.length, count);
  }
});
