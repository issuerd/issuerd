import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const directory = dirname(fileURLToPath(import.meta.url));
const driverPath = join(directory, 'authorization.mjs');
const fakeHarnessPath = join(directory, 'fixtures', 'fake-harness.mjs');

async function waitFor(check, message, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(message);
}

function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

function kill(pid) {
  try {
    process.kill(pid, 'SIGKILL');
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  }
}

function descendants(rootPid) {
  const listing = execFileSync('ps', ['-eo', 'pid=,ppid=,args='], { encoding: 'utf8' });
  const children = new Map();
  for (const line of listing.split('\n')) {
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/);
    if (!match) continue;
    const processInfo = { pid: Number(match[1]), args: match[3] };
    const parentPid = Number(match[2]);
    const siblings = children.get(parentPid) ?? [];
    siblings.push(processInfo);
    children.set(parentPid, siblings);
  }
  const result = [];
  const queue = [rootPid];
  while (queue.length > 0) {
    const parentPid = queue.shift();
    for (const child of children.get(parentPid) ?? []) {
      result.push(child);
      queue.push(child.pid);
    }
  }
  return result;
}

async function makeTempDirectory(t) {
  const path = await mkdtemp(join(tmpdir(), 'issuerd-mcp-lifecycle-'));
  t.after(() => rm(path, { recursive: true, force: true }));
  return path;
}

function startDriver(t, environment) {
  const child = spawn(process.execPath, [driverPath], {
    env: { ...process.env, MCP_CLIENT_SECRET: '', ...environment },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk.toString(); });
  child.stderr.on('data', (chunk) => { output += chunk.toString(); });
  const completion = once(child, 'close');
  t.after(async () => {
    const processes = descendants(child.pid);
    kill(child.pid);
    for (const { pid } of processes) kill(pid);
    await completion.catch(() => {});
  });
  return { child, completion, output: () => output };
}

async function waitForHarnessPid(pidFile) {
  return waitFor(async () => {
    try {
      const pid = Number(await readFile(pidFile, 'utf8'));
      return Number.isInteger(pid) && pid > 0 ? pid : undefined;
    } catch (error) {
      if (error.code === 'ENOENT') return undefined;
      throw error;
    }
  }, 'fake harness did not write its pid');
}

test('a signal-terminated harness cannot exit successfully', { timeout: 15_000 }, async (t) => {
  const temp = await makeTempDirectory(t);
  const pidFile = join(temp, 'harness.pid');
  const driver = startDriver(t, {
    CONFORMANCE_BIN: fakeHarnessPath,
    CONFORMANCE_RESULTS: join(temp, 'results'),
    FAKE_HARNESS_PID_FILE: pidFile,
  });
  const harnessPid = await waitForHarnessPid(pidFile);
  t.after(() => kill(harnessPid));

  process.kill(harnessPid, 'SIGTERM');
  const [code, signal] = await driver.completion;
  assert.equal(signal, null, driver.output());
  assert.notEqual(code, 0, driver.output());
});

test('interrupting the driver terminates the harness', { timeout: 15_000 }, async (t) => {
  const temp = await makeTempDirectory(t);
  const pidFile = join(temp, 'harness.pid');
  const driver = startDriver(t, {
    CONFORMANCE_BIN: fakeHarnessPath,
    CONFORMANCE_RESULTS: join(temp, 'results'),
    FAKE_HARNESS_PID_FILE: pidFile,
  });
  const harnessPid = await waitForHarnessPid(pidFile);
  t.after(() => kill(harnessPid));

  driver.child.kill('SIGTERM');
  const [code, signal] = await driver.completion;
  assert.equal(signal, null, driver.output());
  assert.notEqual(code, 0, driver.output());
  await waitFor(() => !isAlive(harnessPid), 'fake harness survived driver interruption');
});

test('interrupting browser login reaps the harness and Chromium', { timeout: 20_000 }, async (t) => {
  const temp = await makeTempDirectory(t);
  const pidFile = join(temp, 'harness.pid');
  let notifyLogin;
  const login = new Promise((resolve) => { notifyLogin = resolve; });
  const server = createServer((request, response) => {
    if (request.url === '/authorize') {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<form method="post" action="/login"><input name="username"><input name="password" type="password"><button type="submit">Sign in</button></form>');
      return;
    }
    if (request.url === '/login' && request.method === 'POST') {
      notifyLogin();
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<body>Waiting for callback</body>');
      return;
    }
    response.writeHead(404);
    response.end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const address = server.address();
  const driver = startDriver(t, {
    CONFORMANCE_BIN: fakeHarnessPath,
    CONFORMANCE_RESULTS: join(temp, 'results'),
    FAKE_HARNESS_PID_FILE: pidFile,
    FAKE_AUTHORIZATION_URL: `http://127.0.0.1:${address.port}/authorize`,
    MCP_BROWSER_CALLBACK_TIMEOUT_MS: '1000',
  });
  const harnessPid = await waitForHarnessPid(pidFile);
  await login;
  const children = await waitFor(() => {
    const processes = descendants(driver.child.pid);
    return processes.some(({ args }) => /chrome-headless-shell|playwright_chromiumdev_profile/.test(args))
      ? processes
      : undefined;
  }, 'Chromium did not start');
  t.after(() => {
    for (const { pid } of children) kill(pid);
    kill(harnessPid);
  });

  driver.child.kill('SIGTERM');
  const [code, signal] = await driver.completion;
  assert.equal(signal, null, driver.output());
  assert.notEqual(code, 0, driver.output());
  await waitFor(
    () => children.every(({ pid }) => !isAlive(pid)),
    'a driver child survived browser-login interruption',
  );
});
