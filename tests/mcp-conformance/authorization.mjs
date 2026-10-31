import { spawn } from 'node:child_process';
import { chromium } from 'playwright';

const harness = process.env.CONFORMANCE_BIN ?? `${process.cwd()}/conformance/dist/index.js`;
const url = process.env.ISSUERD_ISSUER ?? 'http://127.0.0.1:18092/realms/mcp-demo';
const resource = process.env.MCP_RESOURCE ?? `${url}/mcp`;
const clientId = process.env.MCP_CLIENT_ID ?? 'mcp-admin-native';
const clientSecret = process.env.MCP_CLIENT_SECRET;
const port = process.env.MCP_CALLBACK_PORT ?? '3000';
const username = process.env.MCP_USERNAME ?? 'mcp-admin';
const password = process.env.MCP_PASSWORD ?? 'Password123!';
const args = [
  harness,
  'authorization',
  '--url', url,
  '--client-id', clientId,
  '--resource', resource,
  '--port', port,
  '-o', process.env.CONFORMANCE_RESULTS ?? `${process.cwd()}/results/authorization`,
];
if (clientSecret) args.push('--client-secret', clientSecret);

const callbackTimeoutMs = Number(process.env.MCP_BROWSER_CALLBACK_TIMEOUT_MS ?? 30_000);
const browsers = new Set();
const child = spawn(process.execPath, args, {
  env: { ...process.env },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let output = '';
let codeGrantLogin;
let dpopLogin;
let successfulSummary = false;
async function authorizeInBrowser(authorizationUrl) {
  console.error('authorization browser login started');
  const browser = await chromium.launch({ headless: true });
  browsers.add(browser);
  let page;
  try {
    page = await browser.newPage();
    await page.goto(authorizationUrl, { waitUntil: 'domcontentloaded' });
    await page.locator('input[name="username"]').fill(username);
    await page.locator('input[name="password"]').fill(password);
    await Promise.all([
      page.waitForURL((url) => url.pathname === '/callback', { timeout: callbackTimeoutMs }),
      page.locator('button[type="submit"]').click(),
    ]);
    console.error('authorization form submitted');
  } catch (error) {
    const body = page ? await page.locator('body').innerText().catch(() => '') : '';
    console.error(`authorization page did not reach callback: ${body}`);
    throw error;
  } finally {
    try {
      await browser.close();
    } finally {
      browsers.delete(browser);
    }
  }
}
function inspect(chunk) {
  output += chunk.toString();
  if (!successfulSummary && /=== SUMMARY ===[\s\S]*Total: 5 passed, 0 failed/.test(output)) {
    successfulSummary = true;
    child.kill('SIGTERM');
  }
  if (!codeGrantLogin) {
    const match = output.match(
      /=== Running scenario: authorization-code-grant ===[\s\S]*?Access the following URL in your browser and complete the authentication process\.\s*(https?:\/\/\S+)/,
    );
    if (match) codeGrantLogin = authorizeInBrowser(match[1]);
  }
  if (!dpopLogin) {
    const match = output.match(
      /=== Running scenario: dpop ===[\s\S]*?Access the following URL in your browser and complete authentication:\s*(https?:\/\/\S+)/,
    );
    if (match) dpopLogin = authorizeInBrowser(match[1]);
  }
}
child.stdout.on('data', inspect);
child.stderr.on('data', inspect);
let rejectCompletion;
const completion = new Promise((resolve, reject) => {
  rejectCompletion = reject;
  child.once('error', reject);
  child.once('close', resolve);
});
const onSigint = () => {
  child.kill('SIGTERM');
  rejectCompletion(new Error('authorization conformance interrupted by SIGINT'));
};
const onSigterm = () => {
  child.kill('SIGTERM');
  rejectCompletion(new Error('authorization conformance interrupted by SIGTERM'));
};
process.once('SIGINT', onSigint);
process.once('SIGTERM', onSigterm);
const timeout = new Promise((_, reject) => {
  setTimeout(() => {
    child.kill('SIGTERM');
    reject(new Error('authorization conformance timed out'));
  }, 300_000).unref();
});
try {
  const status = await Promise.race([completion, timeout]);
  await Promise.all([codeGrantLogin, dpopLogin]);
  process.stdout.write(output);
  process.exitCode = successfulSummary ? 0 : (status ?? 1);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n${output}`);
  process.exitCode = 1;
} finally {
  process.removeListener('SIGINT', onSigint);
  process.removeListener('SIGTERM', onSigterm);
  child.kill('SIGTERM');
  await Promise.allSettled([completion, codeGrantLogin, dpopLogin]);
  await Promise.allSettled([...browsers].map((browser) => browser.close()));
  browsers.clear();
}
