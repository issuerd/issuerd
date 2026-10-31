import { createHash, randomBytes } from 'node:crypto';

const issuer = process.env.ISSUERD_ISSUER ?? 'http://127.0.0.1:18092/realms/mcp-demo';
const baseUrl = process.env.ISSUERD_BASE_URL ?? issuer;
const clientId = process.env.MCP_CLIENT_ID ?? 'mcp-admin-native';
const username = process.env.MCP_USERNAME ?? 'mcp-admin';
const password = process.env.MCP_PASSWORD ?? 'Password123!';
const resource = process.env.MCP_RESOURCE ?? `${issuer}/mcp`;
const redirectUri = process.env.MCP_REDIRECT_URI ?? 'http://127.0.0.1:3000/callback';
const scope = process.env.MCP_SCOPE ?? 'openid mcp:read';
const state = randomBytes(32).toString('base64url');
const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');

function single(url, name, expected) {
  const values = url.searchParams.getAll(name);
  if (values.length !== 1 || (expected !== undefined && values[0] !== expected)) {
    throw new Error(`invalid ${name} response parameter`);
  }
  return values[0];
}

const authorizeUrl = new URL(`${baseUrl}/protocol/openid-connect/auth`);
authorizeUrl.search = new URLSearchParams({
  response_type: 'code',
  client_id: clientId,
  redirect_uri: redirectUri,
  state,
  code_challenge: challenge,
  code_challenge_method: 'S256',
  resource,
  scope,
});
const authorization = await fetch(authorizeUrl, { redirect: 'manual' });
if (authorization.status !== 303) throw new Error(`authorization returned ${authorization.status}`);
const loginLocation = new URL(authorization.headers.get('location'), authorizeUrl);
const executionId = single(loginLocation, 'execution_id');
const flowCookie = authorization.headers
  .getSetCookie()
  .map((cookie) => cookie.split(';')[0])
  .join('; ');
const loginUrl = new URL('/api/v1/auth/login', baseUrl);
loginUrl.searchParams.set('realm', baseUrl.split('/').at(-1));
const login = await fetch(loginUrl, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: flowCookie },
  body: new URLSearchParams({ execution_id: executionId, username, password }),
  redirect: 'manual',
});
if (login.status !== 303) throw new Error(`login returned ${login.status}`);
const callback = new URL(login.headers.get('location'), loginUrl);
const expectedCallback = new URL(redirectUri);
if (callback.origin !== expectedCallback.origin || callback.pathname !== expectedCallback.pathname) {
  throw new Error('authorization returned the wrong callback');
}
single(callback, 'state', state);
single(callback, 'iss', issuer);
const code = single(callback, 'code');
const tokenResponse = await fetch(`${baseUrl}/protocol/openid-connect/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    client_id: clientId,
    resource,
  }),
});
if (tokenResponse.status !== 200) throw new Error(`token endpoint returned ${tokenResponse.status}`);
const token = await tokenResponse.json();
if (typeof token.access_token !== 'string') throw new Error('token response has no access token');
process.stdout.write(token.access_token);
