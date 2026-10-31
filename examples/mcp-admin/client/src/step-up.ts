import { isDeepStrictEqual } from "node:util";
import {
  auth,
  Client,
  StreamableHTTPClientTransport,
  type CallToolResult,
  type FetchLike,
} from "@modelcontextprotocol/client";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/client/validators/ajv";
import {
  ConfidentialProtocolClient,
  nonempty,
  object,
  objects,
  validateStepUpChallenge,
  type ProtocolResponse,
} from "./ciba.js";
import { parseRealmIssuer } from "./config.js";
import { AcceptanceError } from "./errors.js";
import { cookies, LoopbackCallback, redirectLocation, scriptedAuthorization } from "./login.js";
import { NativeOAuthProvider } from "./provider.js";
import { requireSingleParameter } from "./validation.js";

const INITIAL_SCOPE = "openid mcp:read mcp:write";

interface StepUpOptions {
  issuer: string;
  baseUrl: string;
  realm: string;
  resource: string;
  clientId: string;
  clientSecret: string;
  username: string;
  password: string;
  targetUsername: string;
  multiNode: boolean;
}

function options(env: NodeJS.ProcessEnv): StepUpOptions {
  return {
    ...parseRealmIssuer(env.ISSUERD_ISSUER ?? "http://127.0.0.1:18089/realms/mcp-demo"),
    clientId: env.MCP_CONFIDENTIAL_CLIENT_ID ?? "mcp-admin-confidential",
    clientSecret: env.MCP_CLIENT_SECRET ?? "mcp-step-up-secret",
    username: env.MCP_USERNAME ?? "mcp-admin",
    password: env.MCP_PASSWORD ?? "Password123!",
    targetUsername: env.MCP_TARGET_USERNAME ?? "mcp-step-up-target",
    multiNode: env.MCP_MULTI_NODE === "1",
  };
}

function routing(multiNode: boolean): {
  fetchFn: FetchLike;
  select: (phase: string, node: "1" | "2" | "3") => void;
  evidence: Record<string, string>;
} {
  let selected: "1" | "2" | "3" = "1";
  const evidence: Record<string, string> = {};
  return {
    evidence,
    select: (phase, node) => {
      selected = node;
      if (multiNode) evidence[phase] = node;
    },
    fetchFn: async (input, init) => {
      const request = input instanceof Request ? input : undefined;
      const headers = new Headers(request?.headers);
      new Headers(init?.headers).forEach((value, key) => headers.set(key, value));
      if (multiNode) headers.set("x-mcp-demo-node", selected);
      const response = await fetch(input, { ...init, headers });
      if (multiNode && response.headers.get("x-mcp-demo-node") !== selected) {
        throw new AcceptanceError("multi-node gateway did not confirm the selected Issuerd node");
      }
      return response;
    },
  };
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#x27;");
}

async function approveFresh(
  approvalUrl: string,
  options: StepUpOptions,
  targetId: string,
  bindingMessage: string,
  fetchFn: FetchLike,
): Promise<void> {
  const initialUrl = new URL(approvalUrl);
  const initial = await fetchFn(initialUrl, { redirect: "manual" });
  if (initial.status !== 303) {
    throw new AcceptanceError("approval did not require fresh subject-first authentication");
  }
  const loginPage = redirectLocation(initial, initialUrl);
  const executionId = requireSingleParameter(loginPage.searchParams, "execution_id");
  const flowCookies = cookies(initial);
  if (!flowCookies.length) throw new AcceptanceError("approval login did not create a flow cookie");

  const loginUrl = new URL("/api/v1/auth/login", options.baseUrl);
  loginUrl.searchParams.set("realm", options.realm);
  const login = await fetchFn(loginUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: flowCookies.join("; "),
    },
    body: new URLSearchParams({
      execution_id: executionId,
      username: options.username,
      password: options.password,
    }),
    redirect: "manual",
  });
  const continuation = redirectLocation(login, loginUrl);
  if (continuation.origin !== initialUrl.origin || continuation.pathname !== initialUrl.pathname) {
    throw new AcceptanceError("fresh login did not return to the exact approval endpoint");
  }
  requireSingleParameter(
    continuation.searchParams,
    "approval_id",
    requireSingleParameter(initialUrl.searchParams, "approval_id"),
  );
  requireSingleParameter(continuation.searchParams, "iss", options.issuer);
  const ssoCookies = cookies(login);
  if (!ssoCookies.length) throw new AcceptanceError("fresh approval login did not create an SSO session");
  const page = await fetchFn(continuation, {
    headers: { cookie: ssoCookies.join("; ") },
    redirect: "manual",
  });
  if (page.status !== 200) throw new AcceptanceError("authenticated approval page was not rendered");
  const html = await page.text();
  for (const expected of [
    "users_delete",
    targetId,
    escapeHtml(bindingMessage),
    "&quot;confirmation&quot;: &quot;DELETE&quot;",
  ]) {
    if (!html.includes(expected)) throw new AcceptanceError("approval page omitted exact operation details");
  }
  const proof = /name="csrf_proof" value="([^"]+)"/.exec(html)?.[1];
  if (!proof) throw new AcceptanceError("approval page had no session-bound CSRF proof");
  const approvalId = requireSingleParameter(initialUrl.searchParams, "approval_id");
  const decisionUrl = new URL(initialUrl);
  decisionUrl.search = "";
  const decision = await fetchFn(decisionUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: ssoCookies.join("; "),
    },
    body: new URLSearchParams({ approval_id: approvalId, csrf_proof: proof, action: "approve" }),
    redirect: "manual",
  });
  if (decision.status !== 200) throw new AcceptanceError("exact operation approval was rejected");
}

function successfulToolResult(response: ProtocolResponse): Record<string, unknown> {
  if (response.status !== 200) throw new AcceptanceError(`MCP call returned HTTP ${response.status}`);
  const root = object(response.body, "MCP response");
  const result = object(root.result, "MCP result");
  if (result.isError === true) throw new AcceptanceError("MCP tool returned an error result");
  return object(result.structuredContent, "structured tool result");
}

function sdkStructured(result: CallToolResult): Record<string, unknown> {
  if (result.isError === true || result.structuredContent === undefined) {
    throw new AcceptanceError("SDK tool call failed or returned no structured content");
  }
  return object(result.structuredContent, "SDK structured tool result");
}

async function readResources(client: Client, realm: string): Promise<Record<string, unknown>[]> {
  const listed = await client.listResources(undefined, { cacheMode: "refresh" });
  const expected = ["clients", "roles", "config"].map((kind) => `issuerd://realm/${realm}/${kind}`);
  if (!isDeepStrictEqual(listed.resources.map((resource) => resource.uri).sort(), expected.sort())) {
    throw new AcceptanceError("resources/list did not return exactly the three realm resources");
  }
  const snapshots: Record<string, unknown>[] = [];
  for (const uri of expected) {
    const result = await client.readResource({ uri }, { cacheMode: "refresh" });
    const content = result.contents[0];
    if (!content || content.uri !== uri || content.mimeType !== "application/json" || !("text" in content)) {
      throw new AcceptanceError(`${uri} did not return JSON text content`);
    }
    const payload = object(JSON.parse(content.text), `${uri} payload`);
    const serialized = JSON.stringify(payload);
    if (/smtpServer|secretData|credentialData|privateDer|pairwise_sector_key/.test(serialized)) {
      throw new AcceptanceError(`${uri} returned sensitive configuration`);
    }
    snapshots.push({ uri, payload });
  }
  return snapshots;
}

async function run(options: StepUpOptions): Promise<Record<string, unknown>> {
  const loopback = await LoopbackCallback.start();
  const route = routing(options.multiNode);
  try {
    route.select("initial", "1");
    const provider = new NativeOAuthProvider({
      issuer: options.issuer,
      resource: options.resource,
      clientId: options.clientId,
      redirectUri: loopback.redirectUri,
      clientSecret: options.clientSecret,
      scope: INITIAL_SCOPE,
    });
    const initial = await auth(provider, {
      serverUrl: options.resource,
      scope: INITIAL_SCOPE,
      fetchFn: route.fetchFn,
    });
    if (initial !== "REDIRECT") throw new AcceptanceError("confidential client did not begin interactive authorization");
    const callback = await scriptedAuthorization(
      new URL(provider.takeAuthorizationUrl()),
      options,
      route.fetchFn,
    );
    const authorizationCode = requireSingleParameter(callback.searchParams, "code");
    const iss = requireSingleParameter(callback.searchParams, "iss", options.issuer);
    const completed = await auth(provider, {
      serverUrl: options.resource,
      scope: INITIAL_SCOPE,
      authorizationCode,
      iss,
      fetchFn: route.fetchFn,
    });
    if (completed !== "AUTHORIZED") throw new AcceptanceError("confidential authorization-code issuance failed");
    const initialToken = provider.tokens()?.access_token;
    if (!initialToken) throw new AcceptanceError("confidential provider did not retain the initial token");

    const client = new Client(
      { name: "issuerd-mcp-confidential-acceptance", version: "1.0.0" },
      {
        versionNegotiation: { mode: "legacy" },
        jsonSchemaValidator: new AjvJsonSchemaValidator(),
      },
    );
    const transport = new StreamableHTTPClientTransport(new URL(options.resource), {
      authProvider: provider,
      fetch: route.fetchFn,
      onInsufficientScope: "throw",
    });
    let targetId: string;
    let wrongTargetId: string;
    let snapshots: Record<string, unknown>[];
    try {
      await client.connect(transport);
      snapshots = await readResources(client, options.realm);
      const search = sdkStructured(await client.callTool({
        name: "users_search",
        arguments: { search: "mcp-", first: 0, max: 100 },
      }));
      const users = objects(search.users, "user search results");
      const target = users.find((user) => user.username === options.targetUsername);
      const wrongTarget = users.find((user) => user.username === "mcp-observer");
      if (!target || !wrongTarget) throw new AcceptanceError("step-up user fixtures were not discoverable");
      targetId = nonempty(target.id, "target user id");
      wrongTargetId = nonempty(wrongTarget.id, "wrong-target user id");
      const updated = sdkStructured(await client.callTool({
        name: "users_update",
        arguments: { id: targetId, firstName: "Step-up target" },
      }));
      if (updated.status !== "completed") throw new AcceptanceError("ordinary reversible write did not complete");
    } finally {
      await client.close();
    }

    const session = await provider.dpop();
    const protocol = new ConfidentialProtocolClient({
      session,
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      fetchFn: route.fetchFn,
    });
    const arguments_ = { id: targetId, confirmation: "DELETE" };
    const challengeResponse = await protocol.mcp(options.resource, initialToken, "users_delete", arguments_);
    const cibaEndpoint = `${options.issuer}/protocol/openid-connect/ext/ciba/auth`;
    const challenge = validateStepUpChallenge(challengeResponse, cibaEndpoint, options.resource);
    const initiated = await protocol.initiateCiba(
      challenge.backchannelAuthenticationEndpoint,
      challenge,
      options.username,
    );

    route.select("approval", "2");
    await approveFresh(
      initiated.approvalUrl,
      options,
      targetId,
      challenge.bindingMessage,
      route.fetchFn,
    );

    route.select("poll", "3");
    const tokenEndpoint = `${options.issuer}/protocol/openid-connect/token`;
    const stepUpToken = await protocol.pollCiba(
      tokenEndpoint,
      initiated.authReqId,
      options.resource,
      initiated.interval,
    );

    route.select("execution", "1");
    const unrelated = await protocol.mcp(options.resource, stepUpToken.accessToken, "realm_get", {});
    if (unrelated.status !== 403) throw new AcceptanceError("single-purpose token reached an unrelated read tool");
    const wrong = await protocol.mcp(options.resource, stepUpToken.accessToken, "users_delete", {
      id: wrongTargetId,
      confirmation: "DELETE",
    });
    if (wrong.status !== 403 || object(wrong.body, "binding error").error !== "operation_binding_mismatch") {
      throw new AcceptanceError("step-up grant accepted changed target arguments");
    }

    const first = successfulToolResult(
      await protocol.mcp(options.resource, stepUpToken.accessToken, "users_delete", arguments_),
    );
    const replay = successfulToolResult(
      await protocol.mcp(options.resource, stepUpToken.accessToken, "users_delete", arguments_),
    );
    if (first.status !== "completed" || first.tool !== "users_delete" || first.id !== targetId) {
      throw new AcceptanceError("strict deletion returned an invalid result");
    }
    if (!isDeepStrictEqual(first, replay)) {
      throw new AcceptanceError("exact retry did not reconcile the recorded result");
    }
    const after = successfulToolResult(
      await protocol.mcp(options.resource, initialToken, "users_search", {
        username: options.targetUsername,
        first: 0,
        max: 20,
      }),
    );
    if (objects(after.users, "post-deletion users").length !== 0) {
      throw new AcceptanceError("strict deletion did not remove exactly the approved target");
    }

    route.select("cibaReplay", "3");
    const replayCode = await protocol.pollCibaReplay(tokenEndpoint, initiated.authReqId, options.resource);
    if (replayCode !== "invalid_grant") {
      throw new AcceptanceError("consumed auth_req_id did not fail with invalid_grant");
    }

    return {
      ok: true,
      sdk: "@modelcontextprotocol/client@2.4.0",
      issuer: options.issuer,
      resource: options.resource,
      profile: {
        clientId: options.clientId,
        tokenEndpointAuthMethod: "client_secret_basic",
        grantType: "authorization_code",
        pkce: "S256",
        initialScope: INITIAL_SCOPE,
        dpopAlgorithm: session.alg,
      },
      resources: snapshots.map((snapshot) => ({
        uri: snapshot.uri,
        redacted: true,
      })),
      ordinaryWrite: { tool: "users_update", status: "completed" },
      strict: {
        tool: "users_delete",
        targetId,
        operationId: challenge.operationId,
        exactApproval: true,
        freshAuthentication: true,
        sessionBoundCsrf: true,
        tokenType: "DPoP",
        scope: "openid mcp:step_up",
        refreshToken: false,
        expiresIn: stepUpToken.expiresIn,
        unrelatedToolRejected: true,
        changedArgumentsRejected: true,
        execution: first,
        replayReconciled: true,
        cibaReplay: replayCode,
      },
      ...(options.multiNode ? { multiNode: route.evidence } : {}),
    };
  } finally {
    await loopback.close();
  }
}

async function main(): Promise<void> {
  try {
    const report = await run(options(process.env));
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    const message = error instanceof AcceptanceError
      ? error.message
      : "confidential step-up acceptance failed; no credentials or protocol artifacts were logged";
    process.stdout.write(`${JSON.stringify({ ok: false, error: { message } }, null, 2)}\n`);
    process.exitCode = 1;
  }
}

await main();
