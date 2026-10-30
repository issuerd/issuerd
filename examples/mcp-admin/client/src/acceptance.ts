import { isDeepStrictEqual } from "node:util";
import {
  auth,
  Client,
  StreamableHTTPClientTransport,
  type CallToolResult,
  type FetchLike,
  type VersionNegotiationOptions,
} from "@modelcontextprotocol/client";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/client/validators/ajv";
import { AcceptanceError } from "./errors.js";
import {
  LEGACY_VERSIONS,
  MODERN_VERSION,
  MCP_SCOPE,
  TOOL_NAMES,
  type CliOptions,
  type Era,
} from "./config.js";
import { ProtocolEvidence, type DpopEvidence } from "./evidence.js";
import {
  LoopbackCallback,
  openAuthorizationInBrowser,
  probeErrorAuthorizationResponse,
  scriptedAuthorization,
} from "./login.js";
import { NativeOAuthProvider } from "./provider.js";
import { findInPages } from "./paging.js";
import { requireSingleParameter, type AuthorizationEvidence } from "./validation.js";

interface ToolCallEvidence {
  arguments: Record<string, unknown>;
  structuredContent: unknown;
  outputSchemaValidated: true;
  textMirrorMatched: true;
}

interface EraEvidence {
  requestedEra: Era;
  negotiatedEra: "legacy" | "modern";
  negotiationMode: "legacy" | "auto" | "pinned";
  lifecycle: "initialize+notifications/initialized" | "server/discover";
  protocolVersion: string;
  discoverSupportedVersions?: string[];
  tools: string[];
  calls: Record<string, ToolCallEvidence>;
  additionalListCalls: number;
}

export interface AcceptanceReport {
  ok: true;
  sdk: "@modelcontextprotocol/client@2.4.0";
  issuer: string;
  resource: string;
  client: {
    clientId: string;
    applicationType: "native";
    tokenEndpointAuthMethod: "none";
    grantType: "authorization_code";
    pkce: "S256";
    scope: "openid mcp:read";
  };
  authorization: {
    redirectUri: string;
    registeredRedirectUri: string;
    nativeLoopbackPortException: true;
    exactResourceAtAuthorize: true;
    success: AuthorizationEvidence;
    error: AuthorizationEvidence;
  };
  dpop: DpopEvidence;
  eras: EraEvidence[];
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AcceptanceError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function records(value: unknown, label: string): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new AcceptanceError(`${label} must be an array`);
  return value.map((entry) => record(entry, label));
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) throw new AcceptanceError(`${label} must be a nonempty string`);
  return value;
}

async function callTool(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<ToolCallEvidence> {
  try {
    const result: CallToolResult = await client.callTool({ name, arguments: args });
    if (result.isError === true || result.structuredContent === undefined) {
      throw new AcceptanceError(`${name} returned a tool error or no structured content`);
    }
    const first = result.content[0];
    if (!first || first.type !== "text") throw new AcceptanceError(`${name} lacked its text JSON mirror`);
    if (!isDeepStrictEqual(JSON.parse(first.text), result.structuredContent)) {
      throw new AcceptanceError(`${name} text mirror differs from structuredContent`);
    }
    return {
      arguments: args,
      structuredContent: result.structuredContent,
      outputSchemaValidated: true,
      textMirrorMatched: true,
    };
  } catch (error) {
    if (error instanceof AcceptanceError) throw error;
    throw new AcceptanceError(`${name} failed SDK invocation or output schema validation`);
  }
}

async function runEra(
  requestedEra: Era,
  era: "legacy" | "modern",
  options: CliOptions,
  provider: NativeOAuthProvider,
  evidence: ProtocolEvidence,
): Promise<EraEvidence> {
  const negotiationMode = era === "legacy" ? "legacy" : requestedEra === "auto" ? "auto" : "pinned";
  const versionNegotiation: VersionNegotiationOptions =
    negotiationMode === "pinned" ? { mode: { pin: MODERN_VERSION } } : { mode: negotiationMode };
  const client = new Client(
    { name: "issuerd-mcp-admin-acceptance", version: "1.0.0" },
    {
      versionNegotiation,
      jsonSchemaValidator: new AjvJsonSchemaValidator(),
    },
  );
  const transport = new StreamableHTTPClientTransport(new URL(options.resource), {
    authProvider: provider,
    fetch: evidence.fetch,
    onInsufficientScope: "throw",
  });
  try {
    await client.connect(transport);
    const negotiatedEra = client.getProtocolEra();
    const protocolVersion = client.getNegotiatedProtocolVersion();
    if (negotiatedEra !== era || !protocolVersion) {
      throw new AcceptanceError(`did not negotiate the requested ${era} era`);
    }
    if (era === "legacy" && !(LEGACY_VERSIONS as readonly string[]).includes(protocolVersion)) {
      throw new AcceptanceError(`unexpected legacy protocol version ${protocolVersion}`);
    }
    if (era === "modern" && protocolVersion !== MODERN_VERSION) {
      throw new AcceptanceError(`unexpected modern protocol version ${protocolVersion}`);
    }
    const discover = client.getDiscoverResult();
    if (era === "modern" && !discover?.supportedVersions.includes(MODERN_VERSION)) {
      throw new AcceptanceError("modern server/discover did not advertise the negotiated version");
    }

    const listed = await client.listTools(undefined, { cacheMode: "refresh" });
    const names = listed.tools.map((tool) => tool.name);
    if (!isDeepStrictEqual(names, [...TOOL_NAMES])) {
      throw new AcceptanceError("tools/list did not return exactly the 23 read-only tools in deterministic order");
    }
    for (const tool of listed.tools) {
      if (!tool.outputSchema) throw new AcceptanceError(`${tool.name} has no output schema`);
    }

    const calls: Record<string, ToolCallEvidence> = {};
    let additionalListCalls = 0;
    const findPagedTool = (
      name: string,
      baseArgs: Record<string, unknown>,
      outputKey: string,
      predicate: (entry: Record<string, unknown>) => boolean,
    ) =>
      findInPages(
        async (first, max) => {
          const evidence = await callTool(client, name, { ...baseArgs, first, max });
          if (calls[name]) additionalListCalls += 1;
          else calls[name] = evidence;
          return record(evidence.structuredContent, `${name} output`)[outputKey];
        },
        `${name} ${outputKey}`,
        predicate,
      );

    calls.realm_get = await callTool(client, "realm_get", {});
    const realm = record(calls.realm_get.structuredContent, "realm_get output");
    if (realm.realm !== options.realm) throw new AcceptanceError("realm_get returned the wrong realm");

    const usersArgs = { search: "mcp-", first: 0, max: 20 };
    calls.users_search = await callTool(client, "users_search", usersArgs);
    const users = records(
      record(calls.users_search.structuredContent, "users_search output").users,
      "users_search users",
    );
    const selectedUser = users.find((user) => user.username === "mcp-observer");
    if (!selectedUser) throw new AcceptanceError("users_search did not discover mcp-observer");
    const userId = string(selectedUser.id, "discovered user id");
    calls.users_get = await callTool(client, "users_get", { id: userId });
    if (record(calls.users_get.structuredContent, "users_get output").id !== userId) {
      throw new AcceptanceError("users_get did not return the discovered user id");
    }

    calls.users_get_role_mappings = await callTool(client, "users_get_role_mappings", { id: userId });
    const roleMappings = record(calls.users_get_role_mappings.structuredContent, "role mappings output");
    const directRealmRoles = records(roleMappings.realmMappings, "direct realm mappings");
    const effectiveRealmRoles = records(roleMappings.effectiveRealmMappings, "effective realm mappings");
    if (!directRealmRoles.some((entry) => entry.name === "view-users")) {
      throw new AcceptanceError("users_get_role_mappings omitted the direct view-users role");
    }
    if (!effectiveRealmRoles.some((entry) => entry.name === "view-users")) {
      throw new AcceptanceError("users_get_role_mappings omitted the effective view-users role");
    }

    calls.users_get_credentials = await callTool(client, "users_get_credentials", { id: userId });
    const credentials = records(
      record(calls.users_get_credentials.structuredContent, "credentials output").credentials,
      "credential metadata",
    );
    if (!credentials.some((entry) => entry.type === "password")) {
      throw new AcceptanceError("users_get_credentials omitted the observer password metadata");
    }
    for (const credential of credentials) {
      if ("secretData" in credential || "credentialData" in credential || "value" in credential) {
        throw new AcceptanceError("users_get_credentials returned a credential payload");
      }
    }

    calls.users_get_sessions = await callTool(client, "users_get_sessions", { id: userId });
    const sessions = records(record(calls.users_get_sessions.structuredContent, "sessions output").sessions, "sessions");
    if (sessions.length !== 0) throw new AcceptanceError("observer unexpectedly has an interactive acceptance session");

    calls.attack_detection_status = await callTool(client, "attack_detection_status", { id: userId });
    const attackStatus = record(calls.attack_detection_status.structuredContent, "attack status output");
    if (attackStatus.userId !== userId || typeof attackStatus.numFailures !== "number" || typeof attackStatus.locked !== "boolean") {
      throw new AcceptanceError("attack_detection_status returned an invalid status");
    }

    const clientsArgs = { first: 0, max: 20 };
    calls.clients_list = await callTool(client, "clients_list", clientsArgs);
    const clients = records(
      record(calls.clients_list.structuredContent, "clients_list output").clients,
      "clients_list clients",
    );
    const selectedClient = clients.find((entry) => entry.clientId === "mcp-reporting");
    if (!selectedClient) throw new AcceptanceError("clients_list did not discover mcp-reporting");
    const clientId = string(selectedClient.id, "discovered client UUID");
    calls.clients_get = await callTool(client, "clients_get", { id: clientId });
    if (record(calls.clients_get.structuredContent, "clients_get output").id !== clientId) {
      throw new AcceptanceError("clients_get did not return the discovered client UUID");
    }

    const selectedGroup = await findPagedTool("groups_list", {}, "groups", (entry) => entry.name === "mcp-acceptance");
    if (!selectedGroup) throw new AcceptanceError("groups_list did not discover mcp-acceptance");
    const groupId = string(selectedGroup.id, "discovered group UUID");
    calls.users_get_groups = await callTool(client, "users_get_groups", { id: userId });
    const userGroups = records(
      record(calls.users_get_groups.structuredContent, "user groups output").groups,
      "user groups",
    );
    if (!userGroups.some((entry) => entry.id === groupId)) {
      throw new AcceptanceError("users_get_groups omitted the discovered membership");
    }
    calls.groups_get = await callTool(client, "groups_get", { id: groupId });
    if (record(calls.groups_get.structuredContent, "groups_get output").id !== groupId) {
      throw new AcceptanceError("groups_get did not return the discovered group UUID");
    }
    const member = await findPagedTool("groups_members", { id: groupId }, "members", (entry) => entry.id === userId);
    if (!member) throw new AcceptanceError("groups_members did not return mcp-observer");

    const selectedRole = await findPagedTool(
      "roles_list",
      {},
      "roles",
      (entry) => entry.name === "view-realm" && entry.clientRole === false,
    );
    if (!selectedRole) throw new AcceptanceError("roles_list did not discover the view-realm realm role");
    calls.roles_get = await callTool(client, "roles_get", { name: "view-realm" });
    if (record(calls.roles_get.structuredContent, "roles_get output").id !== selectedRole.id) {
      throw new AcceptanceError("roles_get did not return the discovered realm role");
    }

    calls.client_scopes_list = await callTool(client, "client_scopes_list", { first: 0, max: 100 });
    const clientScopes = records(
      record(calls.client_scopes_list.structuredContent, "client scopes output").clientScopes,
      "client scopes",
    );
    if (!clientScopes.some((entry) => entry.name === "profile")) {
      throw new AcceptanceError("client_scopes_list omitted the profile scope");
    }
    for (const scope of clientScopes) {
      for (const mapper of records(scope.protocolMappers ?? [], "protocol mapper summaries")) {
        if ("config" in mapper) throw new AcceptanceError("client_scopes_list returned raw mapper configuration");
      }
    }

    calls.events_search = await callTool(client, "events_search", { first: 0, max: 20 });
    const eventOutput = record(calls.events_search.structuredContent, "event search output");
    if (eventOutput.kind !== "user" || typeof eventOutput.total !== "number") {
      throw new AcceptanceError("events_search returned an invalid user-event page");
    }
    records(eventOutput.events, "audit events");

    calls.flows_list = await callTool(client, "flows_list", {});
    const flows = records(record(calls.flows_list.structuredContent, "flows output").flows, "flows");
    if (!flows.some((entry) => entry.alias === "browser")) {
      throw new AcceptanceError("flows_list omitted the browser flow");
    }

    calls.idp_list = await callTool(client, "idp_list", {});
    const idps = records(
      record(calls.idp_list.structuredContent, "identity providers output").identityProviders,
      "identity providers",
    );
    if (!idps.some((entry) => entry.alias === "mcp-acceptance-idp")) {
      throw new AcceptanceError("idp_list omitted the acceptance identity provider");
    }
    calls.idp_get = await callTool(client, "idp_get", { name: "mcp-acceptance-idp" });
    const idpConfig = record(record(calls.idp_get.structuredContent, "identity provider output").config, "IdP config");
    for (const key of Object.keys(idpConfig)) {
      if (/secret|credential|password|private.?key|token/i.test(key)) {
        throw new AcceptanceError("idp_get returned a sensitive configuration value");
      }
    }

    calls.keys_list = await callTool(client, "keys_list", {});
    const keys = records(record(calls.keys_list.structuredContent, "keys output").keys, "signing keys");
    if (!keys.length || keys.some((entry) => "privateDer" in entry || "privateKey" in entry)) {
      throw new AcceptanceError("keys_list returned no public metadata or leaked private material");
    }

    calls.serverinfo_get = await callTool(client, "serverinfo_get", {});
    const serverInfo = record(calls.serverinfo_get.structuredContent, "server info output");
    string(serverInfo.version, "server version");
    record(serverInfo.capabilities, "server capabilities");

    calls.sessions_list = await callTool(client, "sessions_list", { first: 0, max: 20 });
    const realmSessions = record(calls.sessions_list.structuredContent, "realm sessions output");
    records(realmSessions.sessions, "realm sessions");
    if (typeof realmSessions.total !== "number") {
      throw new AcceptanceError("sessions_list omitted the total count");
    }

    for (const name of TOOL_NAMES) {
      if (!calls[name]) throw new AcceptanceError(`missing ${name} acceptance call`);
    }
    return {
      requestedEra,
      negotiatedEra: era,
      negotiationMode,
      lifecycle: era === "legacy" ? "initialize+notifications/initialized" : "server/discover",
      protocolVersion,
      ...(discover ? { discoverSupportedVersions: discover.supportedVersions } : {}),
      tools: names,
      calls,
      additionalListCalls,
    };
  } finally {
    await client.close();
  }
}

function validateAuthorizationRequest(url: URL, options: CliOptions, provider: NativeOAuthProvider): void {
  requireSingleParameter(url.searchParams, "response_type", "code");
  requireSingleParameter(url.searchParams, "client_id", options.clientId);
  requireSingleParameter(url.searchParams, "redirect_uri", provider.redirectUrl);
  requireSingleParameter(url.searchParams, "scope", MCP_SCOPE);
  requireSingleParameter(url.searchParams, "resource", options.resource);
  requireSingleParameter(url.searchParams, "state", provider.store.expectedState());
  requireSingleParameter(url.searchParams, "code_challenge_method", "S256");
  requireSingleParameter(url.searchParams, "code_challenge");
}

async function issueToken(
  options: CliOptions,
  provider: NativeOAuthProvider,
  evidence: ProtocolEvidence,
  loopback: LoopbackCallback,
): Promise<{ success: AuthorizationEvidence; error: AuthorizationEvidence }> {
  const fetchFn: FetchLike = evidence.fetch;
  const initial = await auth(provider, {
    serverUrl: options.resource,
    scope: MCP_SCOPE,
    fetchFn,
  });
  if (initial !== "REDIRECT") throw new AcceptanceError("SDK did not request interactive authorization");
  const authorizationUrl = new URL(provider.takeAuthorizationUrl());
  validateAuthorizationRequest(authorizationUrl, options, provider);
  const error = await probeErrorAuthorizationResponse(authorizationUrl, provider, fetchFn);

  let callback: URL;
  if (options.mode === "script") {
    callback = await scriptedAuthorization(authorizationUrl, options, fetchFn);
  } else {
    openAuthorizationInBrowser(authorizationUrl);
    callback = await loopback.waitForCallback(options.timeoutMs);
  }
  const success = provider.validateCallback(callback);
  if (success.kind !== "success") throw new AcceptanceError(`authorization failed: ${success.error ?? "unknown error"}`);
  const authorizationCode = requireSingleParameter(callback.searchParams, "code");
  const iss = requireSingleParameter(callback.searchParams, "iss", options.issuer);
  const completed = await auth(provider, {
    serverUrl: options.resource,
    scope: MCP_SCOPE,
    authorizationCode,
    iss,
    fetchFn,
  });
  if (completed !== "AUTHORIZED") throw new AcceptanceError("SDK did not complete token issuance");
  return { success, error };
}

export async function runAcceptance(options: CliOptions): Promise<AcceptanceReport> {
  const loopback = await LoopbackCallback.start();
  try {
    const provider = new NativeOAuthProvider({
      issuer: options.issuer,
      resource: options.resource,
      clientId: options.clientId,
      redirectUri: loopback.redirectUri,
    });
    const evidence = new ProtocolEvidence(options.resource);
    const authorization = await issueToken(options, provider, evidence, loopback);
    const eras: EraEvidence[] = [];
    if (options.era === "auto" || options.era === "legacy") {
      eras.push(await runEra(options.era, "legacy", options, provider, evidence));
    }
    if (options.era === "auto" || options.era === "modern") {
      eras.push(await runEra(options.era, "modern", options, provider, evidence));
    }
    if (eras.length === 2) {
      const [legacy, modern] = eras;
      for (const name of TOOL_NAMES) {
        if (!isDeepStrictEqual(legacy?.calls[name]?.structuredContent, modern?.calls[name]?.structuredContent)) {
          throw new AcceptanceError(`${name} differs between legacy and modern eras`);
        }
      }
    }
    const additionalModernListCalls =
      eras.find((era) => era.negotiatedEra === "modern")?.additionalListCalls ?? 0;
    evidence.assertComplete(options.era === "legacy" ? 0 : TOOL_NAMES.length + 2 + additionalModernListCalls);
    return {
      ok: true,
      sdk: "@modelcontextprotocol/client@2.4.0",
      issuer: options.issuer,
      resource: options.resource,
      client: {
        clientId: options.clientId,
        applicationType: "native",
        tokenEndpointAuthMethod: "none",
        grantType: "authorization_code",
        pkce: "S256",
        scope: MCP_SCOPE,
      },
      authorization: {
        redirectUri: loopback.redirectUri,
        registeredRedirectUri: "http://127.0.0.1:8080/callback",
        nativeLoopbackPortException: true,
        exactResourceAtAuthorize: true,
        success: authorization.success,
        error: authorization.error,
      },
      dpop: evidence.dpop(await provider.dpopAlgorithm()),
      eras,
    };
  } finally {
    await loopback.close();
  }
}
