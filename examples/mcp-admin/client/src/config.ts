export const MCP_SCOPE = "openid mcp:read";
export const MODERN_VERSION = "2026-07-28";
export const LEGACY_VERSIONS = ["2025-06-18", "2025-11-25"] as const;
export const TOOL_NAMES = [
  "attack_detection_status",
  "client_scopes_list",
  "clients_get",
  "clients_list",
  "events_search",
  "flows_list",
  "groups_get",
  "groups_list",
  "groups_members",
  "idp_get",
  "idp_list",
  "keys_list",
  "realm_get",
  "roles_get",
  "roles_list",
  "serverinfo_get",
  "sessions_list",
  "users_get",
  "users_get_credentials",
  "users_get_groups",
  "users_get_role_mappings",
  "users_get_sessions",
  "users_search",
] as const;

export type LoginMode = "interactive" | "script";
export type Era = "auto" | "legacy" | "modern";

export interface CliOptions {
  issuer: string;
  baseUrl: string;
  realm: string;
  resource: string;
  clientId: string;
  mode: LoginMode;
  era: Era;
  username: string;
  password: string;
  timeoutMs: number;
}

export function parseRealmIssuer(raw: string): {
  issuer: string;
  baseUrl: string;
  realm: string;
  resource: string;
} {
  const url = new URL(raw);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("issuer must not contain credentials, query, or fragment");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("issuer must use HTTP or HTTPS");
  }
  const match = /^(.*)\/realms\/([A-Za-z0-9._~-]+)$/.exec(url.pathname);
  if (!match || match[1] === undefined || match[2] === undefined) {
    throw new Error("issuer must have the canonical /realms/{realm} form");
  }
  const issuer = url.href;
  const resource = `${issuer}/mcp`;
  return {
    issuer,
    baseUrl: `${url.origin}${match[1]}`,
    realm: match[2],
    resource,
  };
}

function option(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index < 0) return undefined;
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function enumOption<T extends string>(value: string, allowed: readonly T[], name: string): T {
  if ((allowed as readonly string[]).includes(value)) return value as T;
  throw new Error(`${name} must be one of: ${allowed.join(", ")}`);
}

export function parseCliOptions(args: string[], env: NodeJS.ProcessEnv): CliOptions {
  const issuer = option(args, "--issuer") ?? env.ISSUERD_ISSUER ?? "http://127.0.0.1:8080/realms/mcp-demo";
  const mode = enumOption(
    option(args, "--mode") ?? env.MCP_LOGIN_MODE ?? "interactive",
    ["interactive", "script"] as const,
    "--mode",
  );
  const era = enumOption(
    option(args, "--era") ?? env.MCP_ERA ?? "auto",
    ["auto", "legacy", "modern"] as const,
    "--era",
  );
  const timeoutRaw = option(args, "--timeout-ms") ?? env.MCP_TIMEOUT_MS ?? "180000";
  const timeoutMs = Number(timeoutRaw);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 600_000) {
    throw new Error("timeout must be an integer between 1000 and 600000 milliseconds");
  }
  return {
    ...parseRealmIssuer(issuer),
    clientId: option(args, "--client-id") ?? env.MCP_CLIENT_ID ?? "mcp-admin-native",
    mode,
    era,
    username: option(args, "--username") ?? env.MCP_USERNAME ?? "mcp-admin",
    password: env.MCP_PASSWORD ?? "Password123!",
    timeoutMs,
  };
}

export function usage(): string {
  return [
    "Usage: npm start -- [--issuer URL] [--client-id ID] [--era auto|legacy|modern]",
    "                  [--mode interactive|script] [--username NAME] [--timeout-ms N]",
    "Environment: ISSUERD_ISSUER, MCP_CLIENT_ID, MCP_ERA, MCP_LOGIN_MODE,",
    "             MCP_USERNAME, MCP_PASSWORD, MCP_TIMEOUT_MS.",
    "Lab default password: Password123! (override MCP_PASSWORD; never use it outside a lab).",
  ].join("\n");
}
