type JsonObject = Record<string, unknown>;

interface SetupOptions {
  baseUrl: string;
  realm: string;
  adminUsername: string;
  adminPassword: string;
  clientId: string;
  userPassword: string;
}

interface RequestOptions {
  method?: string;
  token?: string;
  body?: unknown;
}

const READ_ROLES = ["view-realm", "view-users", "view-clients"] as const;
const REGISTERED_REDIRECT = "http://127.0.0.1:8080/callback";

function options(env: NodeJS.ProcessEnv): SetupOptions {
  return {
    baseUrl: (env.ISSUERD_BASE_URL ?? "http://127.0.0.1:8080").replace(/\/$/, ""),
    realm: env.REALM ?? "mcp-demo",
    adminUsername: env.ADMIN_USERNAME ?? "admin",
    adminPassword: env.ADMIN_PASSWORD ?? "admin",
    clientId: env.MCP_CLIENT_ID ?? "mcp-admin-native",
    userPassword: env.MCP_PASSWORD ?? "Password123!",
  };
}

function object(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} was not an object`);
  }
  return value as JsonObject;
}

function objects(value: unknown, label: string): JsonObject[] {
  if (!Array.isArray(value)) throw new Error(`${label} was not an array`);
  return value.map((entry) => object(entry, label));
}

function id(value: JsonObject): string {
  if (typeof value.id !== "string" || !value.id) throw new Error("fixture response had no id");
  return value.id;
}

class AdminApi {
  constructor(private readonly config: SetupOptions) {}

  private async request(path: string, options: RequestOptions = {}): Promise<{ status: number; json: unknown }> {
    const response = await fetch(`${this.config.baseUrl}${path}`, {
      method: options.method ?? "GET",
      headers: {
        accept: "application/json",
        ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
        ...(options.body !== undefined ? { "content-type": "application/json" } : {}),
      },
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    });
    const text = await response.text();
    let json: unknown = null;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        throw new Error(`Admin API returned non-JSON for ${options.method ?? "GET"} ${path}`);
      }
    }
    return { status: response.status, json };
  }

  private async expect(path: string, options: RequestOptions = {}, statuses = [200]): Promise<unknown> {
    const response = await this.request(path, options);
    if (!statuses.includes(response.status)) {
      throw new Error(`Admin API ${options.method ?? "GET"} ${path} returned HTTP ${response.status}`);
    }
    return response.json;
  }

  async adminToken(): Promise<string> {
    const response = await fetch(`${this.config.baseUrl}/realms/master/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({
        grant_type: "password",
        client_id: "admin-cli",
        username: this.config.adminUsername,
        password: this.config.adminPassword,
      }),
    });
    if (!response.ok) throw new Error(`setup-only admin token request returned HTTP ${response.status}`);
    const body = object(await response.json(), "admin token response");
    if (typeof body.access_token !== "string" || !body.access_token) {
      throw new Error("setup-only admin token response had no access token");
    }
    return body.access_token;
  }

  async ensureRealm(token: string): Promise<void> {
    const path = `/admin/realms/${encodeURIComponent(this.config.realm)}`;
    const existing = await this.request(path, { token });
    if (existing.status === 200) return;
    if (existing.status !== 404) throw new Error(`realm lookup returned HTTP ${existing.status}`);
    await this.expect(
      "/admin/realms",
      {
        method: "POST",
        token,
        body: {
          realm: this.config.realm,
          display_name: "MCP read-only acceptance",
          enabled: true,
          ssl_required: "external",
          registrationEnabled: false,
          verifyEmailEnabled: false,
          resetPasswordAllowed: false,
        },
      },
      [201],
    );
  }

  async ensureRole(token: string, name: string): Promise<JsonObject> {
    const path = `/admin/realms/${encodeURIComponent(this.config.realm)}/roles/${encodeURIComponent(name)}`;
    const existing = await this.request(path, { token });
    if (existing.status === 200) return object(existing.json, "role");
    if (existing.status !== 404) throw new Error(`role lookup returned HTTP ${existing.status}`);
    const created = await this.expect(
      `/admin/realms/${encodeURIComponent(this.config.realm)}/roles`,
      { method: "POST", token, body: { name, description: `MCP acceptance ${name}` } },
      [201],
    );
    return object(created, "created role");
  }

  async ensureClient(token: string, clientId: string, native: boolean): Promise<JsonObject> {
    const list = objects(
      await this.expect(`/admin/realms/${encodeURIComponent(this.config.realm)}/clients?max=100`, { token }),
      "clients",
    );
    const existing = list.find((entry) => entry.client_id === clientId || entry.clientId === clientId);
    const desired: JsonObject = {
      client_id: clientId,
      name: native ? "MCP read-only native acceptance" : "MCP reporting fixture",
      description: native ? "Public native CLI; authorization code, PKCE, DPoP" : "Read-only list/get fixture",
      enabled: true,
      protocol: "openid-connect",
      public_client: true,
      bearer_only: false,
      redirect_uris: native ? [REGISTERED_REDIRECT] : [],
      web_origins: [],
      default_scopes: ["openid"],
      optional_scopes: native ? ["mcp:read"] : [],
      consent_required: false,
      full_scope_allowed: true,
      attributes: native ? { token_endpoint_auth_method: "none", application_type: "native" } : {},
    };
    if (!existing) {
      const created = await this.expect(
        `/admin/realms/${encodeURIComponent(this.config.realm)}/clients`,
        { method: "POST", token, body: desired },
        [201],
      );
      return object(created, "created client");
    }
    const uuid = id(existing);
    const current = object(
      await this.expect(
        `/admin/realms/${encodeURIComponent(this.config.realm)}/clients/${encodeURIComponent(uuid)}`,
        { token },
      ),
      "client",
    );
    const updated = await this.expect(
      `/admin/realms/${encodeURIComponent(this.config.realm)}/clients/${encodeURIComponent(uuid)}`,
      {
        method: "PUT",
        token,
        body: {
          ...current,
          ...desired,
          id: uuid,
          attributes: { ...object(current.attributes ?? {}, "client attributes"), ...object(desired.attributes, "desired attributes") },
        },
      },
      [200, 204],
    );
    return updated === null ? { ...current, ...desired, id: uuid } : object(updated, "updated client");
  }

  async ensureUser(
    token: string,
    username: string,
    roles: readonly string[],
    roleRepresentations: Map<string, JsonObject>,
  ): Promise<JsonObject> {
    const base = `/admin/realms/${encodeURIComponent(this.config.realm)}`;
    const users = objects(
      await this.expect(`${base}/users?username=${encodeURIComponent(username)}`, { token }),
      "users",
    );
    let user = users[0];
    if (!user) {
      user = object(
        await this.expect(
          `${base}/users`,
          {
            method: "POST",
            token,
            body: {
              username,
              email: `${username}@lab.issuerd.invalid`,
              first_name: username,
              last_name: "MCP Lab",
              enabled: true,
              email_verified: true,
              realm_roles: [...roles],
              credentials: [{ type: "password", value: this.config.userPassword, temporary: false }],
            },
          },
          [201],
        ),
        "created user",
      );
    }
    const userId = id(user);
    await this.expect(`${base}/users/${encodeURIComponent(userId)}/reset-password`, {
      method: "PUT",
      token,
      body: { type: "password", value: this.config.userPassword, temporary: false },
    }, [200, 204]);
    const assigned = objects(
      await this.expect(`${base}/users/${encodeURIComponent(userId)}/role-mappings/realm`, { token }),
      "assigned roles",
    );
    const assignedNames = new Set(assigned.map((role) => role.name));
    const missing = roles
      .filter((role) => !assignedNames.has(role))
      .map((role) => {
        const representation = roleRepresentations.get(role);
        if (!representation) throw new Error(`missing role fixture ${role}`);
        return representation;
      });
    if (missing.length) {
      await this.expect(`${base}/users/${encodeURIComponent(userId)}/role-mappings/realm`, {
        method: "POST",
        token,
        body: missing,
      }, [200, 204]);
    }
    return user;
  }
}

async function main(): Promise<void> {
  try {
    const config = options(process.env);
    const api = new AdminApi(config);
    const token = await api.adminToken();
    await api.ensureRealm(token);
    const roles = new Map<string, JsonObject>();
    for (const role of READ_ROLES) roles.set(role, await api.ensureRole(token, role));
    const native = await api.ensureClient(token, config.clientId, true);
    const reporting = await api.ensureClient(token, "mcp-reporting", false);
    const admin = await api.ensureUser(token, "mcp-admin", READ_ROLES, roles);
    const observer = await api.ensureUser(token, "mcp-observer", ["view-users"], roles);
    process.stdout.write(`${JSON.stringify({
      ok: true,
      issuer: `${config.baseUrl}/realms/${config.realm}`,
      realm: config.realm,
      nativeClient: {
        id: id(native),
        clientId: config.clientId,
        public: true,
        tokenEndpointAuthMethod: "none",
        applicationType: "native",
        optionalScopes: ["mcp:read"],
        redirectUris: [REGISTERED_REDIRECT],
      },
      fixtures: {
        users: [
          { id: id(admin), username: "mcp-admin", roles: READ_ROLES },
          { id: id(observer), username: "mcp-observer", roles: ["view-users"] },
        ],
        clients: [{ id: id(reporting), clientId: "mcp-reporting" }],
      },
    }, null, 2)}\n`);
  } catch (error) {
    const name = error instanceof Error ? error.name : "Error";
    const message = error instanceof Error ? error.message : "setup failed";
    process.stdout.write(`${JSON.stringify({ ok: false, error: { name, message } }, null, 2)}\n`);
    process.exitCode = 1;
  }
}

await main();
