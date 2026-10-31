import type { DpopSession, FetchLike } from "@modelcontextprotocol/client";
import { AcceptanceError } from "./errors.js";

export type JsonObject = Record<string, unknown>;

export interface ProtocolResponse {
  status: number;
  headers: Headers;
  body: unknown;
}

export interface StepUpChallenge {
  operationId: string;
  bindingMessage: string;
  backchannelAuthenticationEndpoint: string;
  resource: string;
  requiredScope: "openid mcp:step_up";
  expiresIn: number;
}

export interface StepUpToken {
  accessToken: string;
  expiresIn: number;
}

export function object(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AcceptanceError(`${label} must be an object`);
  }
  return value as JsonObject;
}

export function objects(value: unknown, label: string): JsonObject[] {
  if (!Array.isArray(value)) throw new AcceptanceError(`${label} must be an array`);
  return value.map((entry) => object(entry, label));
}

export function nonempty(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) throw new AcceptanceError(`${label} must be nonempty`);
  return value;
}

function errorCode(response: ProtocolResponse): string | undefined {
  if (typeof response.body !== "object" || response.body === null || !("error" in response.body)) {
    return undefined;
  }
  return typeof response.body.error === "string" ? response.body.error : undefined;
}

export class ConfidentialProtocolClient {
  private requestId = 0;

  constructor(
    private readonly options: {
      session: DpopSession;
      clientId: string;
      clientSecret: string;
      fetchFn: FetchLike;
    },
  ) {}

  async mcp(
    resource: string,
    accessToken: string,
    tool: string,
    arguments_: Record<string, unknown>,
  ): Promise<ProtocolResponse> {
    this.requestId += 1;
    return this.request(resource, {
      method: "POST",
      headers: {
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
        "mcp-protocol-version": "2025-11-25",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: this.requestId,
        method: "tools/call",
        params: { name: tool, arguments: arguments_ },
      }),
    }, accessToken);
  }

  async initiateCiba(
    endpoint: string,
    challenge: StepUpChallenge,
    username: string,
  ): Promise<{ authReqId: string; approvalUrl: string; interval: number }> {
    const response = await this.form(endpoint, new URLSearchParams({
      scope: "openid mcp:step_up",
      login_hint: username,
      binding_message: challenge.bindingMessage,
      operation_id: challenge.operationId,
      resource: challenge.resource,
    }), false);
    if (response.status !== 200) {
      throw new AcceptanceError(`CIBA initiation failed: ${errorCode(response) ?? `HTTP ${response.status}`}`);
    }
    const body = object(response.body, "CIBA initiation response");
    const authReqId = nonempty(body.auth_req_id, "auth_req_id");
    const approvalUrl = nonempty(body.approval_url, "approval_url");
    const interval = typeof body.interval === "number" && body.interval >= 1 ? body.interval : 5;
    if (!Number.isSafeInteger(body.expires_in) || Number(body.expires_in) <= 0) {
      throw new AcceptanceError("CIBA initiation returned an invalid expiry");
    }
    return { authReqId, approvalUrl, interval };
  }

  async pollCiba(
    tokenEndpoint: string,
    authReqId: string,
    resource: string,
    interval: number,
    timeoutMs = 90_000,
  ): Promise<StepUpToken> {
    const deadline = Date.now() + timeoutMs;
    let pollingInterval = Math.max(5, interval);
    for (;;) {
      const response = await this.form(tokenEndpoint, new URLSearchParams({
        grant_type: "urn:openid:params:grant-type:ciba",
        auth_req_id: authReqId,
        resource,
      }), true);
      if (response.status === 200) return validateStepUpToken(response.body);
      const code = errorCode(response);
      if (code === "authorization_pending" || code === "slow_down") {
        if (code === "slow_down") pollingInterval += 5;
        if (Date.now() + pollingInterval * 1_000 >= deadline) {
          throw new AcceptanceError("CIBA approval polling timed out");
        }
        await new Promise((resolve) => setTimeout(resolve, pollingInterval * 1_000));
        continue;
      }
      if (response.status === 503) {
        if (Date.now() + 5_000 >= deadline) throw new AcceptanceError("CIBA polling remained unavailable");
        await new Promise((resolve) => setTimeout(resolve, 5_000));
        continue;
      }
      throw new AcceptanceError(`CIBA polling failed: ${code ?? `HTTP ${response.status}`}`);
    }
  }

  async pollCibaReplay(tokenEndpoint: string, authReqId: string, resource: string): Promise<string> {
    const response = await this.form(tokenEndpoint, new URLSearchParams({
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: authReqId,
      resource,
    }), true);
    return errorCode(response) ?? `HTTP ${response.status}`;
  }

  private form(endpoint: string, body: URLSearchParams, dpop: boolean): Promise<ProtocolResponse> {
    if (!dpop) {
      body.set("client_id", this.options.clientId);
      body.set("client_secret", this.options.clientSecret);
    }
    return this.request(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        ...(dpop
          ? { authorization: `Basic ${Buffer.from(`${this.options.clientId}:${this.options.clientSecret}`).toString("base64")}` }
          : {}),
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
    }, dpop ? "" : undefined);
  }

  private async request(
    target: string,
    init: RequestInit,
    accessToken: string | undefined,
  ): Promise<ProtocolResponse> {
    const url = new URL(target);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const headers = new Headers(init.headers);
      if (accessToken !== undefined) {
        headers.set("dpop", await this.options.session.buildProof({
          htm: "POST",
          htu: url,
          ...(accessToken ? { accessToken } : {}),
        }));
        if (accessToken) headers.set("authorization", `DPoP ${accessToken}`);
      }
      const response = await this.options.fetchFn(url, { ...init, headers });
      this.options.session.observeNonce(response, url);
      const text = await response.text();
      let body: unknown = null;
      if (text) {
        try {
          body = JSON.parse(text);
        } catch {
          body = { error: "non_json_response" };
        }
      }
      const result = { status: response.status, headers: response.headers, body };
      const nonceChallenge = response.headers.get("www-authenticate")?.includes("use_dpop_nonce") === true ||
        errorCode(result) === "use_dpop_nonce";
      if (attempt === 0 && response.status === 401 && nonceChallenge && accessToken !== undefined) {
        continue;
      }
      return result;
    }
    throw new AcceptanceError("DPoP nonce retry did not terminate");
  }
}

export function validateStepUpChallenge(
  response: ProtocolResponse,
  expectedEndpoint: string,
  expectedResource: string,
): StepUpChallenge {
  if (response.status !== 401 || errorCode(response) !== "step_up_required") {
    throw new AcceptanceError("strict operation did not return the expected step-up challenge");
  }
  const body = object(response.body, "step-up challenge");
  const endpoint = nonempty(body.backchannel_authentication_endpoint, "backchannel endpoint");
  const resource = nonempty(body.resource, "challenge resource");
  if (endpoint !== expectedEndpoint || resource !== expectedResource) {
    throw new AcceptanceError("step-up challenge changed the CIBA endpoint or canonical resource");
  }
  if (body.required_scope !== "openid mcp:step_up") {
    throw new AcceptanceError("step-up challenge did not require the single-purpose scope");
  }
  if (!Number.isSafeInteger(body.expires_in) || Number(body.expires_in) <= 0 || Number(body.expires_in) > 300) {
    throw new AcceptanceError("step-up challenge returned an invalid operation expiry");
  }
  return {
    operationId: nonempty(body.operation_id, "operation_id"),
    bindingMessage: nonempty(body.binding_message, "binding_message"),
    backchannelAuthenticationEndpoint: endpoint,
    resource,
    requiredScope: "openid mcp:step_up",
    expiresIn: Number(body.expires_in),
  };
}

export function validateStepUpToken(value: unknown): StepUpToken {
  const body = object(value, "CIBA token response");
  if (body.token_type !== "DPoP" || body.scope !== "openid mcp:step_up") {
    throw new AcceptanceError("CIBA did not issue the exact single-purpose DPoP token");
  }
  if (body.refresh_token !== undefined && body.refresh_token !== null) {
    throw new AcceptanceError("CIBA step-up response contained a refresh token");
  }
  if (!Number.isSafeInteger(body.expires_in) || Number(body.expires_in) <= 0 || Number(body.expires_in) > 120) {
    throw new AcceptanceError("CIBA step-up token exceeded its two-minute grant bound");
  }
  return {
    accessToken: nonempty(body.access_token, "step-up access token"),
    expiresIn: Number(body.expires_in),
  };
}
