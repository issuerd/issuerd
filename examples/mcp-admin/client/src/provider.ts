import { randomBytes } from "node:crypto";
import {
  DpopSession,
  type OAuthClientInformationContext,
  type OAuthClientMetadata,
  type OAuthClientProvider,
  type OAuthDiscoveryState,
  type StoredOAuthClientInformation,
  type StoredOAuthTokens,
} from "@modelcontextprotocol/client";
import { MCP_SCOPE } from "./config.js";
import {
  validateAuthorizationCallback,
  type AuthorizationEvidence,
} from "./validation.js";

interface ProviderOptions {
  issuer: string;
  resource: string;
  clientId: string;
  redirectUri: string;
  clientSecret?: string;
  scope?: string;
}

export class IssuerStateStore {
  private readonly registrations = new Map<string, StoredOAuthClientInformation>();
  private readonly tokenSets = new Map<string, StoredOAuthTokens>();
  private readonly discoveries = new Map<string, OAuthDiscoveryState>();
  private readonly states = new Map<string, string>();
  private readonly verifiers = new Map<string, string>();
  private latestTokenIssuer: string | undefined;
  private activeIssuer: string | undefined;

  client(issuer: string): StoredOAuthClientInformation | undefined {
    return this.registrations.get(issuer);
  }

  register(issuer: string, value: StoredOAuthClientInformation): void {
    if (value.issuer !== issuer) throw new Error("client registration issuer binding mismatch");
    this.registrations.set(issuer, value);
  }

  tokens(issuer?: string): StoredOAuthTokens | undefined {
    return issuer === undefined
      ? this.latestTokenIssuer === undefined
        ? undefined
        : this.tokenSets.get(this.latestTokenIssuer)
      : this.tokenSets.get(issuer);
  }

  saveTokens(issuer: string, value: StoredOAuthTokens): void {
    if (value.issuer !== issuer) throw new Error("token issuer binding mismatch");
    this.tokenSets.set(issuer, value);
    this.latestTokenIssuer = issuer;
  }

  saveDiscovery(issuer: string, value: OAuthDiscoveryState): void {
    this.discoveries.set(issuer, value);
    this.activeIssuer = issuer;
  }

  discovery(): OAuthDiscoveryState | undefined {
    return this.activeIssuer === undefined ? undefined : this.discoveries.get(this.activeIssuer);
  }

  activate(issuer: string): void {
    this.activeIssuer = issuer;
  }

  newState(): string {
    if (this.activeIssuer === undefined) throw new Error("no validated issuer for OAuth state");
    const state = randomBytes(32).toString("base64url");
    this.states.set(this.activeIssuer, state);
    return state;
  }

  expectedState(): string {
    if (this.activeIssuer === undefined) throw new Error("no validated issuer for OAuth state");
    const state = this.states.get(this.activeIssuer);
    if (!state) throw new Error("OAuth state was not initialized");
    return state;
  }

  saveCodeVerifier(verifier: string): void {
    if (this.activeIssuer === undefined) throw new Error("no validated issuer for PKCE state");
    this.verifiers.set(this.activeIssuer, verifier);
  }

  codeVerifier(): string {
    if (this.activeIssuer === undefined) throw new Error("no validated issuer for PKCE state");
    const verifier = this.verifiers.get(this.activeIssuer);
    if (!verifier) throw new Error("PKCE verifier was not initialized");
    return verifier;
  }
}

export class NativeOAuthProvider implements OAuthClientProvider {
  readonly store = new IssuerStateStore();
  private readonly session = DpopSession.create({ alg: "ES256" });
  private authorizationUrl: string | undefined;

  constructor(private readonly options: ProviderOptions) {}

  get redirectUrl(): string {
    return this.options.redirectUri;
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      redirect_uris: [this.options.redirectUri],
      token_endpoint_auth_method: this.options.clientSecret === undefined ? "none" : "client_secret_basic",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      application_type: "native",
      client_name: this.options.clientSecret === undefined
        ? "Issuerd MCP read-only acceptance CLI"
        : "Issuerd MCP confidential step-up acceptance CLI",
      scope: this.options.scope ?? MCP_SCOPE,
    };
  }

  clientInformation(ctx?: OAuthClientInformationContext): StoredOAuthClientInformation {
    const issuer = this.validatedIssuer(ctx?.issuer);
    this.store.activate(issuer);
    const existing = this.store.client(issuer);
    if (existing) return existing;
    const registration: StoredOAuthClientInformation = {
      client_id: this.options.clientId,
      ...(this.options.clientSecret === undefined ? {} : { client_secret: this.options.clientSecret }),
      token_endpoint_auth_method: this.options.clientSecret === undefined ? "none" : "client_secret_basic",
      issuer,
    };
    this.store.register(issuer, registration);
    return registration;
  }

  tokens(ctx?: OAuthClientInformationContext): StoredOAuthTokens | undefined {
    return ctx === undefined ? this.store.tokens() : this.store.tokens(this.validatedIssuer(ctx.issuer));
  }

  saveTokens(tokens: StoredOAuthTokens, ctx?: OAuthClientInformationContext): void {
    const issuer = this.validatedIssuer(ctx?.issuer ?? tokens.issuer);
    if (tokens.token_type.toLowerCase() !== "dpop") {
      throw new Error("authorization server did not issue a DPoP-bound access token");
    }
    const granted = new Set((tokens.scope ?? "").split(/\s+/).filter(Boolean));
    const expected = new Set((this.options.scope ?? MCP_SCOPE).split(" "));
    if (granted.size !== expected.size || ![...expected].every((scope) => granted.has(scope))) {
      throw new Error("authorization server did not grant the exact requested scope set");
    }
    this.store.saveTokens(issuer, tokens);
  }

  redirectToAuthorization(authorizationUrl: URL): void {
    this.authorizationUrl = authorizationUrl.href;
  }

  takeAuthorizationUrl(): string {
    const value = this.authorizationUrl;
    this.authorizationUrl = undefined;
    if (!value) throw new Error("SDK did not produce an authorization URL");
    return value;
  }

  saveCodeVerifier(codeVerifier: string): void {
    if (!codeVerifier) throw new Error("empty PKCE verifier");
    this.store.saveCodeVerifier(codeVerifier);
  }

  codeVerifier(): string {
    return this.store.codeVerifier();
  }

  dpop(): Promise<DpopSession> {
    return this.session;
  }

  state(): string {
    return this.store.newState();
  }

  saveDiscoveryState(state: OAuthDiscoveryState): void {
    const metadata = state.authorizationServerMetadata;
    if (!metadata) throw new Error("authorization server metadata is required");
    const issuer = this.validatedIssuer(metadata.issuer);
    if (
      state.resourceMetadata?.resource !== this.options.resource ||
      state.resourceMetadata.dpop_bound_access_tokens_required !== true
    ) {
      throw new Error("protected resource metadata does not require DPoP for the canonical MCP resource");
    }
    if (metadata.authorization_response_iss_parameter_supported !== true) {
      throw new Error("authorization server does not advertise RFC 9207 issuer responses");
    }
    const authenticationMethod = this.options.clientSecret === undefined ? "none" : "client_secret_basic";
    if (!metadata.token_endpoint_auth_methods_supported?.includes(authenticationMethod)) {
      throw new Error("authorization server does not advertise the configured client authentication method");
    }
    this.store.saveDiscovery(issuer, state);
  }

  discoveryState(): OAuthDiscoveryState | undefined {
    return this.store.discovery();
  }

  async validateResourceURL(serverUrl: string | URL, resource?: string): Promise<URL> {
    if (String(serverUrl) !== this.options.resource || resource !== this.options.resource) {
      throw new Error("protected resource is not the exact canonical MCP URL");
    }
    return new URL(this.options.resource);
  }

  expectedIssuer(): string {
    return this.validatedIssuer(this.store.discovery()?.authorizationServerMetadata?.issuer);
  }

  validateCallback(callback: URL): AuthorizationEvidence {
    return validateAuthorizationCallback(callback, {
      issuer: this.expectedIssuer(),
      state: this.store.expectedState(),
      redirectUri: this.options.redirectUri,
    });
  }

  async dpopAlgorithm(): Promise<string> {
    return (await this.session).alg;
  }

  private validatedIssuer(issuer: string | undefined): string {
    if (!issuer || issuer !== this.options.issuer) {
      throw new Error("validated authorization server issuer mismatch");
    }
    return issuer;
  }
}
