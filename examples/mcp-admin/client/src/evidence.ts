import type { FetchLike } from "@modelcontextprotocol/client";

export interface DpopEvidence {
  algorithm: string;
  privateKeyExtractable: false;
  tokenType: "DPoP";
  tokenRequests: number;
  tokenEndpointProofs: number;
  resourceRequests: number;
  resourceRequestProofs: number;
  resourceDpopSchemeRequests: number;
  tokenNonceChallenges: number;
  resourceNonceChallenges: number;
  tokenNonceRetries: number;
  resourceNonceRetries: number;
  canonicalResourceOnEveryTokenRequest: boolean;
  publicClientAuthenticationNone: boolean;
  modernCompleteResults: number;
  modernNonCompleteResults: number;
  serverEnforcedProofClaims: ["htm", "htu", "ath", "jti", "nonce"];
}

export class ProtocolEvidence {
  tokenRequests = 0;
  tokenEndpointProofs = 0;
  resourceRequests = 0;
  resourceRequestProofs = 0;
  resourceDpopSchemeRequests = 0;
  tokenNonceChallenges = 0;
  resourceNonceChallenges = 0;
  tokenNonceRetries = 0;
  resourceNonceRetries = 0;
  modernCompleteResults = 0;
  modernNonCompleteResults = 0;
  private tokenResourceExact = true;
  private publicAuthNone = true;
  private tokenChallengePending = false;
  private resourceChallengePending = false;

  constructor(private readonly resource: string) {}

  readonly fetch: FetchLike = async (input, init) => {
    const request = input instanceof Request ? input : undefined;
    const url = new URL(request?.url ?? String(input));
    const headers = new Headers(request?.headers);
    new Headers(init?.headers).forEach((value, key) => headers.set(key, value));
    const base = `${url.origin}${url.pathname}`;
    const isToken = url.pathname.endsWith("/protocol/openid-connect/token");
    const isResource = base === this.resource;
    const hasProof = headers.has("dpop");

    if (isToken) {
      this.tokenRequests += 1;
      if (hasProof) this.tokenEndpointProofs += 1;
      if (this.tokenChallengePending) {
        this.tokenNonceRetries += 1;
        this.tokenChallengePending = false;
      }
      if (!(init?.body instanceof URLSearchParams)) {
        this.tokenResourceExact = false;
        this.publicAuthNone = false;
      } else {
        const body = init.body;
        if (body.getAll("resource").length !== 1 || body.get("resource") !== this.resource) {
          this.tokenResourceExact = false;
        }
        if (
          headers.has("authorization") ||
          body.has("client_secret") ||
          body.getAll("client_id").length !== 1
        ) {
          this.publicAuthNone = false;
        }
      }
    }
    if (isResource) {
      this.resourceRequests += 1;
      if (hasProof) this.resourceRequestProofs += 1;
      if (headers.get("authorization")?.split(" ", 1)[0]?.toLowerCase() === "dpop") {
        this.resourceDpopSchemeRequests += 1;
      }
      if (this.resourceChallengePending) {
        this.resourceNonceRetries += 1;
        this.resourceChallengePending = false;
      }
    }

    const response = await fetch(input, init);
    const nonceChallenge =
      response.headers.has("dpop-nonce") && (response.status === 400 || response.status === 401);
    if (isToken && nonceChallenge) {
      this.tokenNonceChallenges += 1;
      this.tokenChallengePending = true;
    }
    if (isResource && nonceChallenge) {
      this.resourceNonceChallenges += 1;
      this.resourceChallengePending = true;
    }
    if (
      isResource &&
      headers.get("mcp-protocol-version") === "2026-07-28" &&
      response.ok &&
      response.headers.get("content-type")?.includes("application/json")
    ) {
      const wire: unknown = await response.clone().json().catch(() => undefined);
      const result =
        typeof wire === "object" && wire !== null && "result" in wire ? wire.result : undefined;
      const resultType =
        typeof result === "object" && result !== null && "resultType" in result
          ? result.resultType
          : undefined;
      if (resultType === "complete") this.modernCompleteResults += 1;
      else this.modernNonCompleteResults += 1;
    }
    return response;
  };

  dpop(algorithm: string): DpopEvidence {
    return {
      algorithm,
      privateKeyExtractable: false,
      tokenType: "DPoP",
      tokenRequests: this.tokenRequests,
      tokenEndpointProofs: this.tokenEndpointProofs,
      resourceRequests: this.resourceRequests,
      resourceRequestProofs: this.resourceRequestProofs,
      resourceDpopSchemeRequests: this.resourceDpopSchemeRequests,
      tokenNonceChallenges: this.tokenNonceChallenges,
      resourceNonceChallenges: this.resourceNonceChallenges,
      tokenNonceRetries: this.tokenNonceRetries,
      resourceNonceRetries: this.resourceNonceRetries,
      canonicalResourceOnEveryTokenRequest: this.tokenResourceExact,
      publicClientAuthenticationNone: this.publicAuthNone,
      modernCompleteResults: this.modernCompleteResults,
      modernNonCompleteResults: this.modernNonCompleteResults,
      serverEnforcedProofClaims: ["htm", "htu", "ath", "jti", "nonce"],
    };
  }

  assertComplete(expectedModernResults: number): void {
    if (
      this.tokenRequests < 2 ||
      this.tokenEndpointProofs !== this.tokenRequests ||
      this.tokenNonceChallenges < 1 ||
      this.tokenNonceRetries < 1 ||
      this.resourceRequests < 1 ||
      this.resourceRequestProofs !== this.resourceRequests ||
      this.resourceDpopSchemeRequests !== this.resourceRequests ||
      this.modernCompleteResults !== expectedModernResults ||
      this.modernNonCompleteResults !== 0 ||
      !this.tokenResourceExact ||
      !this.publicAuthNone
    ) {
      throw new Error("incomplete DPoP, nonce, resource, public-client, or modern-result evidence");
    }
  }
}
