import test from "node:test";
import assert from "node:assert/strict";
import { generateDpopKeyPair } from "@modelcontextprotocol/client";
import { IssuerStateStore, NativeOAuthProvider } from "../src/provider.js";

const issuerA = "https://a.example/realms/demo";
const issuerB = "https://b.example/realms/demo";

test("registration, tokens, state, discovery, and PKCE verifiers stay separated by issuer", () => {
  const store = new IssuerStateStore();
  store.register(issuerA, { client_id: "client-a", issuer: issuerA });
  store.register(issuerB, { client_id: "client-b", issuer: issuerB });
  store.saveTokens(issuerA, { access_token: "token-a", token_type: "DPoP", issuer: issuerA });
  store.saveTokens(issuerB, { access_token: "token-b", token_type: "DPoP", issuer: issuerB });
  store.saveDiscovery(issuerA, { authorizationServerUrl: issuerA });
  const stateA = store.newState();
  store.saveCodeVerifier("verifier-a");
  store.saveDiscovery(issuerB, { authorizationServerUrl: issuerB });
  const stateB = store.newState();
  store.saveCodeVerifier("verifier-b");

  assert.equal(store.client(issuerA)?.client_id, "client-a");
  assert.equal(store.client(issuerB)?.client_id, "client-b");
  assert.equal(store.tokens(issuerA)?.access_token, "token-a");
  assert.equal(store.tokens(issuerB)?.access_token, "token-b");
  assert.equal(store.tokens()?.access_token, "token-b");
  assert.notEqual(stateA, stateB);

  store.activate(issuerA);
  assert.equal(store.expectedState(), stateA);
  assert.equal(store.codeVerifier(), "verifier-a");
  assert.equal(store.discovery()?.authorizationServerUrl, issuerA);
  store.activate(issuerB);
  assert.equal(store.expectedState(), stateB);
  assert.equal(store.codeVerifier(), "verifier-b");
  assert.equal(store.discovery()?.authorizationServerUrl, issuerB);
  assert.throws(() => store.register(issuerA, { client_id: "wrong", issuer: issuerB }));
});

test("pre-registered public client state is issuer-bound and carries no secret", () => {
  const provider = new NativeOAuthProvider({
    issuer: issuerA,
    resource: `${issuerA}/mcp`,
    clientId: "native-a",
    redirectUri: "http://127.0.0.1:49152/callback",
  });
  const registration = provider.clientInformation({ issuer: issuerA });
  assert.equal(registration.client_id, "native-a");
  assert.equal(
    "token_endpoint_auth_method" in registration ? registration.token_endpoint_auth_method : undefined,
    "none",
  );
  assert.equal(registration.issuer, issuerA);
  assert.equal("client_secret" in registration, false);
  assert.throws(() => provider.clientInformation({ issuer: issuerB }));
  assert.equal(provider.clientMetadata.application_type, "native");
  assert.deepEqual(provider.clientMetadata.grant_types, ["authorization_code"]);
});

test("one provider reuses one SDK DPoP session with non-extractable ES256 keys", async () => {
  const provider = new NativeOAuthProvider({
    issuer: issuerA,
    resource: `${issuerA}/mcp`,
    clientId: "native-a",
    redirectUri: "http://127.0.0.1:49152/callback",
  });
  const first = await provider.dpop();
  const second = await provider.dpop();
  assert.equal(first, second);
  assert.equal(first.alg, "ES256");
  const generated = await generateDpopKeyPair({ alg: "ES256" });
  assert.equal(generated.privateKey.extractable, false);
});
