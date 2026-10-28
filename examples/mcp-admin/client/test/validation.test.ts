import test from "node:test";
import assert from "node:assert/strict";
import {
  CallbackValidationError,
  matchesNativeRedirect,
  validateAuthorizationCallback,
} from "../src/validation.js";
import { parseRealmIssuer, TOOL_NAMES } from "../src/config.js";

test("acceptance inventory is ten unique tools in deterministic order", () => {
  assert.equal(TOOL_NAMES.length, 10);
  assert.equal(new Set(TOOL_NAMES).size, TOOL_NAMES.length);
  assert.deepEqual([...TOOL_NAMES], [...TOOL_NAMES].sort());
  for (const name of ["groups_get", "groups_list", "groups_members", "roles_get", "roles_list"]) {
    assert.ok(TOOL_NAMES.includes(name as (typeof TOOL_NAMES)[number]));
  }
});

const expected = {
  issuer: "http://127.0.0.1:8080/realms/mcp-demo",
  state: "state-that-must-not-leak",
  redirectUri: "http://127.0.0.1:49152/callback",
};

function callback(params: Record<string, string>, redirect = expected.redirectUri): URL {
  const url = new URL(redirect);
  for (const [name, value] of Object.entries(params)) url.searchParams.append(name, value);
  return url;
}

test("native MCP redirects allow only the literal loopback ephemeral-port exception", () => {
  assert.equal(matchesNativeRedirect("http://127.0.0.1:8080/callback", expected.redirectUri), true);
  assert.equal(matchesNativeRedirect("http://[::1]:8080/callback", "http://[::1]:49152/callback"), true);
  assert.equal(matchesNativeRedirect("https://app.example/cb", "https://app.example/cb"), true);
  for (const requested of [
    "http://127.0.0.1:49152/other",
    "http://127.0.0.2:49152/callback",
    "http://localhost:49152/callback",
    "https://127.0.0.1:49152/callback",
  ]) {
    assert.equal(matchesNativeRedirect("http://127.0.0.1:8080/callback", requested), false);
  }
  assert.equal(
    matchesNativeRedirect("http://127.0.0.1:8080/callback?x=1", "http://127.0.0.1:49152/callback?x=2"),
    false,
  );
  assert.equal(matchesNativeRedirect("http://127.0.0.1:8080/*", expected.redirectUri), false);
});

test("success authorization response records exact issuer, state, and redirect matches", () => {
  const result = validateAuthorizationCallback(
    callback({ code: "code-not-logged", state: expected.state, iss: expected.issuer }),
    expected,
  );
  assert.deepEqual(result, {
    kind: "success",
    expectedIssuer: expected.issuer,
    returnedIssuer: expected.issuer,
    issuerMatched: true,
    stateMatched: true,
    redirectMatched: true,
  });
  assert.equal(JSON.stringify(result).includes(expected.state), false);
  assert.equal(JSON.stringify(result).includes("code-not-logged"), false);
});

test("error authorization response is validated before its error is returned", () => {
  const result = validateAuthorizationCallback(
    callback({ error: "login_required", state: expected.state, iss: expected.issuer }),
    expected,
  );
  assert.equal(result.kind, "error");
  assert.equal(result.error, "login_required");
  assert.equal(result.returnedIssuer, expected.issuer);
});

test("issuer, state, duplicate parameters, and redirect mismatches are rejected", () => {
  const cases = [
    callback({ code: "c", state: expected.state, iss: `${expected.issuer}/` }),
    callback({ code: "c", state: "wrong", iss: expected.issuer }),
    callback({ code: "c", state: expected.state }),
    callback({ code: "c", state: expected.state, iss: expected.issuer }, "http://127.0.0.1:49152/other"),
    callback({ code: "c", state: expected.state, iss: expected.issuer }, "http://localhost:49152/callback"),
  ];
  for (const url of cases) {
    assert.throws(() => validateAuthorizationCallback(url, expected), CallbackValidationError);
  }
  const duplicate = callback({ code: "c", state: expected.state, iss: expected.issuer });
  duplicate.searchParams.append("iss", expected.issuer);
  assert.throws(() => validateAuthorizationCallback(duplicate, expected), CallbackValidationError);
});

test("canonical realm issuer parsing preserves path prefixes and rejects aliases", () => {
  assert.deepEqual(parseRealmIssuer("http://127.0.0.1:9000/prefix/realms/demo"), {
    issuer: "http://127.0.0.1:9000/prefix/realms/demo",
    baseUrl: "http://127.0.0.1:9000/prefix",
    realm: "demo",
    resource: "http://127.0.0.1:9000/prefix/realms/demo/mcp",
  });
  assert.throws(() => parseRealmIssuer("http://127.0.0.1:9000/realms/demo/"));
  assert.throws(() => parseRealmIssuer("http://127.0.0.1:9000/realms/demo?x=1"));
});
