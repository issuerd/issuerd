import test from "node:test";
import assert from "node:assert/strict";
import {
  validateStepUpChallenge,
  validateStepUpToken,
  type ProtocolResponse,
} from "../src/ciba.js";

const endpoint = "https://issuer.example/realms/demo/protocol/openid-connect/ext/ciba/auth";
const resource = "https://issuer.example/realms/demo/mcp";

function response(status: number, body: unknown): ProtocolResponse {
  return { status, headers: new Headers(), body };
}

test("step-up challenge requires the exact endpoint, resource, scope, and bounded expiry", () => {
  const challenge = validateStepUpChallenge(response(401, {
    error: "step_up_required",
    operation_id: "operation",
    binding_message: "Delete the exact user",
    backchannel_authentication_endpoint: endpoint,
    resource,
    required_scope: "openid mcp:step_up",
    expires_in: 300,
  }), endpoint, resource);
  assert.equal(challenge.operationId, "operation");
  assert.equal(challenge.requiredScope, "openid mcp:step_up");

  for (const body of [
    { error: "access_denied" },
    {
      error: "step_up_required",
      operation_id: "operation",
      binding_message: "Delete the exact user",
      backchannel_authentication_endpoint: "https://attacker.example/ciba",
      resource,
      required_scope: "openid mcp:step_up",
      expires_in: 300,
    },
    {
      error: "step_up_required",
      operation_id: "operation",
      binding_message: "Delete the exact user",
      backchannel_authentication_endpoint: endpoint,
      resource,
      required_scope: "openid mcp:write",
      expires_in: 300,
    },
  ]) {
    assert.throws(() => validateStepUpChallenge(response(401, body), endpoint, resource));
  }
});

test("step-up token is single-purpose, DPoP-bound, short-lived, and has no refresh", () => {
  const token = validateStepUpToken({
    access_token: "not-logged",
    token_type: "DPoP",
    scope: "openid mcp:step_up",
    expires_in: 120,
  });
  assert.equal(token.expiresIn, 120);
  for (const body of [
    { access_token: "not-logged", token_type: "Bearer", scope: "openid mcp:step_up", expires_in: 120 },
    { access_token: "not-logged", token_type: "DPoP", scope: "openid mcp:write", expires_in: 120 },
    {
      access_token: "not-logged",
      token_type: "DPoP",
      scope: "openid mcp:step_up",
      expires_in: 120,
      refresh_token: "forbidden",
    },
    { access_token: "not-logged", token_type: "DPoP", scope: "openid mcp:step_up", expires_in: 121 },
  ]) {
    assert.throws(() => validateStepUpToken(body));
  }
});
