export interface AuthorizationExpectation {
  issuer: string;
  state: string;
  redirectUri: string;
}

export interface AuthorizationEvidence {
  kind: "success" | "error";
  expectedIssuer: string;
  returnedIssuer: string;
  issuerMatched: true;
  stateMatched: true;
  redirectMatched: true;
  error?: string;
}

export class CallbackValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CallbackValidationError";
  }
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
}

export function matchesNativeRedirect(registeredRaw: string, requestedRaw: string): boolean {
  if (registeredRaw === requestedRaw && !registeredRaw.includes("*")) return true;
  if (registeredRaw.includes("*") || requestedRaw.includes("*")) return false;
  let registered: URL;
  let requested: URL;
  try {
    registered = new URL(registeredRaw);
    requested = new URL(requestedRaw);
  } catch {
    return false;
  }
  if (
    registered.protocol !== "http:" ||
    requested.protocol !== "http:" ||
    !isLoopbackHostname(registered.hostname) ||
    registered.hostname !== requested.hostname
  ) {
    return false;
  }
  registered.port = "";
  requested.port = "";
  return registered.href === requested.href;
}

export function validateCallbackRedirect(expectedRaw: string, actual: URL): void {
  const expected = new URL(expectedRaw);
  const actualBase = `${actual.origin}${actual.pathname}`;
  const expectedBase = `${expected.origin}${expected.pathname}`;
  if (
    expected.protocol !== "http:" ||
    !isLoopbackHostname(expected.hostname) ||
    expected.search ||
    expected.hash ||
    actualBase !== expectedBase
  ) {
    throw new CallbackValidationError("authorization response redirect did not match the active loopback listener");
  }
}

function one(params: URLSearchParams, name: string): string {
  const values = params.getAll(name);
  if (values.length !== 1 || !values[0]) {
    throw new CallbackValidationError(`authorization response must contain exactly one nonempty ${name}`);
  }
  return values[0];
}

export function validateAuthorizationCallback(
  callback: URL,
  expected: AuthorizationExpectation,
): AuthorizationEvidence {
  validateCallbackRedirect(expected.redirectUri, callback);
  const returnedIssuer = one(callback.searchParams, "iss");
  if (returnedIssuer !== expected.issuer) {
    throw new CallbackValidationError("authorization response issuer mismatch");
  }
  const returnedState = one(callback.searchParams, "state");
  if (returnedState !== expected.state) {
    throw new CallbackValidationError("authorization response state mismatch");
  }
  const codes = callback.searchParams.getAll("code");
  const errors = callback.searchParams.getAll("error");
  if (codes.length === 1 && codes[0] && errors.length === 0) {
    return {
      kind: "success",
      expectedIssuer: expected.issuer,
      returnedIssuer,
      issuerMatched: true,
      stateMatched: true,
      redirectMatched: true,
    };
  }
  if (errors.length === 1 && errors[0] && codes.length === 0) {
    return {
      kind: "error",
      expectedIssuer: expected.issuer,
      returnedIssuer,
      issuerMatched: true,
      stateMatched: true,
      redirectMatched: true,
      error: errors[0],
    };
  }
  throw new CallbackValidationError("authorization response must contain exactly one code or error");
}

export function requireSingleParameter(
  params: URLSearchParams,
  name: string,
  expected?: string,
): string {
  const value = one(params, name);
  if (expected !== undefined && value !== expected) {
    throw new CallbackValidationError(`authorization request parameter mismatch: ${name}`);
  }
  return value;
}
