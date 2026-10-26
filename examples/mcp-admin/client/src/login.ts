import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { FetchLike } from "@modelcontextprotocol/client";
import type { NativeOAuthProvider } from "./provider.js";
import type { AuthorizationEvidence } from "./validation.js";

export class LoopbackCallback {
  private constructor(
    private readonly server: Server,
    readonly redirectUri: string,
    private readonly callback: Promise<URL>,
  ) {}

  static async start(): Promise<LoopbackCallback> {
    let base = "http://127.0.0.1";
    let resolveCallback: (url: URL) => void = () => undefined;
    const callback = new Promise<URL>((resolve) => {
      resolveCallback = resolve;
    });
    const server = createServer((request, response) => {
      const url = new URL(request.url ?? "/", base);
      if (request.method !== "GET" || url.pathname !== "/callback") {
        response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        response.end("Not found\n");
        return;
      }
      response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      response.end("Authorization response received. Return to the CLI.\n");
      resolveCallback(url);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    const address = server.address() as AddressInfo;
    base = `http://127.0.0.1:${address.port}`;
    return new LoopbackCallback(server, `${base}/callback`, callback);
  }

  async waitForCallback(timeoutMs: number): Promise<URL> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        this.callback,
        new Promise<URL>((_, reject) => {
          timer = setTimeout(() => reject(new Error("loopback authorization timed out")), timeoutMs);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async close(): Promise<void> {
    if (!this.server.listening) return;
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

function cookies(response: Response): string[] {
  return response.headers
    .getSetCookie()
    .map((value) => value.split(";", 1)[0])
    .filter((value): value is string => Boolean(value?.includes("=")));
}

function redirectLocation(response: Response, base: URL): URL {
  const location = response.headers.get("location");
  if (response.status !== 303 || !location) {
    throw new Error(`expected an authorization redirect, received HTTP ${response.status}`);
  }
  return new URL(location, base);
}

export async function probeErrorAuthorizationResponse(
  authorizationUrl: URL,
  provider: NativeOAuthProvider,
  fetchFn: FetchLike,
): Promise<AuthorizationEvidence> {
  const probe = new URL(authorizationUrl);
  probe.searchParams.set("prompt", "none");
  const response = await fetchFn(probe, { redirect: "manual" });
  const callback = redirectLocation(response, probe);
  const evidence = provider.validateCallback(callback);
  if (evidence.kind !== "error" || evidence.error !== "login_required") {
    throw new Error("prompt=none did not produce the expected login_required response");
  }
  return evidence;
}

export async function scriptedAuthorization(
  authorizationUrl: URL,
  options: { baseUrl: string; realm: string; username: string; password: string },
  fetchFn: FetchLike,
): Promise<URL> {
  const authorize = await fetchFn(authorizationUrl, { redirect: "manual" });
  const flowCookies = cookies(authorize);
  const loginPage = redirectLocation(authorize, authorizationUrl);
  const executionIds = loginPage.searchParams.getAll("execution_id");
  if (executionIds.length !== 1 || !executionIds[0] || flowCookies.length === 0) {
    throw new Error("authorization did not create a correlated browser login flow");
  }
  const login = new URL("/api/v1/auth/login", options.baseUrl);
  login.searchParams.set("realm", options.realm);
  const form = new URLSearchParams({
    execution_id: executionIds[0],
    username: options.username,
    password: options.password,
  });
  const response = await fetchFn(login, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: flowCookies.join("; "),
    },
    body: form,
    redirect: "manual",
  });
  return redirectLocation(response, login);
}

export function openAuthorizationInBrowser(authorizationUrl: URL): void {
  const command =
    process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", authorizationUrl.href] : [authorizationUrl.href];
  const child = spawn(command, args, { detached: true, stdio: "ignore" });
  child.on("error", () => undefined);
  child.unref();
  process.stderr.write(`${JSON.stringify({
    type: "authorization_required",
    authorizationUrl: authorizationUrl.href,
  })}\n`);
}
