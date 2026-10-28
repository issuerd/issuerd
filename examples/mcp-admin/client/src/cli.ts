import { parseCliOptions, usage } from "./config.js";
import { runAcceptance } from "./acceptance.js";
import { AcceptanceError } from "./errors.js";

function errorShape(error: unknown): { name: string; code?: string; message: string } {
  const name = error instanceof Error ? error.name : "Error";
  const code =
    typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
      ? error.code
      : undefined;
  return {
    name,
    ...(code ? { code } : {}),
    message:
      error instanceof AcceptanceError
        ? error.message
        : "MCP acceptance failed; no credentials or protocol artifacts were logged",
  };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  try {
    const options = parseCliOptions(args, process.env);
    const report = await runAcceptance(options);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ ok: false, error: errorShape(error) }, null, 2)}\n`);
    process.exitCode = 1;
  }
}

await main();
