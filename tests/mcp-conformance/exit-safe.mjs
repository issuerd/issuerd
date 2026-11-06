import { pathToFileURL } from 'node:url';

const harness = process.env.CONFORMANCE_BIN;
if (!harness) throw new Error('CONFORMANCE_BIN is required');

const forcedExit = process.exit.bind(process);
process.exit = (code = 0) => {
  process.exitCode = code;
  setTimeout(() => forcedExit(code), 60_000).unref();
};

await import(pathToFileURL(harness).href);
