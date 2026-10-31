import { writeFileSync } from 'node:fs';

if (process.env.FAKE_HARNESS_PID_FILE) {
  writeFileSync(process.env.FAKE_HARNESS_PID_FILE, String(process.pid));
}
if (process.env.FAKE_AUTHORIZATION_URL) {
  console.log('=== Running scenario: authorization-code-grant ===');
  console.log('Access the following URL in your browser and complete the authentication process.');
  console.log(process.env.FAKE_AUTHORIZATION_URL);
}

setInterval(() => {}, 1_000);
