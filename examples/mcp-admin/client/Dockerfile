FROM node:24.17.0-bookworm-slim@sha256:862263c612aa437e3037674b85419622a9d93bff80aa1eee5398dfe686375532

WORKDIR /opt/mcp-admin
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
COPY test ./test
RUN npm run build \
    && npm run typecheck \
    && node --test dist/test/*.test.js \
    && npm prune --omit=dev

ENV MCP_LOGIN_MODE=script \
    MCP_ERA=auto
CMD ["node", "dist/src/cli.js", "--mode", "script", "--era", "auto"]
