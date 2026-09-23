## Summary

<!-- What does this PR change, and why? Link issues/specs where relevant. -->

## Checklist

- [ ] `cargo fmt --all` applied
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` is clean
- [ ] `cargo test --workspace` passes
- [ ] `CHANGELOG.md` entry added under `## [Unreleased]` (or the `no-changelog` label is applied)
- [ ] `webclientsrc/openapi.json` regenerated if API shapes changed (`cargo run --bin issuerd -- openapi -o webclientsrc/openapi.json` + `npm run generate-api`)
- [ ] Docs / `AGENTS.md` updated if behavior, commands, or conventions changed
- [ ] Backward compatibility preserved (migrations append-only, additive API/config changes) or a migration path is documented
