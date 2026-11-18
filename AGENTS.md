# AGENTS.md

Instructions for AI coding agents (Codex, Claude Code, Cursor, etc.) working on Veil.

Veil is an MCP server that lets an agent request, store and use credentials without ever seeing their values. Security rules below are the most important part of this file.

## Commands

Use pnpm 10 and Node >= 20.11 (CI runs Node 20, 22 and 24).

```bash
pnpm install --frozen-lockfile   # always frozen in CI; do not regenerate the lockfile unless the task is a dependency change
pnpm typecheck                   # tsc --noEmit
pnpm lint                        # eslint .
pnpm test                        # vitest run (unit, property, integration)
pnpm build                       # tsc -p tsconfig.build.json -> dist/
pnpm test:e2e                    # Playwright; needs `pnpm build` first and Chromium installed
```

Before you say a change is done, run `pnpm typecheck && pnpm lint && pnpm test && pnpm build`.

## Security rules (non-negotiable)

- A secret value must never appear in a tool response, log line, audit entry, error message, MCP JSON-RPC message, or test snapshot. Tests in `test/app.test.ts`, `test/mcp.test.ts` and `test/envtools.test.ts` check this with random values. If you add a code path that handles values, add a property test for it.
- Values travel only through the local page, the encrypted store, or the sink (file, env, SSH, git sync). Never through the model.
- Redact before logging. See `src/redact.ts`.
- Do not weaken crypto defaults (`src/crypto/`, `src/envenc/`): AES-256-GCM, scrypt or argon2id. Do not add a new crypto primitive without a note in `THREAT-MODEL.md`.
- Keep file modes (0600) and atomic writes. Prefer the helpers in `src/fileio.ts` for new writes. Some modules write files directly (`src/sshkeys.ts`, `src/app.ts`, `src/cli-vault.ts`, `src/audit.ts`); keep their permission and atomic behavior when you touch them.
- Never edit the person's `config.json` or `approvals.json` (under the Veil home, see `src/config.ts`) to change behavior or approvals, and never add code that lets the agent change them. Only the person changes those.

## Dependencies

- Runtime dependencies are only `@modelcontextprotocol/sdk` and `zod`. Adding a runtime dependency needs a reason in the PR description.
- Optional tools (`psql`, `gh`, `ssh`, `git`, `playwright-core`) are detected at runtime, not required at install time. `veil doctor` reports what is missing.

## Code conventions

- TypeScript, ESM (`"type": "module"`). Imports use the existing style in `src/`.
- Platform code: check `src/platform.ts` before adding OS-specific branches. Targets are Windows, macOS and Linux. Windows CI is non-blocking and the suite still has known Windows failures (see the `windows` job in `.github/workflows/ci.yml`).
- Keep changes small and scoped to the task. Do not reformat unrelated files.

## Tests

- New behavior needs a test in `test/`. Bug fixes need a regression test.
- Tests that depend on POSIX behavior (file modes `0600`, Unix sockets, `/bin/sh`, LF line endings) are known to fail on Windows. Do not "fix" them by deleting the assertion; guard them by platform or document the gap.

## Git and releases

- Commit messages follow Conventional Commits with a scope, for example `feat(ssh): ...`, `fix(keychain): ...`, `docs(changelog): ...`.
- Update `CHANGELOG.md` for user-visible changes.
- Do not publish to npm. The package is not published yet (see README "Install in Claude Code").

## Docs

- `README.md` and `README.es.md` must stay in sync for user-facing changes.
- Format spec: `docs/FORMAT-VEIL-SPEC.md`. Threat model: `THREAT-MODEL.md`. Security reports: `SECURITY.md`.
