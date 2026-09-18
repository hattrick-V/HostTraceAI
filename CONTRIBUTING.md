# Contributing to HostTraceAI

Thanks for your interest. This project is an AI-assisted host provenance and
incident-response workspace. Please read the product boundary below before
proposing changes.

## Scope

HostTraceAI is **not** a vulnerability scanner, penetration-testing console,
asset-discovery platform, alert center, or C2 framework. Contributions are
expected to stay within the host forensics / incident-response domain.

In particular, `tools/` only accepts reviewed, read-only or approval-gated
**host forensic** tool definitions. Vulnerability scanning, credential
brute-forcing, lateral movement, and unreviewed script execution do not belong
there — see `tools/README.md`.

## Getting started

```bash
git clone https://github.com/hattrick-V/HostTraceAI.git
cd HostTraceAI
cp config.example.yaml config.yaml
go build -o hosttrace-ai ./cmd/server
```

The first start creates the `admin` account with a one-time random strong
password, printed to the log.

## Before you open a pull request

All of the following must pass:

```bash
# 1. Formatting
gofmt -l ./cmd ./internal        # must print nothing

# 2. Static analysis
go vet ./...

# 3. Full test suite
go test ./...

# 4. Frontend tests (run from the repository root)
node web/static/js/tool-guard.test.cjs
```

If you touched the browser extension under `plugins/browser-extension/`, also
run its packaging script to confirm it still builds.

### Known-failing frontend tests

Six of the frontend tests currently fail on a clean checkout. This is a
pre-existing condition, unrelated to any recent change:

```bash
# 12 pass / 6 fail on a clean checkout
for f in web/static/js/*.test.cjs; do node "$f" || echo "FAILED: $f"; done
```

| Test file | Reason |
|---|---|
| `chat-codex-layout` | reads `web/static/js/projects.js`, which no longer exists |
| `chat-scroll-refresh` | same |
| `conversation-actions-sync` | same |
| `hitl-approval-ui` | same |
| `project-folder-preview` | same |
| `hitl-conversation-isolation` | asserts an API shape that was refactored |

`projects.js` was removed along with the project/folder feature; neither
`web/templates/index.html` nor the server references it any more. Fixing these
tests is welcome but not required for a contribution.

### Windows notes

Some tests in `internal/security` invoke `/bin/sh`. On Windows, Go resolves a
slash-containing path against the **current drive root** rather than searching
`PATH`, so place `sh.exe` at `C:\bin\sh.exe` (copy it from Git for Windows) to
run those tests locally:

```bash
cp "C:/Program Files/Git/usr/bin/sh.exe" "C:/bin/sh.exe"
```

This is local test setup only; production runs on Linux and no source change is
needed.

## Code guidelines

- Keep comments and user-facing strings in the existing style. The codebase uses
  Chinese for domain comments and English for API identifiers.
- Prefer explicit, well-named constants over magic strings, especially for keys
  that cross process or language boundaries.
- When a value is shared between Go and JavaScript (for example an MCP metadata
  key, a `localStorage` key, or a `BroadcastChannel` name), **change both sides
  in the same commit** and note it in the PR description.
- Do not rename serialized identifiers (for example Eino `schema.RegisterName`
  values or the workflow `PackageFormat` constant) without a migration plan —
  they are read back from persisted data.

## Reporting issues

When reporting a bug, please include:

- What you expected to happen and what actually happened
- Steps to reproduce
- Your OS and Go version
- Relevant log output (redact credentials, internal hostnames, and IPs)

For **security vulnerabilities**, do not open a public issue. Report privately
to the maintainers so a fix can be prepared first.

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0, as described in `LICENSE`.
