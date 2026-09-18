# HostTraceAI

**English** | [简体中文](README_CN.md)

HostTraceAI is an AI-assisted host provenance and incident-response workspace. It is built on a mature conversational agent, MCP, Skills, RBAC, audit, and SQLite foundation, while keeping host investigation as its only product domain.

The platform helps authorized responders investigate Linux and Windows hosts over SSH/MCP, preserve evidence, reason over findings, and produce an auditable timeline and report.

It is not a vulnerability scanner, penetration-testing console, asset-discovery platform, alert center, or C2 framework.

## Screenshots

**Sign-in**

![HostTraceAI sign-in](images/screenshot-login.png)

**Malware triage — findings, external connections and sample hashes**

![Malware triage](images/screenshot-malware-triage.png)

**Approval-gated containment — every action recorded with a rollback path**

![Approval-gated containment](images/screenshot-approval-execution.png)

## Quick start

Requires Go 1.25 or newer (see the `go` directive in `go.mod`).

```bash
git clone https://github.com/hattrick-V/HostTraceAI.git
cd HostTraceAI
cp config.example.yaml config.yaml
go run ./cmd/server --config config.yaml --http --port 19088
```

Then open `http://127.0.0.1:19088/`. The first start creates the `admin`
account with a one-time random strong password, printed to the log — save it
immediately, it is shown only once.

The Web/API port can be supplied with `--port`, the `HOSTTRACE_PORT`
environment variable, or `config.yaml` (in that order).

### Configure an AI model (required)

The AI channel in `config.example.yaml` ships as a **placeholder**
(`base_url: https://api.example.com/v1`, empty `api_key` and `model`). The
service starts, but conversations will not work until you fill these in.

After signing in:

1. Go to **Settings → Basic Settings → AI Channel**;
2. Fill in **Base URL**, **API Key**, and **Model**;
   - Any OpenAI-compatible endpoint works (OpenAI, DeepSeek, Qwen, Zhipu,
     a local vLLM or Ollama server, and so on);
   - Use "Fetch models" to pick from a list where supported; Claude requires
     the model name to be typed manually;
3. Click **Test connection**, then save.

You can also edit the `ai.channels.default` section of `config.yaml` directly
and restart the service.

> Optional: knowledge-base retrieval and vision analysis need separate
> embedding / rerank channels, configured in the same settings page. Leaving
> them unset does not affect basic chat or host investigation.

### Python and MCP are optional

**Python is not required.** The platform itself — Go server, web console, and
the built-in forensics tools — runs fully without it. The Python packages in
`requirements.txt` only serve the optional helper scripts under `mcp-servers/`;
`run.sh` skips them automatically when python3 is absent.

`mcp.enabled: false` in the example config is deliberate: **built-in tools do
not depend on HTTP MCP services**, so a fresh deployment has full capability
out of the box. Enable it only when you want to reach remote hosts over SSH or
attach external MCP servers.

Built-in forensics tools live in `tools/` (binwalk, exiftool, foremost,
strings, exec) and expect the corresponding CLI programs to be installed on
the target host.

See `README_CN.md` for the product model and the local deployment guide.

An optional Chromium DevTools extension (capture browser Network traffic into an investigation) lives in `plugins/browser-extension/`; see `plugins/README.md`.

## Attribution and notice

HostTraceAI's architectural and engineering skeleton is derived from
[CyberStrikeAI](https://github.com/AIPentest/CyberStrikeAI) (Copyright 2025
Ed1s0nZ), which is licensed under the Apache License 2.0. HostTraceAI keeps the
same license, retains the original copyright notice, and documents its changes
in [`NOTICE`](NOTICE).

The reused skeleton covers the Go server layout, the MCP capability centre, the
Markdown Skill loading mechanism, the RBAC / approval / audit layer, and the
web console structure. HostTraceAI then narrows the product scope to host
provenance and incident response, rebrands the product, reduces the built-in
tool set to reviewed host forensic tools, and redesigns the investigation roles
and the Skill library.

We have made a good-faith effort to credit the original work. If the original
author or any rights holder considers this project's use inappropriate or
infringing, please contact **dengpan084@gmail.com**. We will verify and
promptly take the project down or make the requested corrections.

