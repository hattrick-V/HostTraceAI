# MCP Servers

[中文](README_CN.md)

This directory contains **standalone MCP (Model Context Protocol) servers**. They speak the standard MCP protocol over stdio (or HTTP/SSE when a server supports it), so **any MCP client** can use them—not only HostTraceAI, but also **Cursor**, **VS Code** (with an MCP extension), **Claude Code**, and other clients that support MCP.

The public HostTraceAI release does not bundle remote-control or reverse-shell MCP servers. Add your own organization-approved MCP servers through the UI when needed.

## Available servers

No bundled MCP servers are enabled in this open-source distribution.

## How to use

These MCPs are configured per client. Use **absolute paths** for `command` and `args` when using stdio.

### HostTraceAI

1. Open Web UI → **Settings** → **External MCP**.
2. Add a new external MCP and fill in the JSON config (see each server’s README for the exact config).
3. Save and click **Start**; the tools will appear in conversations.

### Cursor

Add your approved MCP server to Cursor’s MCP config (for example, **Settings → Tools & MCP → Add Custom MCP**, or edit `~/.cursor/mcp.json` / project `.cursor/mcp.json`) using that server’s documentation.

### VS Code (MCP extension) / Claude Code / other clients

Configure the client according to the approved MCP server’s documentation. Refer to your client’s docs for where to put the config (e.g. `.mcp.json`, `~/.claude.json`, or the extension’s settings).

## Requirements

- Python 3.10+ for Python-based servers.
- Use the project’s `venv` when possible: e.g. `venv/bin/python3` and the script under `mcp-servers/`.
