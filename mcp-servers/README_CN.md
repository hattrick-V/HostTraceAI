# MCP 服务

[English](README.md)

本目录存放 **独立 MCP（Model Context Protocol）服务**，采用标准 MCP 协议（stdio 或部分服务支持 HTTP/SSE），因此 **任意支持 MCP 的客户端** 均可使用——不限于 HostTraceAI，**Cursor**、**VS Code**（配合 MCP 扩展）、**Claude Code** 等均可接入。

公开开源版不内置远控或反连类 MCP 服务。确有需要时，请在平台 UI 中接入你所在组织已审批的外部 MCP 服务。

## 已提供服务

开源发行包默认不提供内置 MCP 服务示例。

## 使用方式

各 MCP 需在对应客户端里配置后使用。stdio 模式下 `command` 与 `args` 请使用**绝对路径**。

### HostTraceAI

1. 打开 Web 界面 → **设置** → **外部 MCP**。
2. 添加新的外部 MCP，按各服务目录下 README 的说明填写 JSON 配置。
3. 保存后点击 **启动**，对话中即可使用对应工具。

### Cursor

在 Cursor 的 MCP 配置中添加你已审批的 MCP 服务（如 **Settings → Tools & MCP → Add Custom MCP**，或编辑 `~/.cursor/mcp.json` / 项目下的 `.cursor/mcp.json`），具体字段以该服务文档为准。

### VS Code（MCP 扩展）/ Claude Code / 其他客户端

请按已审批 MCP 服务的文档配置。配置位置依客户端而定（如 `.mcp.json`、`~/.claude.json` 或扩展设置），请查阅该客户端的 MCP 说明。

## 依赖说明

- 基于 Python 的服务需 Python 3.10+。
- 建议使用项目自带的 `venv`，例如 `venv/bin/python3` 配合 `mcp-servers/` 下脚本路径。
