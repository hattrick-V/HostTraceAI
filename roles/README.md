# HostTraceAI 角色

角色定义只描述调查职责和可用能力，不包含渗透、漏洞利用或横向移动流程。

---

## 生效方式（重要）

角色文件位于 `roles/`，但**只有在 `config.yaml` 中配置 `roles_dir: roles` 时才会被加载**（`internal/config/config.go:1497`：`cfg.RolesDir` 为空则 `cfg.Roles` 为空 map）。未配置时角色列表为空，聊天界面的角色选择不生效（技能与多代理仍正常，因为它们各自有默认目录）。

角色生效后需要**重启服务**。

## 平台 RoleConfig 只识别这些字段

`name`、`description`、`user_prompt`、`icon`、`tools`、`enabled`（以及可选的 `workflow_id` / `workflow_version` / `workflow_policy`）。

- **不支持 `skills:` 与 `max_iterations:`** —— 写了也会被 YAML 解码忽略（角色不承担技能绑定；技能由 Eino skill 中间件统一加载）。需要限制迭代次数请改 `agents/*.md` 的 `max_iterations`。
- **必须显式写 `enabled: true`**，否则角色加载后处于禁用状态（`handler/agent.go` 与 `multi_agent_prepare.go` 都用 `role.Enabled` 做闸门）。
- `tools` 必须是**平台真实存在的工具 key**（如 `execute`、`ls`、`read_file`、`write_file`、`edit_file`、`glob`、`grep`、`get_asset`、`query_assets`、`upsert_project_fact`、`list_project_facts`、`search_project_facts`、`get_project_fact`、`deprecate_project_fact`、`search_knowledge_base`、`list_knowledge_risk_types`、`analyze_image`、`get_tool_execution`、`wait_tool_execution`、`cancel_tool_execution`；外部 MCP 工具写作 `mcpName::toolName`）。列了不存在的工具名不会报错但也不会生效。
- `user_prompt` 会被**拼接在每条用户消息前**，所以只放"本次任务前提/红线/输出格式"，不要放长文档。

## 三个角色

| 角色 | 对应智能体文件 | 职责 |
| --- | --- | --- |
| 溯源指挥官 | `agents/trace-commander.md`（`kind: orchestrator`，deep 模式主代理） | 接案定界、只读采集、固证、按证据分派专家、汇总时间线与 IOC、处置审批编排、结案 |
| 病毒木马溯源专家 | `agents/malware-triage.md` | 进程/服务/驱动/启动项/计划任务/账号/外联/样本的木马调查与处置建议 |
| WebShell后门溯源专家 | `agents/webshell-triage.md` | Web 目录/脚本时间线/上传目录/访问日志/Web 进程子进程/后门持久化 |

另外 `agents/orchestrator-plan-execute.md` 与 `agents/orchestrator-supervisor.md` 分别是 **plan_execute 与 supervisor 模式的主代理提示**，用于替代 `internal/multiagent/orchestrator_instruction.go` 内置的默认提示（内置版本是"授权渗透测试"风格，与溯源平台的产品边界不符；只要这两个文件存在且正文非空，就会优先使用文件内容）。

## 授权与红线口径

三个角色都在系统提示与 `user_prompt` 里写明：

- 调查已由组织前置授权 —— 不质疑、不反问、不索取许可；
- 只读调查动作直接执行；
- 处置动作走审批（给命令、影响面、回滚方式），**不是拒绝**；
- 禁止以"敏感/隐私/合规/风险"为由推脱或只给建议不取证；
- 硬红线：不删除非恶意文件；样本只移动不销毁并先归档哈希；不做口令尝试；不连接/扫描非目标主机；不修改未审批的系统配置；不编造证据。
