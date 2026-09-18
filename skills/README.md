# HostTraceAI Skills

每个 Skill 使用独立目录和 `SKILL.md`，描述适用条件、证据要求、工具顺序、停止条件和输出格式。Skill 只提供调查知识，不绕过平台权限和审批。

首批：病毒木马溯源、Windows 持久化、Linux 持久化、WebShell 后门溯源、证据审计。

---

## 目录规范（平台校验器 `internal/skillpackage/validate.go` 强制）

- 目录名 = `SKILL.md` front matter 的 `name`：小写字母/数字/单个连字符，≤64 字符，不得首尾连字符、不得连续 `--`、不得含 `claude`/`anthropic`。
- front matter **只允许** `name`、`description`、`license`、`compatibility`、`metadata`、`allowed-tools` 六个顶层键；`description` 必须**单行、双引号包裹**，≤1024 字符。
- front matter 之后必须有正文。可附带 `references/`、`scripts/`、`assets/` 子目录（只在 `*/SKILL.md` 一级被扫描，嵌套目录里的 SKILL.md 不会被加载为技能）。
- 命名与正文一律用 ASCII slug + 中文内容；**中文目录名会被 Web 管理 API 拒绝写入**（校验器要求 name 与目录名一致且为小写 ASCII），因此新增技能请用英文 slug。
- 自检命令（用平台自身代码）：

```bash
cd /dpDATA/HostTraceAI && GOFLAGS=-mod=mod GOPROXY=off go run ./tmp/verify
```

该程序会逐个校验 `skills/*/SKILL.md`、装载 `agents/*.md`、装载 `roles/*.yaml`，并打印结果。

## 现有技能（2026-09-17 补充后共 16 个）

平台原生（首批，中文目录，运行时可加载但无法经 Web API 编辑）：

| 技能 | 用途 |
| --- | --- |
| 病毒木马溯源 | 进程/网络/服务/启动项到样本的木马调查证据链 |
| Windows持久化 | 服务、计划任务、启动项、注册表、事件日志的异常持久化 |
| Linux持久化 | systemd、cron、shell profile、authorized_keys |
| WebShell后门溯源 | Web 根目录、脚本、上传目录、访问日志、子进程 |
| 证据审计 | 证据规范化：来源、时间、哈希、可信度、事实/推断分离 |

本次补充（Hermes 侧溯源/应急技能改写 + 平台缺口新建，均为 ASCII slug）：

| 技能 | 用途 |
| --- | --- |
| investigation-orchestration | 调查编排：接案定界→只读采集→固证→假设验证→时间线→分派→审批→结案 |
| windows-host-triage | Windows 主机木马溯源与处置闭环（远程取证、归档、隔离、清持久化、让安全软件装上） |
| windows-forensic-timeline | 落地时间线还原：文件 MACB、Prefetch/Amcache/UserAssist、事件日志 ID、日志清除与加密时间线 |
| windows-bat-scripting | 中文 Windows 主机上编写/执行 .bat 采集与处置脚本的编码与坑 |
| webroot-forensics | Web 目录取证：脚本时间线、上传目录、访问日志、入口推断、影响面 |
| malware-sample-analysis | 样本判读：PE/.NET/脚本、PDB 与签名、C2 与配置提取、家族特征与置信度分级 |
| memory-forensics | 内存取证（Volatility 3 为主）：隐藏进程、注入、凭据痕迹、时间线 |
| pcap-traffic-analysis | 流量分析：会话统计、C2 心跳与 DNS 隧道识别、文件雕刻、TLS 元数据 |
| remote-host-collection | 主机通道接入与只读采集（含样本外带与哈希复核、批量节奏控制） |
| edr-repair-and-policy-tampering | 安全软件装不上：恶意 CI/WDAC 策略、BYOVD 驱动、卸载残留的排查与修复 |
| trace-report-and-evidence-chain | 结案产出规范：时间线表、IOC 表、证据索引、报告格式与身份标识口径 |

## 技能与智能体的关系

平台不通过角色文件绑定技能：`skills/` 下的技能由 Eino skill 中间件统一加载，Agent 在系统提示里看到技能清单（name + description），需要时用 `skill` 工具加载全文（渐进式披露）。因此**技能描述的第一句必须写清"何时使用"**，否则 Agent 不会想起来加载它。

`agents/*.md` 的 `bind_role` 只用于与 `roles/*.yaml` 的角色名对齐（保持一一对应便于管理），不承担技能绑定职责。
