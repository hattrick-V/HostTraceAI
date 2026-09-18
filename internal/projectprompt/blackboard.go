// Package projectprompt 提供项目黑板相关的系统提示文本（纯字符串，无 database 依赖）。
// 供 agent / multiagent 等包引用，避免 agent → project 导入环导致 gopls 元数据失败。
package projectprompt

import (
	"strings"

	"hosttrace-ai/internal/mcp/builtin"
)

const (
	factRhythmCore              = "勿等会话结束或收尾再批量写入。每**确认**一条新认知（目标主机、账号登录、暴露服务、可疑进程、持久化项、外联、样本哈希、时间线节点）后，**立即**调用 `upsert_project_fact`（同 fact_key 覆盖更新）。每**确认**一条可交付威胁发现（恶意进程、后门脚本、挖矿程序、异常登录、初始入口、横向移动、持久化或外联 IOC）后，**立即**调用 `record_vulnerability`；结案或阶段收尾前必须调用 `record_trace_result` 把主机/发现/证据/时间线/归档包写入 trace_* 表，供仪表盘读取。继续下一步工作前优先落库，避免上下文压缩后细节丢失。未绑项目时仍可记录带 conversation_id 的威胁发现；无法写黑板时说明原因并在本轮保留证据摘要。"
	factRhythmCoordinatorSuffix = "委派/子任务返回新认知或威胁发现时，由协调者及时写入，勿假定子代理已记。"
	factRhythmSubAgentSuffix    = "若工具集中无上述工具，须在交付物末尾给出「待落库」结构化条目（fact_key 建议、summary、body/POC 要点），供协调者**立即**写入。"
)

// FactRecordingIncrementalRhythmMarkdown 返回边溯源边记录节奏（Markdown，供 agents/*.md 与文档对齐）。
func FactRecordingIncrementalRhythmMarkdown(coordinator, subAgent bool) string {
	var b strings.Builder
	b.WriteString("- **边溯源边记录（强制节奏）**：")
	b.WriteString(factRhythmCore)
	if coordinator {
		b.WriteString(factRhythmCoordinatorSuffix)
	}
	if subAgent {
		b.WriteString(factRhythmSubAgentSuffix)
	}
	return b.String()
}

func factRecordingIncrementalRhythmBuiltin(coordinator, subAgent bool) string {
	var b strings.Builder
	b.WriteString("- **边溯源边记录（强制节奏）**：勿等会话结束或收尾再批量写入。每**确认**一条新认知（目标主机、账号登录、暴露服务、可疑进程、持久化项、外联、样本哈希、时间线节点）后，**立即**调用 ")
	b.WriteString(builtin.ToolUpsertProjectFact)
	b.WriteString("（同 fact_key 覆盖更新）。每**确认**一条可交付威胁发现（恶意进程、后门脚本、挖矿程序、异常登录、初始入口、横向移动、持久化或外联 IOC）后，**立即**调用 ")
	b.WriteString(builtin.ToolRecordVulnerability)
	b.WriteString("；结案或阶段收尾前必须调用 ")
	b.WriteString(builtin.ToolRecordTraceResult)
	b.WriteString(" 把主机/发现/证据/时间线/归档包写入 trace_* 表，供仪表盘读取。继续下一步工作前优先落库，避免上下文压缩后细节丢失。未绑项目时仍可记录带 conversation_id 的威胁发现；无法写黑板时说明原因并在本轮保留证据摘要。")
	if coordinator {
		b.WriteString(factRhythmCoordinatorSuffix)
	}
	if subAgent {
		b.WriteString(factRhythmSubAgentSuffix)
	}
	return b.String()
}

func factEdgeRecordingGuidance() string {
	return `### 事实关系边（links）

- 写入 **finding / chain / persistence / ioc** 时，**必须**在 ` + "`upsert_project_fact`" + ` 中提供 ` + "`links`" + `（**推荐 ` + "`from`" + `**：来源 fact 指向当前 fact，即 ` + "`from`" + ` → 当前 ` + "`fact_key`" + `）。
- **最少要求**：finding 类至少 1 条 from=target/* + type=observed_on（即 target → finding）；在发现上记录证据用 from=evidence/* + type=supports（即 evidence → finding）。
- **常用 type**：` + "`observed_on`" + `（发现在哪）、` + "`depends_on`" + `（判断前置）、` + "`leads_to`" + `（认知推进）、` + "`enables`" + `（攻击路径使能）、` + "`supports`" + `（证据支撑）、` + "`contains`" + `（主机/目录包含）、` + "`part_of`" + `（属于时间线/归档）、` + "`communicates_with`" + `（外联关系）。
- 更新时：**省略 links 保留已有边**；传入 links 则**替换**全部关系边（from → 当前 fact）。
- body 中「依赖事实」段落可与 links 并存（人读）；结构化关系以 links 为准。`
}

func factRecordingGuidanceBlock() string {
	return `### 事实写入规范（审计复现 / 知识沉淀）

- **summary**：索引用一行，须含「什么 + 在哪 + 如何验证」要点，禁止只写结论（如仅写「存在后门」）。
- **body**：完整可复现上下文，写入 ` + "`upsert_project_fact`" + ` 的 body 字段；索引不含 body，后续会话须靠 ` + "`get_project_fact`" + ` 取回。
- **category / fact_key 建议**：
  - 环境认知：` + "`target/`" + `、` + "`auth/`" + `、` + "`infra/`" + `、` + "`business/`" + `（body 用环境模板即可）
  - 威胁发现与路径：` + "`finding/`" + `、` + "`chain/`" + `、` + "`persistence/`" + `、` + "`ioc/`" + `、` + "`evidence/`" + `（**必须**写满 body：入口、时间线、命令或日志证据、样本/哈希/外联、关联威胁 ID）
- **与威胁记录分工**：` + "`record_vulnerability`" + ` 记仪表盘可见的可交付威胁发现；事实记**复核所需的全部上下文**（含失败尝试、证据来源、依赖会话），二者可各记一次。
- 更新同一发现时保持相同 ` + "`fact_key`" + ` 覆盖写入，勿散落多个 key 导致上下文丢失。`
}

// FactRecordingBlackboardSection 项目黑板与漏洞记录的完整系统提示块（单/多 Agent 主代理共用）。
func FactRecordingBlackboardSection(coordinatorDelegate bool) string {
	var b strings.Builder
	b.WriteString("## 项目黑板（事实）与威胁发现记录（分离）\n\n")
	b.WriteString("当前对话若已绑定项目，系统会自动注入「项目黑板索引」（仅 fact_key + 摘要）。**摘要不足时必须调用 ")
	b.WriteString(builtin.ToolGetProjectFact)
	b.WriteString("(fact_key) 获取 body，禁止凭摘要臆造细节。**\n\n")
	b.WriteString(factRecordingIncrementalRhythmBuiltin(coordinatorDelegate, false))
	b.WriteString("\n\n")
	b.WriteString("- **环境/目标/认证等认知**（非正式威胁条目）：使用 ")
	b.WriteString(builtin.ToolUpsertProjectFact)
	b.WriteString("，fact_key 建议 `category/slug`（如 target/primary_domain），同 key 覆盖更新；body 记端口/版本/凭据特征与证据来源。\n")
	b.WriteString("- **威胁发现与入侵路径上下文**（审计复核）：fact_key 建议 finding/、chain/、persistence/、ioc/、evidence/ 前缀；**body 必填**完整路径（入口 → 时间线 → 命令/日志/文件证据 → 现象 → 关联 related_vulnerability_id），**禁止仅写结论**；summary 写「什么 + 在哪 + 如何验证」一行要点。\n")
	b.WriteString("- **可交付威胁发现**：使用 ")
	b.WriteString(builtin.ToolRecordVulnerability)
	b.WriteString("，含标题、严重程度、类型、目标、证明证据、影响、处置建议。记前可先 ")
	b.WriteString(builtin.ToolListVulnerabilities)
	b.WriteString(" 查重，详情用 ")
	b.WriteString(builtin.ToolGetVulnerability)
	b.WriteString("(id)（默认仅当前项目/会话）。\n")
	b.WriteString("- 同一发现可能需**各记一次**（事实记**完整入侵路径与证据细节**供复核，威胁记录用于仪表盘与报告）。误报用 ")
	b.WriteString(builtin.ToolDeprecateProjectFact)
	b.WriteString(" 或漏洞状态 false_positive。\n")
	b.WriteString("- **仪表盘同步**：结案或阶段收尾前必须使用 ")
	b.WriteString(builtin.ToolRecordTraceResult)
	b.WriteString(" 写入 trace_* 表；否则溯源对话只会停留在自然语言报告，仪表盘不会显示。\n")
	b.WriteString("- 事实多时用 ")
	b.WriteString(builtin.ToolListProjectFacts)
	b.WriteString(" / ")
	b.WriteString(builtin.ToolSearchProjectFacts)
	b.WriteString(" 检索。\n\n")
	b.WriteString(factEdgeRecordingGuidance())
	b.WriteString("\n\n")
	b.WriteString(factRecordingGuidanceBlock())
	b.WriteString("\n\n严重程度：critical / high / medium / low / info。结案前必须检查是否有已确认威胁尚未调用 record_vulnerability，并必须调用 record_trace_result 同步溯源仪表盘；证明须含足够证据（日志、命令输出、文件哈希、路径、时间戳等）。")
	return b.String()
}

// FactRecordingSubAgentSection 子代理边溯源边记录（无工具时输出待落库条目）。
func FactRecordingSubAgentSection() string {
	return "## 边溯源边记录\n\n" + factRecordingIncrementalRhythmBuiltin(false, true) + "\n"
}

// FactRecordingBlackboardSectionMarkdown 与 FactRecordingBlackboardSection 等价的 Markdown（工具名为字面量，供 agents/*.md）。
func FactRecordingBlackboardSectionMarkdown(coordinatorDelegate bool) string {
	var b strings.Builder
	b.WriteString("## 项目黑板（事实）与威胁发现记录（分离）\n\n")
	b.WriteString("当前对话若已绑定项目，系统会自动注入「项目黑板索引」（仅 `fact_key` + 摘要）。**摘要不足时必须调用 `get_project_fact(fact_key)` 获取 body，禁止凭摘要臆造细节。**\n\n")
	b.WriteString(FactRecordingIncrementalRhythmMarkdown(coordinatorDelegate, false))
	b.WriteString("\n\n")
	b.WriteString("- **环境/目标/认证等认知**（非正式威胁条目）：使用 **`upsert_project_fact`**，`fact_key` 建议 `category/slug`（如 `target/primary_host`），同 key 覆盖更新；body 记端口/版本/凭据特征与证据来源。\n")
	b.WriteString("- **威胁发现与入侵路径上下文**（审计复核）：`fact_key` 建议 `finding/`、`chain/`、`persistence/`、`ioc/`、`evidence/` 前缀；**body 必填**完整路径（入口 → 时间线 → 命令/日志/文件证据 → 现象 → 关联 `related_vulnerability_id`），**禁止仅写结论**；summary 写「什么 + 在哪 + 如何验证」一行要点。\n")
	b.WriteString("- **可交付威胁发现**：使用 **`record_vulnerability`**（标题、描述、严重程度、类型、目标、证明证据、影响、处置建议）。严重程度 critical / high / medium / low / info。\n")
	b.WriteString("- 同一发现可能需**各记一次**（事实记可复核入侵路径，威胁记录用于仪表盘与报告）。误报用 **`deprecate_project_fact`** 或威胁状态 false_positive。\n")
	b.WriteString("- **仪表盘同步**：结案或阶段收尾前必须使用 **`record_trace_result`** 写入 trace_* 表；否则溯源对话只会停留在自然语言报告，仪表盘不会显示。\n")
	b.WriteString("- 事实多时用 **`list_project_facts`** / **`search_project_facts`** 检索。\n\n")
	b.WriteString(factEdgeRecordingGuidance())
	b.WriteString("\n\n")
	b.WriteString(factRecordingGuidanceBlock())
	b.WriteString("\n\n严重程度：critical / high / medium / low / info。结案前必须检查是否有已确认威胁尚未调用 record_vulnerability，并必须调用 record_trace_result 同步溯源仪表盘；证明须含足够证据（日志、命令输出、文件哈希、路径、时间戳等）。")
	return b.String()
}

// FactEdgeRecordingGuidance 写入边时的 Agent 规范（供 project 包复用）。
func FactEdgeRecordingGuidance() string { return factEdgeRecordingGuidance() }

// FactRecordingGuidanceBlock 事实写入规范块（供 project 包复用）。
func FactRecordingGuidanceBlock() string { return factRecordingGuidanceBlock() }
