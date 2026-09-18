package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"hosttrace-ai/internal/authctx"
	"hosttrace-ai/internal/database"
	"hosttrace-ai/internal/mcp"
	"hosttrace-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func registerTraceTools(mcpServer *mcp.Server, db *database.DB, logger *zap.Logger) {
	if mcpServer == nil || db == nil {
		return
	}
	tool := mcp.Tool{
		Name:             builtin.ToolRecordTraceResult,
		ShortDescription: "写入主机溯源结构化结果",
		Description: "在溯源阶段结束或结案前调用：把目标主机、威胁发现、证据、时间线和归档包元数据写入 trace_* 溯源表，供仪表盘和报告读取。" +
			"不要用于普通聊天附件；仅写入已经验证或明确标记置信度的溯源成果。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"host": map[string]interface{}{
					"type":        "object",
					"description": "目标主机信息",
					"required":    []string{"address"},
					"properties": map[string]interface{}{
						"address":   map[string]interface{}{"type": "string", "description": "主机 IP / 主机名。开源示例请使用 192.0.2.10 等文档网段。"},
						"name":      map[string]interface{}{"type": "string", "description": "主机显示名"},
						"osFamily":  map[string]interface{}{"type": "string", "description": "windows/linux/unknown"},
						"transport": map[string]interface{}{"type": "string", "description": "ssh/winrm/local/mcp 等"},
						"tags":      map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
					},
				},
				"task": map[string]interface{}{
					"type":        "object",
					"description": "本次溯源任务摘要",
					"properties": map[string]interface{}{
						"title":               map[string]interface{}{"type": "string"},
						"symptom":             map[string]interface{}{"type": "string"},
						"suspiciousIndicator": map[string]interface{}{"type": "string"},
						"expert":              map[string]interface{}{"type": "string"},
						"status":              map[string]interface{}{"type": "string", "enum": []string{"open", "confirmed", "contained", "remediated", "completed", "failed"}},
						"conclusion":          map[string]interface{}{"type": "string"},
					},
				},
				"findings": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type":     "object",
						"required": []string{"title", "severity"},
						"properties": map[string]interface{}{
							"kind":       map[string]interface{}{"type": "string", "description": "malware/backdoor/miner/persistence/initial_access/ioc 等"},
							"title":      map[string]interface{}{"type": "string"},
							"severity":   map[string]interface{}{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}},
							"confidence": map[string]interface{}{"type": "number", "description": "0-1"},
							"status":     map[string]interface{}{"type": "string", "description": "open/confirmed/contained/remediated"},
							"details":    map[string]interface{}{"type": "object", "description": "证据摘要、IOC、影响、处置建议等结构化细节"},
						},
					},
				},
				"evidence": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"category":   map[string]interface{}{"type": "string", "description": "process/service/file/log/network/registry/task/sample/report"},
							"name":       map[string]interface{}{"type": "string"},
							"content":    map[string]interface{}{"type": "string"},
							"sha256":     map[string]interface{}{"type": "string"},
							"sourceTool": map[string]interface{}{"type": "string"},
						},
					},
				},
				"timeline": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"actor":     map[string]interface{}{"type": "string", "description": "attacker/system/defender/responder/unknown"},
							"eventType": map[string]interface{}{"type": "string", "description": "login/dropper/persistence/mining/c2/containment/remediation"},
							"title":     map[string]interface{}{"type": "string"},
							"detail":    map[string]interface{}{"type": "string"},
							"severity":  map[string]interface{}{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}},
						},
					},
				},
				"artifacts": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"name":      map[string]interface{}{"type": "string"},
							"path":      map[string]interface{}{"type": "string"},
							"sha256":    map[string]interface{}{"type": "string"},
							"sizeBytes": map[string]interface{}{"type": "integer"},
							"mimeType":  map[string]interface{}{"type": "string"},
						},
					},
				},
			},
			"required": []string{"host"},
		},
	}
	mcpServer.RegisterTool(tool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		input, err := traceRecordInputFromArgs(ctx, db, args)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		if len(input.Findings)+len(input.Evidence)+len(input.Timeline)+len(input.Artifacts) == 0 {
			return textResult("错误: 至少需要 findings、evidence、timeline 或 artifacts 中的一类结构化结果", true), nil
		}
		res, err := db.RecordTraceResult(input)
		if err != nil {
			if logger != nil {
				logger.Error("记录溯源结构化结果失败", zap.Error(err))
			}
			return textResult("记录溯源结构化结果失败: "+err.Error(), true), nil
		}
		return textResult(fmt.Sprintf("溯源结果已写入 trace_* 表。\n主机ID: %s\n任务ID: %s\n威胁发现: %d\n证据: %d\n时间线: %d\n归档包: %d",
			res.HostID, res.TaskID, res.FindingsCount, res.EvidenceCount, res.TimelineCount, res.ArtifactCount), false), nil
	})
	if logger != nil {
		logger.Debug("溯源结构化结果 MCP 工具注册成功", zap.String("tool", builtin.ToolRecordTraceResult))
	}
}

func traceRecordInputFromArgs(ctx context.Context, db *database.DB, args map[string]interface{}) (database.TraceRecordInput, error) {
	var in database.TraceRecordInput
	host, _ := args["host"].(map[string]interface{})
	in.HostAddress = strings.TrimSpace(strArg(host, "address"))
	if in.HostAddress == "" {
		return in, fmt.Errorf("host.address 必填")
	}
	in.HostName = strArg(host, "name")
	in.OSFamily = strArg(host, "osFamily")
	in.Transport = strArg(host, "transport")
	if tags, err := stringSliceArg(host["tags"]); err == nil {
		in.Tags = tags
	}

	if task, _ := args["task"].(map[string]interface{}); task != nil {
		in.TaskTitle = strArg(task, "title")
		in.Symptom = strArg(task, "symptom")
		in.SuspiciousIndicator = strArg(task, "suspiciousIndicator")
		in.Expert = strArg(task, "expert")
		in.Status = strArg(task, "status")
		in.Conclusion = strArg(task, "conclusion")
	}
	in.Mode = "interactive"
	in.ConversationID = conversationIDFromToolCtx(ctx)
	if in.ConversationID != "" {
		if pid, err := db.GetConversationProjectID(in.ConversationID); err == nil {
			in.ProjectID = strings.TrimSpace(pid)
		}
	}
	if principal, ok := authctx.PrincipalFromContext(ctx); ok {
		in.CreatedBy = principal.Username
	}
	_ = decodeArg(args["evidence"], &in.Evidence)
	_ = decodeArg(args["findings"], &in.Findings)
	_ = decodeArg(args["timeline"], &in.Timeline)
	_ = decodeArg(args["artifacts"], &in.Artifacts)
	return in, nil
}

func decodeArg(v interface{}, out interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
