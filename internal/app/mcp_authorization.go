package app

import (
	"context"
	"fmt"
	"strings"

	"hosttrace-ai/internal/agent"
	"hosttrace-ai/internal/authctx"
	"hosttrace-ai/internal/database"
	"hosttrace-ai/internal/mcp"
	"hosttrace-ai/internal/mcp/builtin"
)

func mcpToolAuthorizer(db *database.DB) func(context.Context, string, map[string]interface{}) error {
	return func(ctx context.Context, toolName string, args map[string]interface{}) error {
		principal, ok := authctx.PrincipalFromContext(ctx)
		if !ok {
			return fmt.Errorf("missing authenticated principal")
		}
		require := func(permission string) error {
			if !principal.HasPermission(permission) {
				return fmt.Errorf("missing permission %s", permission)
			}
			return nil
		}
		resource := func(permission, resourceType, argument string) error {
			if err := require(permission); err != nil {
				return err
			}
			id := mcpAuthorizationString(args, argument)
			if id == "" || db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor(permission), resourceType, id) {
				return fmt.Errorf("no access to %s %s", resourceType, id)
			}
			if err := authorizeMCPProjectResourceBoundary(ctx, db, resourceType, id); err != nil {
				return err
			}
			return nil
		}
		toolExecutionResource := func(permission string) error {
			if err := require(permission); err != nil {
				return err
			}
			id := mcpAuthorizationString(args, "execution_id")
			if id == "" || db == nil || !db.UserCanAccessToolExecution(principal.UserID, principal.ScopeFor(permission), id) {
				return fmt.Errorf("no access to tool execution %s", id)
			}
			return nil
		}

		switch toolName {
		case builtin.ToolRecordVulnerability:
			if err := require("vulnerability:write"); err != nil {
				return err
			}
			conversationID := mcpAuthorizationString(args, "conversation_id")
			if conversationID == "" {
				conversationID = mcpAuthorizationConversationID(ctx)
			}
			if conversationID == "" || db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("vulnerability:write"), "conversation", conversationID) {
				return fmt.Errorf("no access to conversation %s", conversationID)
			}
			return nil
		case builtin.ToolRecordTraceResult:
			if err := require("agent:execute"); err != nil {
				return err
			}
			conversationID := mcpAuthorizationString(args, "conversation_id")
			if conversationID == "" {
				conversationID = mcpAuthorizationConversationID(ctx)
			}
			if conversationID != "" && db != nil && !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("agent:execute"), "conversation", conversationID) {
				return fmt.Errorf("no access to conversation %s", conversationID)
			}
			return nil
		case builtin.ToolListVulnerabilities:
			if err := require("vulnerability:read"); err != nil {
				return err
			}
			conversationID := mcpAuthorizationConversationID(ctx)
			if conversationID == "" || db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("vulnerability:read"), "conversation", conversationID) {
				return fmt.Errorf("no access to conversation %s", conversationID)
			}
			return nil
		case builtin.ToolGetVulnerability:
			return resource("vulnerability:read", "vulnerability", "id")
		case builtin.ToolQueryAssets:
			return require("asset:read")
		case builtin.ToolGetAsset:
			return resource("asset:read", "asset", "id")
		case builtin.ToolCreateAsset:
			if err := require("asset:write"); err != nil {
				return err
			}
			if projectID := mcpAuthorizationString(args, "project_id"); projectID != "" && (db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("asset:write"), "project", projectID)) {
				return fmt.Errorf("no access to project %s", projectID)
			}
			return nil
		case builtin.ToolUpdateAsset, builtin.ToolCompleteAssetScan:
			if err := resource("asset:write", "asset", "id"); err != nil {
				return err
			}
			if toolName == builtin.ToolCompleteAssetScan {
				conversationID := mcpAuthorizationConversationID(ctx)
				if conversationID == "" || db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("asset:write"), "conversation", conversationID) {
					return fmt.Errorf("no access to conversation %s", conversationID)
				}
				return nil
			}
			if projectID := mcpAuthorizationString(args, "project_id"); projectID != "" && (db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("asset:write"), "project", projectID)) {
				return fmt.Errorf("no access to project %s", projectID)
			}
			return nil
		case builtin.ToolDeleteAsset:
			return resource("asset:delete", "asset", "id")
		case builtin.ToolUpsertProjectFact, builtin.ToolDeprecateProjectFact, builtin.ToolRestoreProjectFact:
			return authorizeProjectTool(ctx, principal, db, "project:write")
		case builtin.ToolGetProjectFact, builtin.ToolListProjectFacts, builtin.ToolSearchProjectFacts:
			return authorizeProjectTool(ctx, principal, db, "project:read")
		case builtin.ToolListKnowledgeRiskTypes, builtin.ToolSearchKnowledgeBase:
			return require("knowledge:read")
		case builtin.ToolAnalyzeImage:
			return require("agent:execute")
		case builtin.ToolGetToolExecution, builtin.ToolWaitToolExecution:
			return toolExecutionResource("monitor:read")
		case builtin.ToolCancelToolExecution:
			return toolExecutionResource("monitor:write")
		case builtin.ToolBatchTaskList:
			return require("tasks:read")
		case builtin.ToolBatchTaskGet:
			return resource("tasks:read", "batch_task", "queue_id")
		case builtin.ToolBatchTaskCreate:
			if err := require("tasks:write"); err != nil {
				return err
			}
			if projectID := mcpAuthorizationString(args, "project_id"); projectID != "" && (db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("tasks:write"), "project", projectID)) {
				return fmt.Errorf("no access to project %s", projectID)
			}
			return nil
		case builtin.ToolBatchTaskDelete, builtin.ToolBatchTaskRemove:
			return resource("tasks:delete", "batch_task", "queue_id")
		case builtin.ToolBatchTaskStart, builtin.ToolBatchTaskRerun, builtin.ToolBatchTaskPause,
			builtin.ToolBatchTaskUpdateMetadata, builtin.ToolBatchTaskUpdateSchedule,
			builtin.ToolBatchTaskScheduleEnabled, builtin.ToolBatchTaskAdd, builtin.ToolBatchTaskUpdate:
			return resource("tasks:write", "batch_task", "queue_id")
		default:
			if builtin.IsBuiltinTool(toolName) {
				return fmt.Errorf("no authorization policy registered for builtin tool %s", toolName)
			}
			if principal.HasPermission("agent:local-execute") {
				return nil
			}
			return fmt.Errorf("missing agent:local-execute")
		}
	}
}

func externalMCPToolAuthorizer() func(context.Context, string, map[string]interface{}) error {
	return func(ctx context.Context, toolName string, _ map[string]interface{}) error {
		principal, ok := authctx.PrincipalFromContext(ctx)
		if !ok {
			return fmt.Errorf("missing authenticated principal")
		}
		if !principal.HasPermission("mcp:external:execute") {
			return fmt.Errorf("missing permission mcp:external:execute")
		}
		if principal.ScopeFor("mcp:external:execute") != database.RBACScopeAll {
			return fmt.Errorf("external MCP invocation requires global scope")
		}
		if strings.TrimSpace(toolName) == "" {
			return fmt.Errorf("missing external tool name")
		}
		return nil
	}
}

func authorizeMCPProjectResourceBoundary(ctx context.Context, db *database.DB, resourceType, resourceID string) error {
	filter := mcpEffectiveProjectFilter(ctx, db)
	if filter == "" || db == nil {
		return nil
	}
	projectID, ok, err := mcpResourceProjectID(db, resourceType, resourceID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if filter == database.ProjectFilterUnbound {
		if projectID != "" {
			return fmt.Errorf("resource %s %s belongs to project %s, current conversation is unbound", resourceType, resourceID, projectID)
		}
		return nil
	}
	if projectID != filter {
		if projectID == "" {
			return fmt.Errorf("resource %s %s is unbound, current conversation project is %s", resourceType, resourceID, filter)
		}
		return fmt.Errorf("resource %s %s belongs to project %s, current conversation project is %s", resourceType, resourceID, projectID, filter)
	}
	return nil
}

func mcpResourceProjectID(db *database.DB, resourceType, resourceID string) (string, bool, error) {
	switch resourceType {
	default:
		return "", false, nil
	}
}

func authorizeProjectTool(ctx context.Context, principal authctx.Principal, db *database.DB, permission string) error {
	if !principal.HasPermission(permission) {
		return fmt.Errorf("missing permission %s", permission)
	}
	conversationID := mcpAuthorizationConversationID(ctx)
	if conversationID == "" || db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor(permission), "conversation", conversationID) {
		return fmt.Errorf("no access to conversation %s", conversationID)
	}
	projectID, err := db.GetConversationProjectID(conversationID)
	if err != nil {
		return fmt.Errorf("no access to project: %w", err)
	}
	if strings.TrimSpace(projectID) == "" {
		return fmt.Errorf("当前对话未绑定项目，无法使用项目黑板工具，请先在对话中选择项目或创建带项目的对话")
	}
	if !db.UserCanAccessResource(principal.UserID, principal.ScopeFor(permission), "project", projectID) {
		return fmt.Errorf("no access to project %s", projectID)
	}
	return nil
}

func mcpAuthorizationConversationID(ctx context.Context) string {
	if id := strings.TrimSpace(agent.ConversationIDFromContext(ctx)); id != "" {
		return id
	}
	return strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx))
}

func mcpAuthorizationString(args map[string]interface{}, key string) string {
	value, _ := args[key].(string)
	return strings.TrimSpace(value)
}
