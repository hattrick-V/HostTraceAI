package builtin

// 内置工具名称常量
// 所有代码中使用内置工具名称的地方都应该使用这些常量，而不是硬编码字符串
const (
	// 漏洞管理工具
	ToolRecordVulnerability = "record_vulnerability"
	ToolListVulnerabilities = "list_vulnerabilities"
	ToolGetVulnerability    = "get_vulnerability"

	// 主机溯源结构化结果工具
	ToolRecordTraceResult = "record_trace_result"

	// 资产管理工具
	ToolCreateAsset       = "create_asset"
	ToolGetAsset          = "get_asset"
	ToolQueryAssets       = "query_assets"
	ToolUpdateAsset       = "update_asset"
	ToolDeleteAsset       = "delete_asset"
	ToolCompleteAssetScan = "complete_asset_scan"

	// 项目黑板（事实）工具
	ToolUpsertProjectFact    = "upsert_project_fact"
	ToolGetProjectFact       = "get_project_fact"
	ToolListProjectFacts     = "list_project_facts"
	ToolSearchProjectFacts   = "search_project_facts"
	ToolDeprecateProjectFact = "deprecate_project_fact"
	ToolRestoreProjectFact   = "restore_project_fact"

	// 知识库工具
	ToolListKnowledgeRiskTypes = "list_knowledge_risk_types"
	ToolSearchKnowledgeBase    = "search_knowledge_base"

	// 视觉分析（本地图片 → VL 模型 → 文本摘要）
	ToolAnalyzeImage = "analyze_image"

	// 长耗时工具执行控制（后台 execution 查询/等待/取消）
	ToolGetToolExecution    = "get_tool_execution"
	ToolWaitToolExecution   = "wait_tool_execution"
	ToolCancelToolExecution = "cancel_tool_execution"

	// 批量任务队列（与 Web 端批量任务一致，供模型创建/启停/查询队列）
	ToolBatchTaskList            = "batch_task_list"
	ToolBatchTaskGet             = "batch_task_get"
	ToolBatchTaskCreate          = "batch_task_create"
	ToolBatchTaskStart           = "batch_task_start"
	ToolBatchTaskRerun           = "batch_task_rerun"
	ToolBatchTaskPause           = "batch_task_pause"
	ToolBatchTaskDelete          = "batch_task_delete"
	ToolBatchTaskUpdateMetadata  = "batch_task_update_metadata"
	ToolBatchTaskUpdateSchedule  = "batch_task_update_schedule"
	ToolBatchTaskScheduleEnabled = "batch_task_schedule_enabled"
	ToolBatchTaskAdd             = "batch_task_add_task"
	ToolBatchTaskUpdate          = "batch_task_update_task"
	ToolBatchTaskRemove          = "batch_task_remove_task"
)

// IsBuiltinTool 检查工具名称是否是内置工具
func IsBuiltinTool(toolName string) bool {
	switch toolName {
	case ToolRecordVulnerability,
		ToolListVulnerabilities,
		ToolGetVulnerability,
		ToolRecordTraceResult,
		ToolCreateAsset,
		ToolGetAsset,
		ToolQueryAssets,
		ToolUpdateAsset,
		ToolDeleteAsset,
		ToolCompleteAssetScan,
		ToolUpsertProjectFact,
		ToolGetProjectFact,
		ToolListProjectFacts,
		ToolSearchProjectFacts,
		ToolDeprecateProjectFact,
		ToolRestoreProjectFact,
		ToolListKnowledgeRiskTypes,
		ToolSearchKnowledgeBase,
		ToolAnalyzeImage,
		ToolGetToolExecution,
		ToolWaitToolExecution,
		ToolCancelToolExecution,
		ToolBatchTaskList,
		ToolBatchTaskGet,
		ToolBatchTaskCreate,
		ToolBatchTaskStart,
		ToolBatchTaskRerun,
		ToolBatchTaskPause,
		ToolBatchTaskDelete,
		ToolBatchTaskUpdateMetadata,
		ToolBatchTaskUpdateSchedule,
		ToolBatchTaskScheduleEnabled,
		ToolBatchTaskAdd,
		ToolBatchTaskUpdate,
		ToolBatchTaskRemove:
		return true
	default:
		return false
	}
}

// GetAllBuiltinTools 返回所有内置工具名称列表
func GetAllBuiltinTools() []string {
	return []string{
		ToolRecordVulnerability,
		ToolListVulnerabilities,
		ToolGetVulnerability,
		ToolRecordTraceResult,
		ToolCreateAsset,
		ToolGetAsset,
		ToolQueryAssets,
		ToolUpdateAsset,
		ToolDeleteAsset,
		ToolCompleteAssetScan,
		ToolUpsertProjectFact,
		ToolGetProjectFact,
		ToolListProjectFacts,
		ToolSearchProjectFacts,
		ToolDeprecateProjectFact,
		ToolRestoreProjectFact,
		ToolListKnowledgeRiskTypes,
		ToolSearchKnowledgeBase,
		ToolAnalyzeImage,
		ToolGetToolExecution,
		ToolWaitToolExecution,
		ToolCancelToolExecution,
		ToolBatchTaskList,
		ToolBatchTaskGet,
		ToolBatchTaskCreate,
		ToolBatchTaskStart,
		ToolBatchTaskRerun,
		ToolBatchTaskPause,
		ToolBatchTaskDelete,
		ToolBatchTaskUpdateMetadata,
		ToolBatchTaskUpdateSchedule,
		ToolBatchTaskScheduleEnabled,
		ToolBatchTaskAdd,
		ToolBatchTaskUpdate,
		ToolBatchTaskRemove,
	}
}
