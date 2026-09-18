package app

import (
	"hosttrace-ai/internal/config"
	"hosttrace-ai/internal/mcp"
	"hosttrace-ai/internal/vision"

	"go.uber.org/zap"
)

func registerVisionTools(mcpServer *mcp.Server, cfg *config.Config, logger *zap.Logger) {
	vision.RegisterAnalyzeImageTool(mcpServer, cfg, logger)
}
