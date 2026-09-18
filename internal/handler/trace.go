package handler

import (
	"net/http"
	"strconv"

	"hosttrace-ai/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type TraceHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewTraceHandler(db *database.DB, logger *zap.Logger) *TraceHandler {
	return &TraceHandler{db: db, logger: logger}
}

func (h *TraceHandler) DashboardSummary(c *gin.Context) {
	limit := 10
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 50 {
			limit = n
		}
	}
	summary, err := h.db.GetTraceDashboardSummary(limit)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("获取溯源仪表盘摘要失败", zap.Error(err))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取溯源仪表盘摘要失败"})
		return
	}
	c.JSON(http.StatusOK, summary)
}
