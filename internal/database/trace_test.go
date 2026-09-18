package database

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestRecordTraceResultFeedsDashboardSummary(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "trace.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	result, err := db.RecordTraceResult(TraceRecordInput{
		HostAddress:         "192.0.2.10",
		HostName:            "win-host",
		OSFamily:            "windows",
		Transport:           "ssh",
		ConversationID:      "conv_demo",
		ProjectID:           "proj_demo",
		TaskTitle:           "Windows 主机挖矿溯源",
		Symptom:             "CPU 异常升高",
		SuspiciousIndicator: "异常矿池外联",
		Expert:              "malware-triage",
		Status:              "completed",
		Conclusion:          "确认存在挖矿程序与持久化脚本",
		CreatedBy:           "admin",
		Findings: []TraceFindingInput{{
			Kind:       "miner",
			Title:      "确认挖矿程序与计划任务持久化",
			Severity:   "high",
			Confidence: 0.95,
			Status:     "confirmed",
			Details: map[string]interface{}{
				"process": "miner.exe",
			},
		}},
		Evidence: []TraceEvidenceInput{{
			Category:   "hash",
			Name:       "miner.exe md5",
			Content:    "样本哈希与路径",
			SHA256:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			SourceTool: "record_trace_result",
		}},
		Timeline: []TraceTimelineInput{{
			Actor:     "attacker",
			EventType: "persistence",
			Title:     "创建计划任务",
			Detail:    "发现异常计划任务启动挖矿程序",
			Severity:  "high",
		}},
		Artifacts: []TraceArtifactInput{{
			Name:      "20260917+192.0.2.10.zip",
			Path:      "trace_archives/20260917+192.0.2.10.zip",
			SHA256:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			SizeBytes: 12345,
			MimeType:  "application/zip",
		}},
	})
	if err != nil {
		t.Fatalf("RecordTraceResult: %v", err)
	}
	if result.FindingsCount != 1 || result.EvidenceCount != 1 || result.TimelineCount != 1 || result.ArtifactCount != 1 {
		t.Fatalf("unexpected result counts: %+v", result)
	}

	summary, err := db.GetTraceDashboardSummary(10)
	if err != nil {
		t.Fatalf("GetTraceDashboardSummary: %v", err)
	}
	if summary.HostCount != 1 || summary.TaskCount != 1 || summary.FindingCount != 1 || summary.EvidenceCount != 1 || summary.ArtifactCount != 1 {
		t.Fatalf("unexpected summary counts: %+v", summary)
	}
	if summary.BySeverity["high"] != 1 || summary.ByStatus["confirmed"] != 1 {
		t.Fatalf("unexpected summary buckets: severity=%v status=%v", summary.BySeverity, summary.ByStatus)
	}
	if len(summary.RecentFindings) != 1 || summary.RecentFindings[0].Address != "192.0.2.10" {
		t.Fatalf("unexpected recent findings: %+v", summary.RecentFindings)
	}
	if len(summary.RecentTimeline) != 1 || summary.RecentTimeline[0].Title != "创建计划任务" {
		t.Fatalf("unexpected recent timeline: %+v", summary.RecentTimeline)
	}
}
