package database

// HostTraceAI 溯源领域表。它们与原有漏洞和攻击链表分离，
// 保留同一套 SQLite 迁移机制，避免把溯源证据误建模成漏洞或攻击记录。

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type TraceHost struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Address       string     `json:"address"`
	OSFamily      string     `json:"osFamily"`
	Transport     string     `json:"transport"`
	CredentialRef string     `json:"credentialRef,omitempty"`
	Status        string     `json:"status"`
	Tags          []string   `json:"tags,omitempty"`
	LastSeenAt    *time.Time `json:"lastSeenAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

type TraceTask struct {
	ID                  string    `json:"id"`
	HostID              string    `json:"hostId"`
	ConversationID      string    `json:"conversationId,omitempty"`
	ProjectID           string    `json:"projectId,omitempty"`
	Title               string    `json:"title"`
	Symptom             string    `json:"symptom"`
	SuspiciousIndicator string    `json:"suspiciousIndicator"`
	Expert              string    `json:"expert"`
	Status              string    `json:"status"`
	Mode                string    `json:"mode"`
	Conclusion          string    `json:"conclusion"`
	CreatedBy           string    `json:"createdBy"`
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

type TraceEvidenceInput struct {
	Category   string `json:"category"`
	Name       string `json:"name"`
	Content    string `json:"content"`
	SHA256     string `json:"sha256"`
	SourceTool string `json:"sourceTool"`
}

type TraceFindingInput struct {
	Kind       string                 `json:"kind"`
	Title      string                 `json:"title"`
	Severity   string                 `json:"severity"`
	Confidence float64                `json:"confidence"`
	Status     string                 `json:"status"`
	Details    map[string]interface{} `json:"details"`
}

type TraceTimelineInput struct {
	Actor     string `json:"actor"`
	EventType string `json:"eventType"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Severity  string `json:"severity"`
}

type TraceArtifactInput struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
	MimeType  string `json:"mimeType"`
}

type TraceRecordInput struct {
	HostAddress         string
	HostName            string
	OSFamily            string
	Transport           string
	Tags                []string
	ConversationID      string
	ProjectID           string
	TaskTitle           string
	Symptom             string
	SuspiciousIndicator string
	Expert              string
	Status              string
	Mode                string
	Conclusion          string
	CreatedBy           string
	Evidence            []TraceEvidenceInput
	Findings            []TraceFindingInput
	Timeline            []TraceTimelineInput
	Artifacts           []TraceArtifactInput
}

type TraceRecordResult struct {
	HostID        string `json:"hostId"`
	TaskID        string `json:"taskId"`
	FindingsCount int    `json:"findingsCount"`
	EvidenceCount int    `json:"evidenceCount"`
	TimelineCount int    `json:"timelineCount"`
	ArtifactCount int    `json:"artifactCount"`
}

type TraceDashboardFinding struct {
	ID        string    `json:"id"`
	TaskID    string    `json:"taskId"`
	HostID    string    `json:"hostId"`
	HostName  string    `json:"hostName"`
	Address   string    `json:"address"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

type TraceDashboardTimeline struct {
	ID        string    `json:"id"`
	TaskID    string    `json:"taskId"`
	HostID    string    `json:"hostId"`
	Address   string    `json:"address"`
	Actor     string    `json:"actor"`
	EventType string    `json:"eventType"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	CreatedAt time.Time `json:"createdAt"`
}

type TraceDashboardSummary struct {
	HostCount      int                      `json:"hostCount"`
	TaskCount      int                      `json:"taskCount"`
	FindingCount   int                      `json:"findingCount"`
	EvidenceCount  int                      `json:"evidenceCount"`
	ArtifactCount  int                      `json:"artifactCount"`
	BySeverity     map[string]int           `json:"bySeverity"`
	ByStatus       map[string]int           `json:"byStatus"`
	RecentFindings []TraceDashboardFinding  `json:"recentFindings"`
	RecentTimeline []TraceDashboardTimeline `json:"recentTimeline"`
	UpdatedAt      time.Time                `json:"updatedAt"`
}

func (db *DB) initTraceTables() error {
	statements := map[string]string{
		"trace_hosts": `CREATE TABLE IF NOT EXISTS trace_hosts (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL,
			os_family TEXT NOT NULL DEFAULT 'unknown', transport TEXT NOT NULL DEFAULT 'ssh',
			credential_ref TEXT, status TEXT NOT NULL DEFAULT 'active', tags_json TEXT NOT NULL DEFAULT '[]',
			last_seen_at DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL
		);`,
		"trace_tasks": `CREATE TABLE IF NOT EXISTS trace_tasks (
			id TEXT PRIMARY KEY, host_id TEXT NOT NULL, title TEXT NOT NULL,
			conversation_id TEXT NOT NULL DEFAULT '', project_id TEXT NOT NULL DEFAULT '',
			symptom TEXT NOT NULL DEFAULT '', suspicious_indicator TEXT NOT NULL DEFAULT '',
			expert TEXT NOT NULL DEFAULT 'commander', status TEXT NOT NULL DEFAULT 'queued',
			mode TEXT NOT NULL DEFAULT 'interactive', conclusion TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL,
			FOREIGN KEY(host_id) REFERENCES trace_hosts(id)
		);`,
		"trace_evidence": `CREATE TABLE IF NOT EXISTS trace_evidence (
			id TEXT PRIMARY KEY, task_id TEXT NOT NULL, host_id TEXT NOT NULL,
			category TEXT NOT NULL, name TEXT NOT NULL, content TEXT NOT NULL DEFAULT '',
			sha256 TEXT NOT NULL DEFAULT '', source_tool TEXT NOT NULL DEFAULT '',
			collected_at DATETIME NOT NULL, FOREIGN KEY(task_id) REFERENCES trace_tasks(id),
			FOREIGN KEY(host_id) REFERENCES trace_hosts(id)
		);`,
		"trace_findings": `CREATE TABLE IF NOT EXISTS trace_findings (
			id TEXT PRIMARY KEY, task_id TEXT NOT NULL, host_id TEXT NOT NULL,
			kind TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium',
			confidence REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'open',
			details_json TEXT NOT NULL DEFAULT '{}', created_at DATETIME NOT NULL,
			FOREIGN KEY(task_id) REFERENCES trace_tasks(id), FOREIGN KEY(host_id) REFERENCES trace_hosts(id)
		);`,
		"trace_artifacts": `CREATE TABLE IF NOT EXISTS trace_artifacts (
			id TEXT PRIMARY KEY, task_id TEXT NOT NULL, host_id TEXT NOT NULL,
			name TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL DEFAULT '',
			size_bytes INTEGER NOT NULL DEFAULT 0, mime_type TEXT NOT NULL DEFAULT '',
			retention_until DATETIME, created_at DATETIME NOT NULL,
			FOREIGN KEY(task_id) REFERENCES trace_tasks(id), FOREIGN KEY(host_id) REFERENCES trace_hosts(id)
		);`,
		"trace_timeline": `CREATE TABLE IF NOT EXISTS trace_timeline (
			id TEXT PRIMARY KEY, task_id TEXT NOT NULL, actor TEXT NOT NULL,
			event_type TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
			severity TEXT NOT NULL DEFAULT 'info', created_at DATETIME NOT NULL,
			FOREIGN KEY(task_id) REFERENCES trace_tasks(id)
		);`,
		"trace_actions": `CREATE TABLE IF NOT EXISTS trace_actions (
			id TEXT PRIMARY KEY, task_id TEXT NOT NULL, host_id TEXT NOT NULL,
			action TEXT NOT NULL, arguments_json TEXT NOT NULL DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'pending_approval', requested_by TEXT NOT NULL DEFAULT '',
			approved_by TEXT, result_json TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL, completed_at DATETIME,
			FOREIGN KEY(task_id) REFERENCES trace_tasks(id), FOREIGN KEY(host_id) REFERENCES trace_hosts(id)
		);`,
	}
	for name, ddl := range statements {
		if _, err := db.Exec(ddl); err != nil {
			return fmt.Errorf("创建%s失败: %w", name, err)
		}
	}
	for _, col := range []struct {
		name string
		stmt string
	}{
		{"conversation_id", "ALTER TABLE trace_tasks ADD COLUMN conversation_id TEXT NOT NULL DEFAULT ''"},
		{"project_id", "ALTER TABLE trace_tasks ADD COLUMN project_id TEXT NOT NULL DEFAULT ''"},
	} {
		if err := db.addColumnIfMissing("trace_tasks", col.name, col.stmt); err != nil {
			return err
		}
	}
	const indexes = `CREATE INDEX IF NOT EXISTS idx_trace_hosts_address ON trace_hosts(address);
		CREATE INDEX IF NOT EXISTS idx_trace_hosts_status ON trace_hosts(status);
		CREATE INDEX IF NOT EXISTS idx_trace_tasks_host ON trace_tasks(host_id);
		CREATE INDEX IF NOT EXISTS idx_trace_tasks_conversation ON trace_tasks(conversation_id);
		CREATE INDEX IF NOT EXISTS idx_trace_tasks_project ON trace_tasks(project_id);
		CREATE INDEX IF NOT EXISTS idx_trace_tasks_status ON trace_tasks(status);
		CREATE INDEX IF NOT EXISTS idx_trace_tasks_updated ON trace_tasks(updated_at);
		CREATE INDEX IF NOT EXISTS idx_trace_evidence_task ON trace_evidence(task_id);
		CREATE INDEX IF NOT EXISTS idx_trace_findings_task ON trace_findings(task_id);
		CREATE INDEX IF NOT EXISTS idx_trace_artifacts_task ON trace_artifacts(task_id);
		CREATE INDEX IF NOT EXISTS idx_trace_timeline_task ON trace_timeline(task_id);
		CREATE INDEX IF NOT EXISTS idx_trace_actions_task ON trace_actions(task_id);`
	if _, err := db.Exec(indexes); err != nil {
		return fmt.Errorf("创建trace索引失败: %w", err)
	}
	return nil
}

func (db *DB) RecordTraceResult(in TraceRecordInput) (*TraceRecordResult, error) {
	address := strings.TrimSpace(in.HostAddress)
	if address == "" {
		return nil, fmt.Errorf("host address is required")
	}
	now := time.Now().UTC()
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	host, err := upsertTraceHostTx(tx, in, now)
	if err != nil {
		return nil, err
	}
	taskID := "trace_task_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	title := strings.TrimSpace(in.TaskTitle)
	if title == "" {
		title = "主机溯源：" + address
	}
	status := cleanTraceStatus(in.Status)
	if status == "" {
		status = "completed"
	}
	expert := strings.TrimSpace(in.Expert)
	if expert == "" {
		expert = "commander"
	}
	mode := strings.TrimSpace(in.Mode)
	if mode == "" {
		mode = "interactive"
	}
	if _, err := tx.Exec(`INSERT INTO trace_tasks
		(id, host_id, conversation_id, project_id, title, symptom, suspicious_indicator, expert, status, mode, conclusion, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		taskID, host.ID, strings.TrimSpace(in.ConversationID), strings.TrimSpace(in.ProjectID), title, strings.TrimSpace(in.Symptom),
		strings.TrimSpace(in.SuspiciousIndicator), expert, status, mode, strings.TrimSpace(in.Conclusion), strings.TrimSpace(in.CreatedBy), now, now,
	); err != nil {
		return nil, err
	}

	result := &TraceRecordResult{HostID: host.ID, TaskID: taskID}
	for _, ev := range in.Evidence {
		if strings.TrimSpace(ev.Name) == "" && strings.TrimSpace(ev.Content) == "" {
			continue
		}
		cat := strings.TrimSpace(ev.Category)
		if cat == "" {
			cat = "note"
		}
		if _, err := tx.Exec(`INSERT INTO trace_evidence
			(id, task_id, host_id, category, name, content, sha256, source_tool, collected_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"trace_ev_"+strings.ReplaceAll(uuid.New().String(), "-", ""), taskID, host.ID, cat, strings.TrimSpace(ev.Name),
			strings.TrimSpace(ev.Content), strings.TrimSpace(ev.SHA256), strings.TrimSpace(ev.SourceTool), now,
		); err != nil {
			return nil, err
		}
		result.EvidenceCount++
	}
	for _, f := range in.Findings {
		title := strings.TrimSpace(f.Title)
		if title == "" {
			continue
		}
		sev := cleanTraceSeverity(f.Severity)
		if sev == "" {
			sev = "medium"
		}
		st := cleanTraceStatus(f.Status)
		if st == "" {
			st = "open"
		}
		kind := strings.TrimSpace(f.Kind)
		if kind == "" {
			kind = "finding"
		}
		conf := f.Confidence
		if conf < 0 {
			conf = 0
		}
		if conf > 1 {
			conf = 1
		}
		details, _ := json.Marshal(f.Details)
		if len(details) == 0 || string(details) == "null" {
			details = []byte("{}")
		}
		if _, err := tx.Exec(`INSERT INTO trace_findings
			(id, task_id, host_id, kind, title, severity, confidence, status, details_json, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"trace_finding_"+strings.ReplaceAll(uuid.New().String(), "-", ""), taskID, host.ID, kind, title, sev, conf, st, string(details), now,
		); err != nil {
			return nil, err
		}
		result.FindingsCount++
	}
	for _, item := range in.Timeline {
		title := strings.TrimSpace(item.Title)
		if title == "" {
			continue
		}
		actor := strings.TrimSpace(item.Actor)
		if actor == "" {
			actor = "unknown"
		}
		eventType := strings.TrimSpace(item.EventType)
		if eventType == "" {
			eventType = "observation"
		}
		sev := cleanTraceSeverity(item.Severity)
		if sev == "" {
			sev = "info"
		}
		if _, err := tx.Exec(`INSERT INTO trace_timeline
			(id, task_id, actor, event_type, title, detail, severity, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			"trace_tl_"+strings.ReplaceAll(uuid.New().String(), "-", ""), taskID, actor, eventType, title, strings.TrimSpace(item.Detail), sev, now,
		); err != nil {
			return nil, err
		}
		result.TimelineCount++
	}
	for _, art := range in.Artifacts {
		if strings.TrimSpace(art.Path) == "" && strings.TrimSpace(art.Name) == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO trace_artifacts
			(id, task_id, host_id, name, path, sha256, size_bytes, mime_type, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"trace_art_"+strings.ReplaceAll(uuid.New().String(), "-", ""), taskID, host.ID, strings.TrimSpace(art.Name),
			strings.TrimSpace(art.Path), strings.TrimSpace(art.SHA256), art.SizeBytes, strings.TrimSpace(art.MimeType), now,
		); err != nil {
			return nil, err
		}
		result.ArtifactCount++
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func upsertTraceHostTx(tx *sql.Tx, in TraceRecordInput, now time.Time) (*TraceHost, error) {
	address := strings.TrimSpace(in.HostAddress)
	name := strings.TrimSpace(in.HostName)
	if name == "" {
		name = address
	}
	osFamily := strings.TrimSpace(in.OSFamily)
	if osFamily == "" {
		osFamily = "unknown"
	}
	transport := strings.TrimSpace(in.Transport)
	if transport == "" {
		transport = "ssh"
	}
	tags, _ := json.Marshal(in.Tags)
	var existingID string
	err := tx.QueryRow(`SELECT id FROM trace_hosts WHERE address = ? ORDER BY updated_at DESC LIMIT 1`, address).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if existingID == "" {
		existingID = "trace_host_" + strings.ReplaceAll(uuid.New().String(), "-", "")
		if _, err := tx.Exec(`INSERT INTO trace_hosts
			(id, name, address, os_family, transport, credential_ref, status, tags_json, last_seen_at, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, '', 'active', ?, ?, ?, ?)`,
			existingID, name, address, osFamily, transport, string(tags), now, now, now,
		); err != nil {
			return nil, err
		}
	} else {
		if _, err := tx.Exec(`UPDATE trace_hosts SET name = ?, os_family = ?, transport = ?, tags_json = ?, last_seen_at = ?, updated_at = ? WHERE id = ?`,
			name, osFamily, transport, string(tags), now, now, existingID,
		); err != nil {
			return nil, err
		}
	}
	return &TraceHost{ID: existingID, Name: name, Address: address, OSFamily: osFamily, Transport: transport, Tags: in.Tags, LastSeenAt: &now, CreatedAt: now, UpdatedAt: now}, nil
}

func cleanTraceSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return ""
	}
}

func cleanTraceStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "open", "confirmed", "contained", "remediated", "fixed", "false_positive", "ignored", "queued", "running", "completed", "failed":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func (db *DB) GetTraceDashboardSummary(limit int) (*TraceDashboardSummary, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	out := &TraceDashboardSummary{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
		UpdatedAt:  time.Now().UTC(),
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM trace_hosts`).Scan(&out.HostCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM trace_tasks`).Scan(&out.TaskCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM trace_findings`).Scan(&out.FindingCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM trace_evidence`).Scan(&out.EvidenceCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM trace_artifacts`).Scan(&out.ArtifactCount)
	if rows, err := db.Query(`SELECT severity, COUNT(*) FROM trace_findings GROUP BY severity`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int
			if rows.Scan(&k, &n) == nil {
				out.BySeverity[k] = n
			}
		}
	}
	if rows, err := db.Query(`SELECT status, COUNT(*) FROM trace_findings GROUP BY status`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int
			if rows.Scan(&k, &n) == nil {
				out.ByStatus[k] = n
			}
		}
	}
	rows, err := db.Query(`SELECT f.id, f.task_id, f.host_id, h.name, h.address, f.kind, f.title, f.severity, f.status, f.created_at
		FROM trace_findings f JOIN trace_hosts h ON h.id = f.host_id
		ORDER BY f.created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item TraceDashboardFinding
		if rows.Scan(&item.ID, &item.TaskID, &item.HostID, &item.HostName, &item.Address, &item.Kind, &item.Title, &item.Severity, &item.Status, &item.CreatedAt) == nil {
			out.RecentFindings = append(out.RecentFindings, item)
		}
	}
	rows.Close()

	tRows, err := db.Query(`SELECT tl.id, tl.task_id, t.host_id, h.address, tl.actor, tl.event_type, tl.title, tl.severity, tl.created_at
		FROM trace_timeline tl JOIN trace_tasks t ON t.id = tl.task_id JOIN trace_hosts h ON h.id = t.host_id
		ORDER BY tl.created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer tRows.Close()
	for tRows.Next() {
		var item TraceDashboardTimeline
		if tRows.Scan(&item.ID, &item.TaskID, &item.HostID, &item.Address, &item.Actor, &item.EventType, &item.Title, &item.Severity, &item.CreatedAt) == nil {
			out.RecentTimeline = append(out.RecentTimeline, item)
		}
	}
	return out, nil
}
