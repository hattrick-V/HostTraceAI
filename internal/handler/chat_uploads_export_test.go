package handler

import (
	"strings"
	"testing"
	"time"
)

func TestChatUploadsExportFilenameUsesHostIP(t *testing.T) {
	filename := chatUploadsExportFilename(nil, "", "", "192.0.2.10")
	wantPrefix := time.Now().Format("20060102") + "+192.0.2.10"
	if filename != wantPrefix+".zip" {
		t.Fatalf("expected %q, got %q", wantPrefix+".zip", filename)
	}
}

func TestChatUploadsExportFilenameInfersSingleHostIP(t *testing.T) {
	files := []ChatUploadFileItem{
		{RelativePath: "__conversation_artifact__/conv/192.0.2.10/evidence/miner.exe"},
		{Name: "192.0.2.10-process.txt"},
	}
	filename := chatUploadsExportFilename(files, "", "", "")
	wantPrefix := time.Now().Format("20060102") + "+192.0.2.10"
	if filename != wantPrefix+".zip" {
		t.Fatalf("expected %q, got %q", wantPrefix+".zip", filename)
	}
}

func TestChatUploadsExportFilenameFallsBackWhenMultipleIPs(t *testing.T) {
	files := []ChatUploadFileItem{
		{RelativePath: "192.0.2.10/miner.exe"},
		{RelativePath: "198.51.100.8/script.sh"},
	}
	filename := chatUploadsExportFilename(files, "project-a", "", "")
	if strings.Contains(filename, "+192.0.2.10") || strings.Contains(filename, "+198.51.100.8") {
		t.Fatalf("expected fallback filename when multiple IPs are present, got %q", filename)
	}
	if !strings.HasPrefix(filename, "chat-files-project-project-a-") || !strings.HasSuffix(filename, ".zip") {
		t.Fatalf("unexpected fallback filename %q", filename)
	}
}
