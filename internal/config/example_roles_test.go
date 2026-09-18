package config

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestExampleConfigLoadsBuiltInRoles(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	cfg, err := Load(filepath.Join(repoRoot, "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load(config.example.yaml): %v", err)
	}

	for _, name := range []string{"溯源指挥官", "病毒木马溯源专家", "WebShell后门溯源专家"} {
		role, ok := cfg.Roles[name]
		if !ok {
			t.Fatalf("built-in role %q was not loaded", name)
		}
		if !role.Enabled {
			t.Fatalf("built-in role %q is not enabled", name)
		}
	}
}

func TestExampleConfigLoadsForensicTools(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	cfg, err := Load(filepath.Join(repoRoot, "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load(config.example.yaml): %v", err)
	}

	tools := make(map[string]bool, len(cfg.Security.Tools))
	for _, tool := range cfg.Security.Tools {
		if tool.Enabled {
			tools[tool.Name] = true
		}
	}

	// 只允许主机溯源类只读/取证工具。故意不包含 nmap、smbmap、enum4linux-ng 等
	// 漏洞扫描/横向移动工具，见 tools/README.md 的收录边界。
	for _, name := range []string{"exec", "strings", "exiftool", "binwalk", "foremost"} {
		if !tools[name] {
			t.Fatalf("forensic tool %q was not loaded and enabled", name)
		}
	}

	for _, name := range []string{"nmap", "smbmap", "enum4linux-ng"} {
		if tools[name] {
			t.Fatalf("offensive tool %q must not ship in the default tool catalog", name)
		}
	}
}
