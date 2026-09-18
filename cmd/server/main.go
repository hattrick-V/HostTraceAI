package main

import (
	"context"
	"flag"
	"fmt"
	"hosttrace-ai/internal/app"
	"hosttrace-ai/internal/config"
	"hosttrace-ai/internal/database"
	"hosttrace-ai/internal/logger"
	"hosttrace-ai/internal/security"
	"hosttrace-ai/internal/termout"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"go.uber.org/zap"
	"golang.org/x/term"
)

func main() {
	var configPath = flag.String("config", "config.yaml", "Path to the configuration file")
	var httpsBootstrap = flag.Bool("https", false, "Enable HTTPS for the main site; uses an in-memory self-signed certificate when no cert/key is configured")
	var httpBootstrap = flag.Bool("http", false, "Force plain HTTP for the main site, overriding TLS settings in the configuration file")
	var resetAdminPassword = flag.Bool("reset-admin-password", false, "Interactively reset the built-in admin password and exit")
	var portOverride = flag.Int("port", 0, "Override the Web/API listening port (1024-65535)")
	flag.Parse()

	// 环境变量兼容（便于 systemd/docker 等不传参场景）
	if *httpsBootstrap && *httpBootstrap {
		fmt.Fprintln(os.Stderr, "--http and --https cannot be used together")
		os.Exit(2)
	}
	if !*httpsBootstrap && !*httpBootstrap {
		v := strings.TrimSpace(os.Getenv("HOSTTRACE_HTTPS"))
		if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
			*httpsBootstrap = true
		}
	}

	// 加载配置
	cp := strings.TrimSpace(*configPath)
	if cp == "" {
		cp = "config.yaml"
	}
	if strings.HasPrefix(cp, "-") {
		fmt.Fprintf(os.Stderr, "Invalid -config path %q.\nIf HTTPS is also needed, use: ./hosttrace-ai --https -config config.yaml (-config must be followed by a yaml file path).\n", cp)
		os.Exit(2)
	}
	localConfig, err := config.EnsureLocalConfig(cp)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		return
	}

	cfg, err := config.Load(cp)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		return
	}
	if localConfig.Created {
		termout.PrintConfigCreated()
	}

	if *resetAdminPassword {
		if err := runResetAdminPassword(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to reset admin password: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *httpBootstrap {
		config.ApplyPlainHTTPBootstrap(cfg)
	} else if *httpsBootstrap {
		config.ApplyDevHTTPSBootstrap(cfg)
	}

	port := cfg.Server.Port
	if envPort := strings.TrimSpace(os.Getenv("HOSTTRACE_PORT")); envPort != "" {
		parsed, parseErr := strconv.Atoi(envPort)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "Invalid HOSTTRACE_PORT %q: %v\n", envPort, parseErr)
			os.Exit(2)
		}
		port = parsed
	}
	if *portOverride > 0 {
		port = *portOverride
	}
	if port <= 0 {
		port = 9088
	}
	if port < 1024 || port > 65535 {
		fmt.Fprintf(os.Stderr, "Invalid Web/API port %d; choose a value between 1024 and 65535\n", port)
		os.Exit(2)
	}
	// 让后续应用组件（包括工具描述中的服务端口）使用最终端口。
	cfg.Server.Port = port
	scheme := "http"
	if config.MainWebUIUsesHTTPS(&cfg.Server) {
		scheme = "https"
	}
	termout.PrintStartupWebUI(termout.StartupWebUIOptions{
		Scheme:       scheme,
		Port:         port,
		SelfSigned:   scheme == "https" && cfg.Server.TLSAutoSelfSign,
		HTTPRedirect: scheme == "https" && config.ServerHTTPRedirectEnabled(&cfg.Server),
	})

	// MCP 启用且 auth_header_value 为空时，自动生成随机密钥并写回配置
	if err := config.EnsureMCPAuth(cp, cfg); err != nil {
		fmt.Printf("Failed to configure MCP authentication: %v\n", err)
		return
	}
	if cfg.MCP.Enabled {
		config.PrintMCPConfigJSON(cfg.MCP)
	}

	// 初始化日志
	log := logger.New(cfg.Log.Level, cfg.Log.Output, logger.DiagnosticOptions{
		Dir:           cfg.Log.DiagnosticDir,
		Disabled:      cfg.Log.DiagnosticDisabled,
		RetentionDays: cfg.Log.DiagnosticRetentionDays,
	})
	defer log.Sync()
	defer log.Close()

	// 开箱体检：AI 通道没填时明确告警，避免用户面对"能启动但聊不动"的静默失败。
	warnIncompleteAIChannel(cfg, log)

	// 创建可取消的根 context，用于优雅关闭
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 监听系统信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 创建应用
	application, err := app.New(cfg, log, cp)
	if err != nil {
		log.Fatal("应用初始化失败", "error", err)
	}

	// 在后台监听信号
	go func() {
		sig := <-sigCh
		log.Info("收到系统信号，开始优雅关闭: " + sig.String())
		application.Shutdown()
		cancel()
	}()

	// 启动服务器（传入 context 以支持优雅关闭）
	if err := application.RunWithContext(ctx); err != nil {
		// context 取消导致的关闭不视为错误
		if ctx.Err() != nil {
			log.Info("服务器已优雅关闭")
		} else {
			log.Fatal("服务器启动失败", "error", err)
		}
	}
}

func runResetAdminPassword(cfg *config.Config) error {
	dbPath := strings.TrimSpace(cfg.Database.Path)
	if dbPath == "" {
		dbPath = "data/conversations.db"
	}
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("database does not exist: %s; start the service once to initialize it first", dbPath)
		}
		return err
	}

	fmt.Println("Reset built-in admin password")
	fmt.Println()

	password, err := readHiddenPassword("New admin password: ")
	if err != nil {
		return err
	}
	password = strings.TrimSpace(password)
	if len(password) < 8 {
		return fmt.Errorf("new password must be at least 8 characters")
	}
	confirm, err := readHiddenPassword("Confirm new password: ")
	if err != nil {
		return err
	}
	if password != strings.TrimSpace(confirm) {
		return fmt.Errorf("passwords do not match")
	}

	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}

	db, err := database.NewDB(dbPath, zap.NewNop())
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	admin, err := db.GetRBACUserByUsername("admin")
	if err != nil {
		return fmt.Errorf("built-in admin account was not found; start the service once to initialize it first: %w", err)
	}
	if !admin.IsBuiltin {
		return fmt.Errorf("admin account is not built in; refusing to reset it")
	}
	if err := db.UpdateRBACAdminPassword(hash); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Admin password has been reset.")
	fmt.Println("If the service is running, existing login sessions remain valid until the service restarts or the sessions expire.")
	return nil
}

func readHiddenPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// warnIncompleteAIChannel 在 AI 通道缺少必要字段时打印醒目提示。
// 平台在没有 AI 凭据时仍能启动（便于先做完初始化再进设置页填写），
// 但对话会不可用，因此这里必须让用户看得见原因。
func warnIncompleteAIChannel(cfg *config.Config, log *logger.Logger) {
	if cfg == nil {
		return
	}
	channelName := cfg.AI.DefaultChannel
	if strings.TrimSpace(channelName) == "" {
		channelName = "default"
	}
	channel, ok := cfg.AI.Channels[cfg.AI.DefaultChannel]
	if !ok {
		log.Warn("AI 通道未配置：默认通道 " + channelName + " 不存在，对话将不可用")
		return
	}

	var missing []string
	if strings.TrimSpace(channel.BaseURL) == "" {
		missing = append(missing, "base_url")
	}
	if strings.TrimSpace(channel.APIKey) == "" {
		missing = append(missing, "api_key")
	}
	if strings.TrimSpace(channel.Model) == "" {
		missing = append(missing, "model")
	}
	if len(missing) == 0 {
		return
	}

	log.Warn("AI 通道未配置完整，对话将不可用；缺少：" + strings.Join(missing, ", "))
	fmt.Println()
	fmt.Println("! AI channel is not configured yet -- conversations will not work.")
	fmt.Println("  Missing: " + strings.Join(missing, ", "))
	fmt.Println("  Sign in, then go to: Settings -> Basic Settings -> AI Channel")
	fmt.Println("  Or edit ai.channels." + cfg.AI.DefaultChannel + " in your config file and restart.")
	fmt.Println()
}
