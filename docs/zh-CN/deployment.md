# 部署与配置

HostTraceAI 使用 HostTraceAI 验证过的 Go 服务启动方式和 YAML 配置。首次部署：

```bash
cp config.example.yaml config.yaml
go run ./cmd/server --config config.yaml
```

生产环境应启用 HTTPS、强管理员密码、内网访问控制和数据库定期备份。不要把 SSH 私钥或密码提交到配置文件。
