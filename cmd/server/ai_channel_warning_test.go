package main

import (
	"testing"

	"hosttrace-ai/internal/config"
	"hosttrace-ai/internal/logger"
)

func TestWarnIncompleteAIChannelDoesNotPanic(t *testing.T) {
	log := logger.New("info", "stdout")
	defer func() { _ = log.Close() }()

	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{"nil config", nil},
		{"no channels", &config.Config{}},
		{"placeholder channel", &config.Config{
			AI: config.AIConfig{
				DefaultChannel: "default",
				Channels: map[string]config.AIChannelConfig{
					"default": {BaseURL: "https://api.example.com/v1"},
				},
			},
		}},
		{"complete channel", &config.Config{
			AI: config.AIConfig{
				DefaultChannel: "default",
				Channels: map[string]config.AIChannelConfig{
					"default": {BaseURL: "https://api.openai.com/v1", APIKey: "sk-x", Model: "gpt-4o"},
				},
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warnIncompleteAIChannel(tc.cfg, log)
		})
	}
}
