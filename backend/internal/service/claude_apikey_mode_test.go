package service

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"net/http"
	"testing"
)

func TestClaudeCodeAPIKeyMode(t *testing.T) {
	a := &Account{Platform: PlatformAnthropic, Type: AccountTypeOAuth, Credentials: map[string]any{"auth_mode": "apikey", "api_key": "upstream-test-key", "base_url": "https://provider.example"}}
	if !a.IsClaudeCodeAPIKey() || !a.IsOAuth() || a.CanGetUsage() {
		t.Fatal("incorrect Claude Code account capabilities")
	}
	if a.GetBaseURL() != "https://provider.example" {
		t.Fatal("wrong upstream base URL")
	}
	s := &GatewayService{}
	token, kind, err := s.GetAccessToken(context.Background(), a)
	if err != nil || token != "upstream-test-key" || kind != "oauth" {
		t.Fatal("API key must retain the OAuth protocol path", kind, err)
	}
	provider := &ClaudeTokenProvider{}
	if value, err := provider.GetAccessToken(context.Background(), a); err != nil || value != token {
		t.Fatal("provider tried OAuth refresh", err)
	}
	if (&ClaudeTokenRefresher{}).CanRefresh(a) {
		t.Fatal("API keys must never refresh")
	}
	headers := http.Header{"Anthropic-Ratelimit-Unified-5h-Status": []string{"allowed"}}
	(&RateLimitService{}).UpdateSessionWindow(context.Background(), a, headers)
	if a.SessionWindowStart != nil {
		t.Fatal("API key account acquired an OAuth usage window")
	}
	delete(a.Credentials, "api_key")
	if _, _, err := s.GetAccessToken(context.Background(), a); err == nil {
		t.Fatal("missing key accepted")
	}
	a.Credentials["auth_mode"] = "oauth"
	if a.IsClaudeCodeAPIKey() || !a.CanGetUsage() {
		t.Fatal("normal OAuth behavior changed")
	}
}

func TestClaudeCodeAPIKeyWireAuthentication(t *testing.T) {
	a := &Account{Platform: PlatformAnthropic, Type: AccountTypeOAuth, Credentials: map[string]any{"auth_mode": "apikey", "api_key": "test-key", "base_url": "https://provider.example"}}
	s := &GatewayService{cfg: &config.Config{}}
	body := []byte(`{"model":"claude-opus-5-5","messages":[{"role":"user","content":"hello"}]}`)
	req, _, err := s.buildUpstreamRequest(context.Background(), nil, a, body, "test-key", "oauth", "claude-opus-5-5", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Host != "provider.example" || getHeaderRaw(req.Header, "x-api-key") != "test-key" || getHeaderRaw(req.Header, "authorization") != "" {
		t.Fatal("incorrect API key wire authentication")
	}
	if getHeaderRaw(req.Header, "x-app") != "cli" {
		t.Fatal("Claude Code headers not applied")
	}
	req, _, err = s.buildCountTokensRequest(context.Background(), nil, a, body, "test-key", "oauth", "claude-opus-5-5", true)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Host != "provider.example" || getHeaderRaw(req.Header, "x-api-key") != "test-key" || getHeaderRaw(req.Header, "authorization") != "" {
		t.Fatal("incorrect count_tokens authentication")
	}
}
