// Package oauth 只做一件事：Authorization Code 模式下拿 code 换 token、再读 userinfo。
// 不绑定任何具体厂商：端点、字段名都来自配置，GitHub / Keycloak / Authentik / Auth0 都能用。
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
)

var (
	ErrExchange = errors.New("oauth: 换取令牌失败")
	ErrUserinfo = errors.New("oauth: 读取用户信息失败")
)

type Client struct {
	cfg  config.OAuth
	http *http.Client
}

func New(cfg config.OAuth) *Client {
	timeout := cfg.Timeout.Duration
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: timeout}}
}

// AuthCodeURL 拼接授权地址。state 由调用方生成并服务端保存（一次性）。
func (c *Client) AuthCodeURL(state string) string {
	u, err := url.Parse(c.cfg.AuthorizeURL)
	if err != nil {
		return c.cfg.AuthorizeURL
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURI)
	q.Set("state", state)
	if len(c.cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Exchange 用 code 换 access_token。
func (c *Client) Exchange(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret)
	form.Set("redirect_uri", c.cfg.RedirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrExchange, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: HTTP %d", ErrExchange, resp.StatusCode)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.AccessToken == "" {
		return "", ErrExchange
	}
	return payload.AccessToken, nil
}

// Userinfo 读取用户信息（原样返回 JSON 对象，字段解析交给调用方）。
func (c *Client) Userinfo(ctx context.Context, token string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.UserinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserinfo, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrUserinfo, resp.StatusCode)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, ErrUserinfo
	}
	return out, nil
}

// Lookup 按点号路径取字段，例如 "sub"、"data.user.id"。
func Lookup(data map[string]any, path string) string {
	if path == "" {
		return ""
	}
	var cur any = data
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = m[part]
		if !ok {
			return ""
		}
	}
	switch v := cur.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case json.Number:
		return v.String()
	}
	return ""
}

// UserinfoURL 供测试观察。
func (c *Client) UserinfoURL() string { return c.cfg.UserinfoURL }
