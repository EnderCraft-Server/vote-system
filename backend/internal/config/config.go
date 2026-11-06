package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration 让 YAML 里可以直接写 "15s" / "8h"。
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("解析时长 %q 失败：%w", s, err)
	}
	d.Duration = v
	return nil
}

type Config struct {
	Env      string   `yaml:"env"`
	Server   Server   `yaml:"server"`
	Database Database `yaml:"database"`
	Security Security `yaml:"security"`
	OAuth    OAuth    `yaml:"oauth"`
	Risk     Risk     `yaml:"risk"`
	Captcha  Captcha  `yaml:"captcha"`
	Limits   Limits   `yaml:"limits"`
	Demo     Demo     `yaml:"demo"`
	Log      Log      `yaml:"log"`
}

type Server struct {
	RPCListen         string   `yaml:"rpc_listen"`
	AdminListen       string   `yaml:"admin_listen"`
	AdminAllowedCIDRs []string `yaml:"admin_allowed_cidrs"`
	ReadTimeout       Duration `yaml:"read_timeout"`
	WriteTimeout      Duration `yaml:"write_timeout"`
	IdleTimeout       Duration `yaml:"idle_timeout"`
	MaxConnections    int      `yaml:"max_connections"`
	MaxFrameBytes     int      `yaml:"max_frame_bytes"`
}

type Database struct {
	Driver          string   `yaml:"driver"`
	DSN             string   `yaml:"dsn"`
	MaxOpenConns    int      `yaml:"max_open_conns"`
	MaxIdleConns    int      `yaml:"max_idle_conns"`
	ConnMaxLifetime Duration `yaml:"conn_max_lifetime"`
}

type Security struct {
	RPCSecret            string   `yaml:"rpc_secret"`
	RPCClockSkew         Duration `yaml:"rpc_clock_skew"`
	RPCNonceTTL          Duration `yaml:"rpc_nonce_ttl"`
	AdminSessionTTL      Duration `yaml:"admin_session_ttl"`
	AdminIdleTimeout     Duration `yaml:"admin_idle_timeout"`
	AdminCookieSecure    bool     `yaml:"admin_cookie_secure"`
	AdminLoginMaxAttempt int      `yaml:"admin_login_max_attempts"`
	AdminLoginLockout    Duration `yaml:"admin_login_lockout"`
	AdminBcryptCost      int      `yaml:"admin_bcrypt_cost"`
}

// Risk 是风控阈值：只看"最近 window 内的票"，对同一个 IP 聚合打分。
type Risk struct {
	Window         Duration `yaml:"window"`
	MinVotes       int      `yaml:"min_votes"`
	VolumeWarn     int      `yaml:"volume_warn"`
	VolumeHigh     int      `yaml:"volume_high"`
	BurstPerMinute int      `yaml:"burst_per_minute"`
	PollSpread     int      `yaml:"poll_spread"`
	RegularityCV   float64  `yaml:"regularity_cv"`
	UAChange       int      `yaml:"ua_change"`
}

// OAuth 是"危险操作二次授权"用的 OAuth2 客户端配置。
// 每个管理员把自己的一次外部身份绑定到账号上，之后删除数据前都要重新走一次授权。
type OAuth struct {
	Enabled            bool     `yaml:"enabled"`
	AuthorizeURL       string   `yaml:"authorize_url"`
	TokenURL           string   `yaml:"token_url"`
	UserinfoURL        string   `yaml:"userinfo_url"`
	ClientID           string   `yaml:"client_id"`
	ClientSecret       string   `yaml:"client_secret"`
	RedirectURI        string   `yaml:"redirect_uri"`
	Scopes             []string `yaml:"scopes"`
	SubjectField       string   `yaml:"subject_field"`
	EmailField         string   `yaml:"email_field"`
	AllowedEmailDomain []string `yaml:"allowed_email_domains"`
	Timeout            Duration `yaml:"timeout"`
	PendingTTL         Duration `yaml:"pending_ttl"`
}

type Captcha struct {
	Enabled           bool     `yaml:"enabled"`
	Length            int      `yaml:"length"`
	TTL               Duration `yaml:"ttl"`
	MaxAttempts       int      `yaml:"max_attempts"`
	CreatePerIPMinute int      `yaml:"create_per_ip_per_minute"`
	// Pow 是"工作量证明"层：没有可被 OCR/多模态模型识别的语义，
	// 只把每次提交的代价变成可度量的 CPU 工作量，并按申请次数逐级加码。
	Pow Pow `yaml:"pow"`
}

type Pow struct {
	Enabled       bool     `yaml:"enabled"`
	BaseBits      int      `yaml:"base_bits"`
	MaxBits       int      `yaml:"max_bits"`
	EscalateEvery int      `yaml:"escalate_every"`
	TTL           Duration `yaml:"ttl"`
	Window        Duration `yaml:"window"`
}

type Limits struct {
	VotePerIPMinute int    `yaml:"vote_per_ip_per_minute"`
	AnswerTextMax   int    `yaml:"answer_text_max"`
	IPDefaultAction string `yaml:"ip_default_action"`
	// OneVotePerIP 对应需求里的"每个 IP 只能投票一次"。默认 true；
	// 只有压力测试/演示需要"同一 IP 连投"时才关，生产必须保持 true。
	OneVotePerIP bool `yaml:"one_vote_per_ip"`
}

type Demo struct {
	Seed          bool   `yaml:"seed"`
	AdminUsername string `yaml:"admin_username"`
	AdminPassword string `yaml:"admin_password"`
}

type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Default 返回一份可直接跑起来的默认值，再由 YAML 覆盖。
func Default() *Config {
	return &Config{
		Env: "production",
		Server: Server{
			RPCListen:      "127.0.0.1:7788",
			AdminListen:    "127.0.0.1:7789",
			ReadTimeout:    Duration{15 * time.Second},
			WriteTimeout:   Duration{15 * time.Second},
			IdleTimeout:    Duration{60 * time.Second},
			MaxConnections: 256,
			MaxFrameBytes:  1 << 20,
		},
		Database: Database{
			Driver:          "mysql",
			MaxOpenConns:    32,
			MaxIdleConns:    8,
			ConnMaxLifetime: Duration{30 * time.Minute},
		},
		Security: Security{
			RPCClockSkew:         Duration{60 * time.Second},
			RPCNonceTTL:          Duration{300 * time.Second},
			AdminSessionTTL:      Duration{8 * time.Hour},
			AdminIdleTimeout:     Duration{30 * time.Minute},
			AdminCookieSecure:    true,
			AdminLoginMaxAttempt: 5,
			AdminLoginLockout:    Duration{15 * time.Minute},
			AdminBcryptCost:      12,
		},
		Risk: Risk{
			Window:         Duration{24 * time.Hour},
			MinVotes:       3,
			VolumeWarn:     10,
			VolumeHigh:     30,
			BurstPerMinute: 5,
			PollSpread:     3,
			RegularityCV:   0.15,
			UAChange:       3,
		},
		OAuth: OAuth{
			Enabled:            false,
			Scopes:             []string{"openid", "profile", "email"},
			SubjectField:       "sub",
			EmailField:         "email",
			Timeout:            Duration{10 * time.Second},
			PendingTTL:         Duration{5 * time.Minute},
			AllowedEmailDomain: nil,
		},
		Captcha: Captcha{
			Enabled:           true,
			Length:            4,
			TTL:               Duration{5 * time.Minute},
			MaxAttempts:       3,
			CreatePerIPMinute: 10,
			Pow: Pow{
				Enabled:       true,
				BaseBits:      18,
				MaxBits:       24,
				EscalateEvery: 3,
				TTL:           Duration{5 * time.Minute},
				Window:        Duration{10 * time.Minute},
			},
		},
		Limits: Limits{
			VotePerIPMinute: 3,
			AnswerTextMax:   300,
			IPDefaultAction: "allow",
			OneVotePerIP:    true,
		},
		Demo: Demo{AdminUsername: "admin"},
		Log:  Log{Level: "info", Format: "text"},
	}
}

// Load 读取 YAML 配置，环境变量可以覆盖若干关键项（便于容器化部署）。
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置 %s 失败：%w", path, err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("解析配置 %s 失败：%w", path, err)
	}
	applyEnvOverrides(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("VOTE_ENV"); v != "" {
		cfg.Env = v
	}
	if v := os.Getenv("VOTE_RPC_SECRET"); v != "" {
		cfg.Security.RPCSecret = v
	}
	if v := os.Getenv("VOTE_DB_DSN"); v != "" {
		cfg.Database.DSN = v
	}
	if v := os.Getenv("VOTE_RPC_LISTEN"); v != "" {
		cfg.Server.RPCListen = v
	}
	if v := os.Getenv("VOTE_ADMIN_LISTEN"); v != "" {
		cfg.Server.AdminListen = v
	}
	if v := os.Getenv("VOTE_ADMIN_PASSWORD"); v != "" {
		cfg.Demo.AdminPassword = v
	}
}

func (c *Config) IsProduction() bool { return c.Env == "production" }

// Validate 在启动时一次性把配置错误暴露出来，避免带着错配置对外服务。
func (c *Config) Validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	switch c.Env {
	case "production", "development":
	default:
		add("env 只能是 production 或 development，当前为 %q", c.Env)
	}
	if c.Server.RPCListen == "" {
		add("server.rpc_listen 不能为空")
	}
	if c.Server.MaxFrameBytes < 4096 || c.Server.MaxFrameBytes > 8<<20 {
		add("server.max_frame_bytes 需在 4 KiB ~ 8 MiB 之间")
	}
	if c.Server.MaxConnections < 1 {
		add("server.max_connections 必须大于 0")
	}

	if strings.Contains(c.Security.RPCSecret, "CHANGE_ME") || c.Security.RPCSecret == "" {
		add("security.rpc_secret 仍是占位符，请生成随机密钥（openssl rand -hex 32）")
	} else if len(c.Security.RPCSecret) < 32 {
		add("security.rpc_secret 至少 32 字节，当前 %d 字节", len(c.Security.RPCSecret))
	}

	switch c.Database.Driver {
	case "mysql":
		if c.Database.DSN == "" {
			add("database.dsn 不能为空")
		}
	case "memory":
		if c.IsProduction() {
			add("database.driver=memory 只能用于 development，生产必须用 mysql")
		}
	default:
		add("database.driver 只能是 mysql 或 memory，当前为 %q", c.Database.Driver)
	}

	if c.Captcha.Enabled {
		if c.Captcha.Length < 4 || c.Captcha.Length > 8 {
			add("captcha.length 需在 4~8 之间")
		}
		if c.Captcha.TTL.Duration < 30*time.Second || c.Captcha.TTL.Duration > time.Hour {
			add("captcha.ttl 需在 30s ~ 1h 之间")
		}
		if c.Captcha.MaxAttempts < 1 || c.Captcha.MaxAttempts > 10 {
			add("captcha.max_attempts 需在 1~10 之间")
		}
	}

	if c.Captcha.Pow.Enabled {
		if c.Captcha.Pow.BaseBits < 10 || c.Captcha.Pow.BaseBits > 28 {
			add("captcha.pow.base_bits 需在 10~28 之间（18 ≈ 26 万次哈希，浏览器约 0.3s）")
		}
		if c.Captcha.Pow.MaxBits < c.Captcha.Pow.BaseBits || c.Captcha.Pow.MaxBits > 32 {
			add("captcha.pow.max_bits 需在 base_bits~32 之间")
		}
		if c.Captcha.Pow.EscalateEvery < 1 {
			add("captcha.pow.escalate_every 至少为 1")
		}
	}
	if c.Risk.Window.Duration <= 0 {
		add("risk.window 必须大于 0")
	}
	if c.Risk.VolumeWarn <= 0 || c.Risk.VolumeHigh < c.Risk.VolumeWarn {
		add("risk.volume_warn / volume_high 需 >0 且 high >= warn")
	}
	if c.Risk.BurstPerMinute <= 0 || c.Risk.PollSpread <= 0 || c.Risk.UAChange <= 0 {
		add("risk.burst_per_minute / poll_spread / ua_change 需 > 0")
	}
	if c.OAuth.Enabled {
		if c.OAuth.AuthorizeURL == "" || c.OAuth.TokenURL == "" || c.OAuth.UserinfoURL == "" {
			add("oauth 启用时必须配置 authorize_url / token_url / userinfo_url")
		}
		if c.OAuth.ClientID == "" || c.OAuth.ClientSecret == "" {
			add("oauth 启用时必须配置 client_id / client_secret")
		}
		if c.OAuth.RedirectURI == "" {
			add("oauth 启用时必须配置 redirect_uri（例如 https://admin.example.com/oauth/callback）")
		}
	}
	if c.Security.AdminBcryptCost < 10 || c.Security.AdminBcryptCost > 15 {
		add("security.admin_bcrypt_cost 需在 10~15 之间")
	}
	switch c.Limits.IPDefaultAction {
	case "allow", "deny":
	default:
		add("limits.ip_default_action 只能是 allow 或 deny")
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		add("log.format 只能是 text 或 json")
	}

	if len(problems) > 0 {
		return errors.New("配置有问题：\n  - " + strings.Join(problems, "\n  - "))
	}
	return nil
}

// ValidateSecret 检查密钥是否已经换成真实值（供启动自检使用）。
func (c *Config) ValidateSecret() error {
	if strings.Contains(c.Security.RPCSecret, "CHANGE_ME") {
		return errors.New("security.rpc_secret 未替换")
	}
	return nil
}
