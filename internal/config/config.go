// Package config loads the YAML config and expands ${ENV} placeholders so that
// secrets live only in the environment.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"ip-roller-bot/internal/provider"
)

type Config struct {
	Telegram  TelegramConfig  `yaml:"telegram"`
	Storage   StorageConfig   `yaml:"storage"`
	Providers ProvidersConfig `yaml:"providers"`
}

type TelegramConfig struct {
	Token          string  `yaml:"token"`
	AdminUserIDs   []int64 `yaml:"admin_user_ids"`   // могут управлять аккаунтами и whitelist'ом
	AllowedUserIDs []int64 `yaml:"allowed_user_ids"` // статически разрешённые (всегда доступны)
}

type StorageConfig struct {
	Driver string `yaml:"driver"` // sqlite (only sqlite is implemented)
	DSN    string `yaml:"dsn"`
}

// ProvidersConfig holds one optional block per provider.
type ProvidersConfig struct {
	Timeweb  *ProviderConfig `yaml:"timeweb"`
	VKCloud  *ProviderConfig `yaml:"vkcloud"`
	Selectel *ProviderConfig `yaml:"selectel"`
	Gcore    *ProviderConfig `yaml:"gcore"`
	MWS      *ProviderConfig `yaml:"mws"`
	RuVDS    *ProviderConfig `yaml:"ruvds"`
	Beget    *ProviderConfig `yaml:"beget"`
}

// ProviderConfig is a superset of every provider's settings; each adapter reads
// only the fields it needs.
type ProviderConfig struct {
	Enabled        bool     `yaml:"enabled"`
	Strategy       string   `yaml:"strategy"`
	MaxRollsPerRun int      `yaml:"max_rolls_per_run"`
	DailyCap       int      `yaml:"daily_cap"`
	RateLimitRPS   float64  `yaml:"rate_limit_rps"`
	CostPerRoll    string   `yaml:"cost_per_roll"`
	Masks          []string `yaml:"masks"`

	// Token-auth REST providers (timeweb, ruvds, mws, beget).
	Token string `yaml:"token"`

	// Timeweb
	AvailabilityZone string `yaml:"availability_zone"`

	// OpenStack (vkcloud, selectel)
	AuthURL             string `yaml:"auth_url"`
	Region              string `yaml:"region"`
	AppCredentialID     string `yaml:"app_credential_id"`
	AppCredentialSecret string `yaml:"app_credential_secret"`
	FloatingNetworkID   string `yaml:"floating_network_id"`
	FloatingIPQuota     int    `yaml:"floating_ip_quota"`

	// Selectel password auth
	AccountID       string `yaml:"account_id"`
	ServiceUser     string `yaml:"service_user"`
	ServicePassword string `yaml:"service_password"`
	ProjectID       string `yaml:"project_id"`

	// MWS
	NetworkID    string `yaml:"network_id"`
	SubnetworkID string `yaml:"subnetwork_id"`

	// Gcore
	APIURL   string `yaml:"api_url"`
	APIToken string `yaml:"api_token"`
	RegionID int    `yaml:"region_id"`

	// RuVDS / Beget recreate strategies need a target server.
	ServerID string `yaml:"server_id"`
}

// Caps builds engine roll caps from the config block.
func (c *ProviderConfig) Caps() provider.RollCaps {
	return provider.RollCaps{
		MaxRollsPerRun: c.MaxRollsPerRun,
		DailyCap:       c.DailyCap,
		RateLimitRPS:   c.RateLimitRPS,
		CostPerRoll:    c.CostPerRoll,
		Strategy:       c.Strategy,
	}
}

// CapsOf builds roll caps from a (possibly nil) block, applying a default rate
// limit so a missing block can't produce an unthrottled provider.
func CapsOf(c *ProviderConfig) provider.RollCaps {
	if c == nil {
		return provider.RollCaps{RateLimitRPS: 5}
	}
	caps := c.Caps()
	if caps.RateLimitRPS <= 0 {
		caps.RateLimitRPS = 5
	}
	return caps
}

// Get returns the block for a machine provider name, or nil.
func (p ProvidersConfig) Get(name string) *ProviderConfig {
	switch name {
	case "timeweb":
		return p.Timeweb
	case "vkcloud":
		return p.VKCloud
	case "selectel":
		return p.Selectel
	case "gcore":
		return p.Gcore
	case "mws":
		return p.MWS
	case "ruvds":
		return p.RuVDS
	case "beget":
		return p.Beget
	}
	return nil
}

// Load reads path, expands ${ENV} placeholders, and unmarshals YAML.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded := os.ExpandEnv(string(raw))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Telegram.Token == "" {
		return nil, fmt.Errorf("telegram.token не задан (проверь TELEGRAM_TOKEN)")
	}
	if cfg.Storage.Driver == "" {
		cfg.Storage.Driver = "sqlite"
	}
	if cfg.Storage.DSN == "" {
		cfg.Storage.DSN = "./ip-roller.db"
	}
	// STORAGE_DSN env wins over the file value — lets Docker point the DB at a
	// mounted volume without editing the committed config.
	if dsn := os.Getenv("STORAGE_DSN"); dsn != "" {
		cfg.Storage.DSN = dsn
	}
	return &cfg, nil
}
