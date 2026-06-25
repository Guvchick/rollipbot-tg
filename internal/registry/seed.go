package registry

import (
	"context"
	"log/slog"
	"strconv"

	"ip-roller-bot/internal/config"
	"ip-roller-bot/internal/storage"
)

// Field describes one credential field of a provider type.
type Field struct {
	Name     string
	Required bool
	Secret   bool // mask in listings
}

// Fields returns the credential schema for a provider type (used by /addaccount
// validation and help). Non-secret connection fields (region, auth_url, ...) are
// optional and fall back to config.yaml type defaults when omitted.
func Fields(typ string) []Field {
	switch typ {
	case "timeweb":
		return []Field{{"token", true, true}, {"availability_zone", false, false}}
	case "vkcloud":
		return []Field{
			{"app_credential_id", true, true}, {"app_credential_secret", true, true},
			{"floating_network_id", true, false}, {"auth_url", false, false}, {"region", false, false},
		}
	case "selectel":
		return []Field{
			{"account_id", true, false}, {"service_user", true, false}, {"service_password", true, true},
			{"project_id", true, false}, {"floating_network_id", true, false},
			{"auth_url", false, false}, {"region", false, false},
		}
	case "gcore":
		return []Field{
			{"api_token", true, true}, {"project_id", true, false}, {"region_id", true, false},
			{"api_url", false, false},
		}
	case "mws":
		return []Field{
			{"token", true, true}, {"project_id", true, false},
			{"network_id", true, false}, {"subnetwork_id", true, false},
		}
	case "ruvds":
		return []Field{{"token", true, true}, {"server_id", true, false}}
	case "beget":
		return []Field{{"token", true, true}, {"server_id", true, false}, {"api_url", false, false}}
	}
	return nil
}

// ValidateCreds checks required fields are present and rejects unknown keys.
func ValidateCreds(typ string, creds map[string]string) error {
	known := map[string]bool{}
	for _, f := range Fields(typ) {
		known[f.Name] = true
		if f.Required && creds[f.Name] == "" {
			return &fieldError{typ, "отсутствует обязательное поле: " + f.Name}
		}
	}
	for k := range creds {
		if !known[k] {
			return &fieldError{typ, "неизвестное поле: " + k}
		}
	}
	if typ == "gcore" {
		if v := creds["region_id"]; v != "" {
			if _, err := strconv.Atoi(v); err != nil {
				return &fieldError{typ, "region_id должно быть числом"}
			}
		}
	}
	return nil
}

type fieldError struct{ typ, msg string }

func (e *fieldError) Error() string { return e.typ + ": " + e.msg }

// credsFromBlock extracts per-account connection fields from a (env-expanded)
// config block for first-run seeding.
func credsFromBlock(typ string, b *config.ProviderConfig) map[string]string {
	m := map[string]string{}
	put := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	switch typ {
	case "timeweb":
		put("token", b.Token)
		put("availability_zone", b.AvailabilityZone)
	case "vkcloud":
		put("app_credential_id", b.AppCredentialID)
		put("app_credential_secret", b.AppCredentialSecret)
		put("floating_network_id", b.FloatingNetworkID)
		put("auth_url", b.AuthURL)
		put("region", b.Region)
	case "selectel":
		put("account_id", b.AccountID)
		put("service_user", b.ServiceUser)
		put("service_password", b.ServicePassword)
		put("project_id", b.ProjectID)
		put("floating_network_id", b.FloatingNetworkID)
		put("auth_url", b.AuthURL)
		put("region", b.Region)
	case "gcore":
		put("api_token", b.APIToken)
		put("project_id", b.ProjectID)
		if b.RegionID != 0 {
			put("region_id", strconv.Itoa(b.RegionID))
		}
		put("api_url", b.APIURL)
	case "mws":
		put("token", b.Token)
		put("project_id", b.ProjectID)
		put("network_id", b.NetworkID)
		put("subnetwork_id", b.SubnetworkID)
	case "ruvds":
		put("token", b.Token)
		put("server_id", b.ServerID)
	case "beget":
		put("token", b.Token)
		put("server_id", b.ServerID)
		put("api_url", b.APIURL)
	}
	return m
}

// hasMinimumCreds reports whether the required secrets are present.
func hasMinimumCreds(typ string, creds map[string]string) bool {
	return ValidateCreds(typ, creds) == nil
}

// SeedFromConfig populates the accounts table from enabled config blocks on the
// first run only (when the table is empty). This preserves the env/.env
// bootstrap while making the database the source of truth thereafter.
func SeedFromConfig(ctx context.Context, store storage.Storage, cfg *config.Config, log *slog.Logger) error {
	n, err := store.CountAccounts(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil // already seeded / managed via bot
	}
	seeded := 0
	for _, typ := range Types {
		b := cfg.Providers.Get(typ)
		if b == nil || !b.Enabled {
			continue
		}
		creds := credsFromBlock(typ, b)
		if !hasMinimumCreds(typ, creds) {
			log.Warn("seed: пропуск (нет/неполные креды)", "type", typ)
			continue
		}
		id, err := store.UpsertAccount(ctx, storage.Account{
			Provider: typ, Label: "default", Enabled: true, Credentials: creds,
		})
		if err != nil {
			log.Warn("seed: ошибка", "type", typ, "err", err)
			continue
		}
		log.Info("seed: аккаунт создан из config/env", "type", typ, "label", "default", "id", id)
		seeded++
	}
	if seeded > 0 {
		log.Info("seed завершён", "accounts", seeded)
	}
	return nil
}
