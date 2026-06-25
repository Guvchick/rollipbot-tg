// Package registry builds live provider.Account instances from credential rows
// stored in the database, merging in per-type defaults (caps, region, masks)
// from config.yaml. It supports hot reload so accounts added/removed via the
// bot take effect without a restart.
package registry

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync"

	"ip-roller-bot/internal/config"
	"ip-roller-bot/internal/provider"
	"ip-roller-bot/internal/provider/beget"
	"ip-roller-bot/internal/provider/gcore"
	"ip-roller-bot/internal/provider/mws"
	"ip-roller-bot/internal/provider/ruvds"
	"ip-roller-bot/internal/provider/selectel"
	"ip-roller-bot/internal/provider/timeweb"
	"ip-roller-bot/internal/provider/vkcloud"
	"ip-roller-bot/internal/storage"
)

// Types lists every supported provider type (machine name).
var Types = []string{"timeweb", "vkcloud", "selectel", "gcore", "mws", "ruvds", "beget"}

// IsType reports whether t is a known provider type.
func IsType(t string) bool {
	for _, x := range Types {
		if x == t {
			return true
		}
	}
	return false
}

// Registry holds the currently enabled accounts behind an RWMutex.
type Registry struct {
	cfg   *config.Config
	store storage.Storage
	log   *slog.Logger

	mu    sync.RWMutex
	byKey map[string]*provider.Account
	order []string
}

func New(cfg *config.Config, store storage.Storage, log *slog.Logger) *Registry {
	return &Registry{cfg: cfg, store: store, log: log, byKey: map[string]*provider.Account{}}
}

// Reload rebuilds the in-memory account set from enabled DB rows.
func (r *Registry) Reload(ctx context.Context) error {
	accs, err := r.store.ListEnabledAccounts(ctx)
	if err != nil {
		return err
	}
	byKey := make(map[string]*provider.Account, len(accs))
	var order []string
	for _, a := range accs {
		block := r.cfg.Providers.Get(a.Provider)
		inner, err := buildAdapter(a.Provider, a.Credentials, block, config.CapsOf(block))
		if err != nil {
			r.log.Warn("пропуск аккаунта", "id", a.ID, "provider", a.Provider, "label", a.Label, "err", err)
			continue
		}
		acc := provider.NewAccount(inner, a.Provider, a.Label, a.ID)
		byKey[acc.Key()] = acc
		order = append(order, acc.Key())
	}
	sort.Strings(order)

	r.mu.Lock()
	r.byKey, r.order = byKey, order
	r.mu.Unlock()
	r.log.Info("registry reloaded", "accounts", len(order))
	return nil
}

// Get returns the account for a key.
func (r *Registry) Get(key string) (*provider.Account, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byKey[key]
	return a, ok
}

// Accounts returns a snapshot of enabled accounts in stable display order.
func (r *Registry) Accounts() []*provider.Account {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*provider.Account, 0, len(r.order))
	for _, k := range r.order {
		out = append(out, r.byKey[k])
	}
	return out
}

// Len returns the number of enabled accounts.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.order)
}

// buildAdapter constructs a concrete adapter from credentials, using config
// block values as defaults for non-secret connection fields.
func buildAdapter(typ string, creds map[string]string, b *config.ProviderConfig, caps provider.RollCaps) (provider.Provider, error) {
	if b == nil {
		b = &config.ProviderConfig{}
	}
	get := func(key, fallback string) string {
		if v := creds[key]; v != "" {
			return v
		}
		return fallback
	}

	switch typ {
	case "timeweb":
		if creds["token"] == "" {
			return nil, fmt.Errorf("timeweb: пустой token")
		}
		return timeweb.New(creds["token"], get("availability_zone", b.AvailabilityZone), caps), nil

	case "vkcloud":
		return vkcloud.New(vkcloud.Config{
			AuthURL:               get("auth_url", b.AuthURL),
			Region:                get("region", b.Region),
			ApplicationCredID:     creds["app_credential_id"],
			ApplicationCredSecret: creds["app_credential_secret"],
			FloatingNetworkID:     get("floating_network_id", b.FloatingNetworkID),
		}, caps), nil

	case "selectel":
		return selectel.New(selectel.Config{
			AuthURL:           get("auth_url", b.AuthURL),
			Region:            get("region", b.Region),
			AccountID:         creds["account_id"],
			ServiceUser:       creds["service_user"],
			ServicePassword:   creds["service_password"],
			ProjectID:         creds["project_id"],
			FloatingNetworkID: get("floating_network_id", b.FloatingNetworkID),
		}, caps), nil

	case "gcore":
		regionID := b.RegionID
		if v := creds["region_id"]; v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("gcore: region_id не число: %q", v)
			}
			regionID = n
		}
		return gcore.New(gcore.Config{
			APIURL:    get("api_url", b.APIURL),
			APIToken:  creds["api_token"],
			ProjectID: creds["project_id"],
			RegionID:  regionID,
		}, caps), nil

	case "mws":
		return mws.New(mws.Config{
			Token:        creds["token"],
			ProjectID:    creds["project_id"],
			NetworkID:    creds["network_id"],
			SubnetworkID: creds["subnetwork_id"],
		}, caps), nil

	case "ruvds":
		return ruvds.New(ruvds.Config{
			Token:    creds["token"],
			Strategy: b.Strategy,
			ServerID: creds["server_id"],
		}, caps), nil

	case "beget":
		return beget.New(beget.Config{
			APIURL:   get("api_url", b.APIURL),
			Token:    creds["token"],
			Strategy: b.Strategy,
			ServerID: creds["server_id"],
		}, caps), nil
	}
	return nil, fmt.Errorf("неизвестный тип провайдера: %s", typ)
}
