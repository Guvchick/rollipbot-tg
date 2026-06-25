// Package selectel implements the Provider for Selectel (OpenStack/Neutron
// floating IPs) via gophercloud, using a project-scoped service-user IAM token.
package selectel

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"

	"ip-roller-bot/internal/provider"
)

const defaultAuthURL = "https://cloud.api.selcloud.ru/identity/v3"

type Config struct {
	AuthURL           string
	Region            string
	AccountID         string // Selectel account number (domain)
	ServiceUser       string
	ServicePassword   string
	ProjectID         string
	FloatingNetworkID string
}

type Provider struct {
	ao       gophercloud.AuthOptions
	region   string
	extNetID string
	caps     provider.RollCaps

	mu  sync.Mutex
	net *gophercloud.ServiceClient
}

func New(cfg Config, caps provider.RollCaps) *Provider {
	authURL := cfg.AuthURL
	if authURL == "" {
		authURL = defaultAuthURL
	}
	ao := gophercloud.AuthOptions{
		IdentityEndpoint: authURL,
		Username:         cfg.ServiceUser,
		Password:         cfg.ServicePassword,
		DomainName:       cfg.AccountID, // Selectel account number is the domain
		TenantID:         cfg.ProjectID, // project scope
		AllowReauth:      true,          // IAM tokens live 24h; auto-renew
	}
	return &Provider{ao: ao, region: cfg.Region, extNetID: cfg.FloatingNetworkID, caps: caps}
}

func (p *Provider) Name() string            { return "selectel" }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

func (p *Provider) client(ctx context.Context) (*gophercloud.ServiceClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.net != nil {
		return p.net, nil
	}
	pc, err := openstack.AuthenticatedClient(ctx, p.ao)
	if err != nil {
		return nil, fmt.Errorf("selectel: auth: %w", err)
	}
	nc, err := openstack.NewNetworkV2(pc, gophercloud.EndpointOpts{Region: p.region})
	if err != nil {
		return nil, fmt.Errorf("selectel: network client: %w", err)
	}
	p.net = nc
	return nc, nil
}

func (p *Provider) Allocate(ctx context.Context) (provider.AllocatedIP, error) {
	nc, err := p.client(ctx)
	if err != nil {
		return provider.AllocatedIP{}, err
	}
	fip, err := floatingips.Create(ctx, nc, floatingips.CreateOpts{
		FloatingNetworkID: p.extNetID,
	}).Extract()
	if err != nil {
		return provider.AllocatedIP{}, fmt.Errorf("selectel: create floating ip: %w", err)
	}
	addr, err := netip.ParseAddr(fip.FloatingIP)
	if err != nil {
		return provider.AllocatedIP{}, fmt.Errorf("selectel: некорректный ip %q: %w", fip.FloatingIP, err)
	}
	return provider.AllocatedIP{Addr: addr, ID: fip.ID}, nil
}

func (p *Provider) Release(ctx context.Context, ip provider.AllocatedIP) error {
	nc, err := p.client(ctx)
	if err != nil {
		return err
	}
	return floatingips.Delete(ctx, nc, ip.ID).ExtractErr()
}

func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, portID string) error {
	nc, err := p.client(ctx)
	if err != nil {
		return err
	}
	_, err = floatingips.Update(ctx, nc, ip.ID, floatingips.UpdateOpts{PortID: &portID}).Extract()
	return err
}

var _ provider.Provider = (*Provider)(nil)
