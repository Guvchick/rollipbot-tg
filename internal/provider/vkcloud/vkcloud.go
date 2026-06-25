// Package vkcloud implements the Provider for VK Cloud (OpenStack/Neutron
// floating IPs) via gophercloud, authenticating with an Application Credential.
package vkcloud

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

type Config struct {
	AuthURL               string
	Region                string
	ApplicationCredID     string
	ApplicationCredSecret string
	FloatingNetworkID     string
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
	ao := gophercloud.AuthOptions{
		IdentityEndpoint:            cfg.AuthURL,
		ApplicationCredentialID:     cfg.ApplicationCredID,
		ApplicationCredentialSecret: cfg.ApplicationCredSecret,
		AllowReauth:                 true,
	}
	return &Provider{ao: ao, region: cfg.Region, extNetID: cfg.FloatingNetworkID, caps: caps}
}

func (p *Provider) Name() string            { return "vkcloud" }
func (p *Provider) Caps() provider.RollCaps { return p.caps }

// client lazily authenticates and caches the Neutron client.
func (p *Provider) client(ctx context.Context) (*gophercloud.ServiceClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.net != nil {
		return p.net, nil
	}
	pc, err := openstack.AuthenticatedClient(ctx, p.ao)
	if err != nil {
		return nil, fmt.Errorf("vkcloud: auth: %w", err)
	}
	nc, err := openstack.NewNetworkV2(pc, gophercloud.EndpointOpts{Region: p.region})
	if err != nil {
		return nil, fmt.Errorf("vkcloud: network client: %w", err)
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
		return provider.AllocatedIP{}, fmt.Errorf("vkcloud: create floating ip: %w", err)
	}
	addr, err := netip.ParseAddr(fip.FloatingIP)
	if err != nil {
		return provider.AllocatedIP{}, fmt.Errorf("vkcloud: некорректный ip %q: %w", fip.FloatingIP, err)
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

// Attach binds the floating IP to a Neutron port (portID = VM's private port).
func (p *Provider) Attach(ctx context.Context, ip provider.AllocatedIP, portID string) error {
	nc, err := p.client(ctx)
	if err != nil {
		return err
	}
	_, err = floatingips.Update(ctx, nc, ip.ID, floatingips.UpdateOpts{PortID: &portID}).Extract()
	return err
}

var _ provider.Provider = (*Provider)(nil)
