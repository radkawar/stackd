package ec2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"stackd/compute/docker"
	"stackd/compute/network"
)

type GuestNetworkConfig struct {
	Docker         *docker.Client
	Bridges        *network.Bridges
	StateDirectory string
	DNSMasqBinary  string
	// DHCPReleaseBinary retires dnsmasq's native lease before address reuse.
	DHCPReleaseBinary string
	// DNSUpstream is an explicitly configured native forwarder. An empty list
	// serves only authoritative local names; host resolv.conf is never read.
	DNSUpstream []netip.Addr
}

type GuestNetworkManager struct {
	config        GuestNetworkConfig
	loader        string
	releaseLoader string
	libraries     string
	mu            sync.Mutex
	attachments   map[string]*guestAttachment
}

type guestAttachment struct {
	manager     *GuestNetworkManager
	arn         string
	spec        network.Specification
	bridge      network.Bridge
	tap         string
	server      *http.Server
	callback    string
	policyMu    sync.Mutex
	policyReady bool
	closed      bool
}

const guestNetworkLabel = "stackd.ec2.guest-network"

func NewGuestNetworks(ctx context.Context, config GuestNetworkConfig) (*GuestNetworkManager, error) {
	if config.Docker == nil || config.Bridges == nil {
		return nil, errors.New("guest networking requires the local Docker client and shared bridge owner")
	}
	if !filepath.IsAbs(config.StateDirectory) || !filepath.IsAbs(config.DNSMasqBinary) || !filepath.IsAbs(config.DHCPReleaseBinary) {
		return nil, errors.New("guest networking requires explicit absolute state-directory, dnsmasq and dhcp_release paths")
	}
	if err := os.MkdirAll(config.StateDirectory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(config.StateDirectory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("guest network state directory must be private (0700)")
	}
	loader, libraries, err := networkUtilityLoader(config.DNSMasqBinary)
	if err != nil {
		return nil, err
	}
	releaseLoader, _, err := networkUtilityLoader(config.DHCPReleaseBinary)
	if err != nil {
		return nil, fmt.Errorf("dhcp_release: %w", err)
	}
	for _, address := range config.DNSUpstream {
		if !address.Is4() || !address.IsGlobalUnicast() {
			return nil, errors.New("native DNS upstreams must be explicit unicast IPv4 addresses")
		}
	}
	var engine struct {
		OSType          string
		SecurityOptions []string
	}
	if err := config.Docker.JSON(ctx, http.MethodGet, "/info", nil, &engine); err != nil {
		return nil, err
	}
	if engine.OSType != "linux" {
		return nil, &CapabilityError{Feature: "local Linux Docker guest networking"}
	}
	for _, option := range engine.SecurityOptions {
		if strings.Contains(option, "rootless") || strings.Contains(option, "userns") {
			return nil, &CapabilityError{Feature: "rootful Docker without user namespace remapping"}
		}
	}
	if err := config.Docker.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(docker.ToolkitImage)+"/json", nil, nil); err != nil {
		return nil, fmt.Errorf("guest network toolkit must be installed locally: %w", err)
	}
	return &GuestNetworkManager{config: config, loader: loader, releaseLoader: releaseLoader, libraries: libraries, attachments: map[string]*guestAttachment{}}, nil
}

func (m *GuestNetworkManager) lock(ctx context.Context) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if m.mu.TryLock() {
			break
		}
		if err := waitTick(ctx); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(filepath.Join(m.config.StateDirectory, "network.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN); _ = file.Close(); m.mu.Unlock() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			file.Close()
			m.mu.Unlock()
			return nil, err
		}
		if err := waitTick(ctx); err != nil {
			file.Close()
			m.mu.Unlock()
			return nil, err
		}
	}
}

func guestTAP(arn string) string   { return "st" + identifier(arn)[:12] }
func guestTable(arn string) string { return "stackd_ec2_" + identifier(arn) }
func guestAlias(arn string) string { return "stackd.ec2:" + arn }

func (m *GuestNetworkManager) helper(ctx context.Context, arn string, command, environment []string) ([]byte, error) {
	return docker.RunHelper(ctx, m.config.Docker, "ec2-network", docker.ContainerConfig{
		Image: docker.ToolkitImage, Entrypoint: command, Env: environment, Labels: map[string]string{guestNetworkLabel: arn},
		HostConfig: docker.ContainerHostConfig{NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN", "NET_RAW"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32, Mounts: []docker.ContainerMount{{Type: "bind", Source: "/dev/net/tun", Target: "/dev/net/tun"}}, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}}},
	})
}

func validateGuestNetwork(arn string, spec network.Specification, handler http.Handler) error {
	if arn == "" || handler == nil {
		return errors.New("guest network requires instance identity and metadata handler")
	}
	if !spec.Pool.IsValid() || !spec.Pool.Addr().Is4() || !spec.Pool.Contains(spec.Gateway) || !spec.Pool.Contains(spec.Address) || !spec.Policy.Subnet.Contains(spec.Address) {
		return errors.New("guest network requires containing VPC/subnet and IPv4 addresses")
	}
	mac, err := net.ParseMAC(spec.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return errors.New("guest network requires an Ethernet unicast MAC")
	}
	for _, servers := range [][]netip.Addr{spec.DNS, spec.NTPServers, spec.NetBIOSServers} {
		for _, address := range servers {
			if !address.Is4() || !address.IsGlobalUnicast() {
				return errors.New("DHCP servers must be IPv4 unicast addresses")
			}
		}
	}
	if spec.NetBIOSNodeType != 0 && spec.NetBIOSNodeType != 1 && spec.NetBIOSNodeType != 2 && spec.NetBIOSNodeType != 4 && spec.NetBIOSNodeType != 8 {
		return errors.New("invalid DHCP NetBIOS node type")
	}
	names := strings.Fields(spec.DomainName)
	names = append(names, spec.Hostname, spec.PublicHostname)
	for _, name := range names {
		if len(name) > 253 {
			return errors.New("DHCP domain or hostname is too long")
		}
		for _, part := range strings.Split(name, ".") {
			if name == "" {
				break
			}
			if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
				return errors.New("invalid DHCP DNS name")
			}
			for _, character := range part {
				if character != '-' && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
					return errors.New("invalid DHCP DNS name")
				}
			}
		}
	}
	return nil
}

func (m *GuestNetworkManager) Prepare(ctx context.Context, arn string, spec network.Specification, handler http.Handler) (_ GuestAttachment, err error) {
	if err := validateGuestNetwork(arn, spec, handler); err != nil {
		return nil, err
	}
	unlock, err := m.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if existing := m.attachments[arn]; existing != nil {
		if err := existing.configure(ctx, spec); err != nil {
			return nil, err
		}
		return existing, nil
	}
	attachment := &guestAttachment{manager: m, arn: arn, spec: spec, tap: guestTAP(arn)}
	err = m.config.Bridges.WithBridge(ctx, spec, func(bridge network.Bridge) error {
		attachment.bridge = bridge
		if err := m.prepareTAP(ctx, attachment); err != nil {
			return err
		}
		if err := attachment.prepareMetadata(ctx, handler); err != nil {
			return err
		}
		if err := attachment.configure(ctx, spec); err != nil {
			return err
		}
		_, err := m.helper(ctx, arn, []string{"ip", "link", "set", "dev", attachment.tap, "up"}, nil)
		return err
	})
	if err != nil {
		if attachment.server != nil {
			err = errors.Join(err, attachment.closeController())
		}
		// Native partial resources retain the instance identity; Remove can
		// release them without inventing metadata or disturbing another guest.
		return nil, err
	}
	m.attachments[arn] = attachment
	return attachment, nil
}

type guestLink struct {
	Name     string   `json:"ifname"`
	Alias    string   `json:"ifalias"`
	Master   string   `json:"master"`
	Flags    []string `json:"flags"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
		Data struct {
			Type    string `json:"type"`
			Persist bool   `json:"persist"`
			User    int    `json:"user"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

func (m *GuestNetworkManager) links(ctx context.Context, arn string) ([]guestLink, error) {
	output, err := m.helper(ctx, arn, []string{"ip", "-d", "-j", "link", "show"}, nil)
	if err != nil {
		return nil, err
	}
	var links []guestLink
	if err := json.Unmarshal(output, &links); err != nil {
		return nil, err
	}
	return links, nil
}

func (m *GuestNetworkManager) prepareTAP(ctx context.Context, a *guestAttachment) error {
	links, err := m.links(ctx, a.arn)
	if err != nil {
		return err
	}
	for _, link := range links {
		if link.Name != a.tap {
			continue
		}
		if link.Alias != guestAlias(a.arn) || link.Master != a.bridge.Device || link.LinkInfo.Kind != "tun" || link.LinkInfo.Data.Type != "tap" || !link.LinkInfo.Data.Persist || link.LinkInfo.Data.User != os.Getuid() {
			return errors.New("existing native TAP identity/bridge/owner differs")
		}
		return nil
	}
	_, err = m.helper(ctx, a.arn, []string{"/bin/sh", "-ec", `ip tuntap add dev "$TAP" mode tap user "$OWNER"
trap 'ip link delete dev "$TAP"' EXIT
ip link set dev "$TAP" alias "$ALIAS"
ip link set dev "$TAP" master "$BRIDGE"
trap - EXIT`}, []string{"TAP=" + a.tap, "OWNER=" + strconv.Itoa(os.Getuid()), "ALIAS=" + guestAlias(a.arn), "BRIDGE=" + a.bridge.Device})
	return err
}

func (a *guestAttachment) TAPName() string { return a.tap }

func (a *guestAttachment) Configure(ctx context.Context, spec network.Specification) error {
	unlock, err := a.manager.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return a.configure(ctx, spec)
}

func (a *guestAttachment) configure(ctx context.Context, spec network.Specification) error {
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	if a.closed {
		return errors.New("guest network controller is closed")
	}
	if err := validateGuestNetwork(a.arn, spec, a.server.Handler); err != nil {
		return err
	}
	if spec.NetworkID != a.spec.NetworkID || spec.Pool != a.spec.Pool || spec.Gateway != a.spec.Gateway || spec.Address != a.spec.Address || spec.MAC != a.spec.MAC {
		return errors.New("cannot change a surviving guest's physical network identity")
	}
	if a.policyReady && a.spec.Policy.Equal(spec.Policy) && slices.Equal(a.spec.DNS, spec.DNS) && slices.Equal(a.spec.NTPServers, spec.NTPServers) && slices.Equal(a.spec.NetBIOSServers, spec.NetBIOSServers) && a.spec.NetBIOSNodeType == spec.NetBIOSNodeType && a.spec.Hostname == spec.Hostname && a.spec.PublicHostname == spec.PublicHostname && a.spec.DomainName == spec.DomainName && a.spec.DNSSupport == spec.DNSSupport {
		return nil
	}
	previous := a.spec
	a.policyReady = false
	a.spec = spec
	if err := a.manager.prepareDNS(ctx, a); err != nil {
		a.spec = previous
		return err
	}
	if err := a.manager.config.Bridges.ApplyPolicy(ctx, guestTable(a.arn), spec, spec.Policy, a.tap, network.Options{Callback: a.callback, Guest: true, PublicOwner: a.manager.config.StateDirectory}, a.bridge); err != nil {
		a.spec = previous
		return err
	}
	a.spec.DNS = slices.Clone(spec.DNS)
	a.spec.NTPServers = slices.Clone(spec.NTPServers)
	a.spec.NetBIOSServers = slices.Clone(spec.NetBIOSServers)
	a.policyReady = true
	return nil
}

func (a *guestAttachment) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	unlock, err := a.manager.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if a.manager.attachments[a.arn] != a {
		return nil
	}
	delete(a.manager.attachments, a.arn)
	return a.closeController()
}

func (a *guestAttachment) closeController() error {
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	a.closed = true
	var err error
	if a.server != nil {
		err = a.server.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return errors.Join(err, a.manager.removeMetadataRules(ctx, a.arn))
}

func (m *GuestNetworkManager) Remove(ctx context.Context, arn string, spec network.Specification) error {
	if arn == "" {
		return errors.New("instance identity required")
	}
	unlock, err := m.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if attachment := m.attachments[arn]; attachment != nil {
		if err := attachment.closeController(); err != nil {
			return err
		}
		delete(m.attachments, arn)
	}
	links, err := m.links(ctx, arn)
	if err != nil {
		return err
	}
	for _, link := range links {
		if link.Name != guestTAP(arn) {
			continue
		}
		if link.Alias != guestAlias(arn) || link.LinkInfo.Kind != "tun" {
			return errors.New("refusing to delete an unowned native TAP")
		}
		if _, err := m.helper(ctx, arn, []string{"ip", "link", "delete", "dev", link.Name}, nil); err != nil {
			return err
		}
	}
	if err := m.removeMetadataRules(ctx, arn); err != nil {
		return err
	}
	if err := m.config.Bridges.RemovePolicy(ctx, guestTable(arn), m.config.StateDirectory); err != nil {
		return err
	}
	if err := m.removeDNS(ctx, arn, spec); err != nil {
		return err
	}
	return m.config.Bridges.Release(ctx, spec.NetworkID)
}

var _ GuestNetworks = (*GuestNetworkManager)(nil)
var _ GuestAttachment = (*guestAttachment)(nil)
