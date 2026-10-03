package ec2

import (
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"stackd/compute/docker"
	"stackd/compute/network"
)

// Execute installed host networking utilities with their ELF loader and
// read-only native libraries inside the trusted helper. No host chroot, package
// installation, host configuration change or replacement DHCP implementation.
func networkUtilityLoader(binary string) (string, string, error) {
	info, err := os.Stat(binary)
	if err != nil {
		return "", "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", "", errors.New("configured network utility is not executable")
	}
	file, err := elf.Open(binary)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	if file.Machine != elf.EM_X86_64 {
		return "", "", &CapabilityError{Feature: "native network utility x86_64 ELF loader"}
	}
	var interpreter string
	for _, program := range file.Progs {
		if program.Type != elf.PT_INTERP {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(program.Open(), 4096))
		if err != nil {
			return "", "", err
		}
		interpreter = strings.TrimRight(string(data), "\x00")
	}
	if interpreter == "" {
		return "", "", &CapabilityError{Feature: "configured network utility dynamic ELF interpreter"}
	}
	interpreter, err = filepath.EvalSymlinks(interpreter)
	if err != nil {
		return "", "", err
	}
	libraries, err := filepath.EvalSymlinks("/usr/lib")
	if err != nil {
		return "", "", err
	}
	relative, err := filepath.Rel(libraries, interpreter)
	if err != nil || strings.HasPrefix(relative, "..") {
		return "", "", &CapabilityError{Feature: "network utility interpreter outside installed native library directory"}
	}
	return "/native-lib/" + relative, libraries, nil
}

func (m *GuestNetworkManager) dnsDirectory(networkID string) string {
	return filepath.Join(m.config.StateDirectory, "vpc-"+identifier(networkID))
}
func dnsContainer(networkID string) string { return "stackd-ec2-dns-" + identifier(networkID) }
func dnsAddress(spec network.Specification) netip.Addr {
	return spec.Pool.Masked().Addr().Next().Next()
}

func atomicNativeConfig(path string, data []byte) (err error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".config-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func guestConfigFiles(spec network.Specification) (hosts, dhcp, options string) {
	id := identifier(spec.MAC)
	tag := "guest-" + id
	hostname := spec.Hostname
	domains := strings.Fields(spec.DomainName)
	if hostname != "" {
		fqdn := hostname
		if !strings.Contains(hostname, ".") && len(domains) > 0 {
			fqdn += "." + domains[0]
		}
		hosts = spec.Address.String() + " " + fqdn
		if fqdn != hostname {
			hosts += " " + hostname
		}
		hosts += "\n"
	}
	if spec.PublicHostname != "" {
		hosts += spec.Address.String() + " " + spec.PublicHostname + "\n"
	}
	dhcp = spec.MAC + ",set:" + tag + "," + spec.Address.String()
	if hostname != "" {
		dhcp += "," + strings.Split(hostname, ".")[0]
	}
	dhcp += ",infinite\n"
	maskBytes := net.CIDRMask(spec.Policy.Subnet.Bits(), 32)
	mask := net.IP(maskBytes).String()
	broadcast := spec.Policy.Subnet.Masked().Addr().As4()
	for index := range broadcast {
		broadcast[index] |= ^maskBytes[index]
	}
	options = "tag:" + tag + ",option:netmask," + mask + "\ntag:" + tag + ",option:router," + spec.Gateway.String() + "\n"
	options += "tag:" + tag + ",28," + netip.AddrFrom4(broadcast).String() + "\n"
	options += "tag:" + tag + ",option:dns-server"
	for _, address := range spec.DNS {
		options += "," + address.String()
	}
	options += "\n"
	if len(domains) > 0 {
		options += "tag:" + tag + ",option:domain-name," + domains[0] + "\n"
		options += "tag:" + tag + ",option:domain-search," + strings.Join(domains, ",") + "\n"
	}
	for _, item := range []struct {
		option  string
		servers []netip.Addr
	}{{"ntp-server", spec.NTPServers}, {"netbios-ns", spec.NetBIOSServers}} {
		if len(item.servers) == 0 {
			continue
		}
		options += "tag:" + tag + ",option:" + item.option
		for _, server := range item.servers {
			options += "," + server.String()
		}
		options += "\n"
	}
	if spec.NetBIOSNodeType != 0 {
		options += "tag:" + tag + ",option:netbios-nodetype," + strconv.Itoa(spec.NetBIOSNodeType) + "\n"
	}
	// RFC3442 supplies an on-link route to the physical VPC gateway even when
	// the EC2 logical subnet is elsewhere in the shared bridge's VPC pool.
	options += "tag:" + tag + ",option:classless-static-route," + spec.Gateway.String() + "/32,0.0.0.0,0.0.0.0/0," + spec.Gateway.String() + "\n"
	return hosts, dhcp, options
}

func (m *GuestNetworkManager) prepareDNS(ctx context.Context, a *guestAttachment) error {
	directory := m.dnsDirectory(a.spec.NetworkID)
	for _, part := range []string{"hosts", "dhcp", "options"} {
		if err := os.MkdirAll(filepath.Join(directory, part), 0700); err != nil {
			return err
		}
	}
	if err := m.ensureDNSAddress(ctx, a); err != nil {
		return err
	}
	hosts, dhcp, options := guestConfigFiles(a.spec)
	name := identifier(a.arn)
	for _, item := range []struct{ directory, data string }{{"hosts", hosts}, {"options", options}, {"dhcp", dhcp}} {
		if err := atomicNativeConfig(filepath.Join(directory, item.directory, name), []byte(item.data)); err != nil {
			return err
		}
	}
	if err := m.dnsFirewall(ctx, a.arn, a.spec, a.bridge.Device, true); err != nil {
		return err
	}
	return m.ensureDNSDaemon(ctx, a)
}

func (m *GuestNetworkManager) ensureDNSAddress(ctx context.Context, a *guestAttachment) error {
	var native struct {
		IPAM struct {
			Config []struct{ AuxiliaryAddresses map[string]string }
		}
		Containers map[string]struct{ IPv4Address string }
	}
	if err := m.config.Docker.JSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(a.bridge.Name), nil, &native); err != nil {
		return err
	}
	address := dnsAddress(a.spec)
	reserved := false
	for _, pool := range native.IPAM.Config {
		for _, value := range pool.AuxiliaryAddresses {
			if value == address.String() {
				reserved = true
			}
		}
	}
	if !reserved {
		return &CapabilityError{Feature: "VPC bridge must reserve native AmazonProvidedDNS address in Docker IPAM"}
	}
	for _, endpoint := range native.Containers {
		prefix, err := netip.ParsePrefix(endpoint.IPv4Address)
		if err == nil && prefix.Addr() == address {
			return &CapabilityError{Feature: "AmazonProvidedDNS address conflicts with a native endpoint"}
		}
	}
	output, err := m.helper(ctx, a.arn, []string{"ip", "-j", "address", "show", "dev", a.bridge.Device}, nil)
	if err != nil {
		return err
	}
	var interfaces []struct {
		Addresses []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(output, &interfaces); err != nil {
		return err
	}
	for _, device := range interfaces {
		for _, existing := range device.Addresses {
			if existing.Local == address.String() {
				if existing.Prefix != 32 {
					return errors.New("native DNS address has incompatible prefix")
				}
				return nil
			}
		}
	}
	if _, err := m.helper(ctx, a.arn, []string{"arping", "-D", "-c", "2", "-w", "2", "-I", a.bridge.Device, address.String()}, nil); err != nil {
		return fmt.Errorf("native DNS address conflict probe failed: %w", err)
	}
	_, err = m.helper(ctx, a.arn, []string{"ip", "address", "add", address.String() + "/32", "dev", a.bridge.Device}, nil)
	return err
}

type dnsInspection struct {
	ID     string `json:"Id"`
	Config struct {
		Image      string
		Entrypoint []string
		Labels     map[string]string
	}
	State struct {
		Running  bool
		Error    string
		ExitCode int
	}
}

func dockerMissing(err error) bool {
	var native *docker.Error
	return errors.As(err, &native) && native.StatusCode == http.StatusNotFound
}

func (m *GuestNetworkManager) inspectDNS(ctx context.Context, networkID string) (dnsInspection, error) {
	var existing dnsInspection
	err := m.config.Docker.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(dnsContainer(networkID))+"/json", nil, &existing)
	if err == nil && existing.Config.Labels[guestNetworkLabel] != networkID {
		return existing, errors.New("native DNS container belongs to another owner")
	}
	return existing, err
}

func (m *GuestNetworkManager) ensureDNSDaemon(ctx context.Context, a *guestAttachment) error {
	directory := m.dnsDirectory(a.spec.NetworkID)
	mask := net.IP(net.CIDRMask(a.spec.Pool.Bits(), 32)).String()
	command := []string{m.loader, "--library-path", "/native-lib/x86_64-linux-gnu", "/native-dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null", "--user=root", "--group=root", "--no-resolv", "--no-hosts", "--bind-interfaces", "--except-interface=lo", "--interface=" + a.bridge.Device, "--listen-address=" + dnsAddress(a.spec).String(), "--dhcp-range=" + a.spec.Pool.Masked().Addr().String() + ",static," + mask + ",infinite", "--dhcp-hostsdir=/state/dhcp", "--dhcp-optsdir=/state/options", "--hostsdir=/state/hosts", "--dhcp-ignore=tag:!known", "--dhcp-ignore-clid", "--leasefile-ro", "--pid-file=", "--log-facility=-", "--domain-needed"}
	if !a.spec.DNSSupport {
		command = append(command, "--port=0")
	}
	for _, domain := range strings.Fields(a.spec.DomainName) {
		command = append(command, "--local=/"+domain+"/")
	}
	for _, address := range m.config.DNSUpstream {
		if address == dnsAddress(a.spec) {
			return errors.New("native DNS upstream cannot refer to its own listener")
		}
		command = append(command, "--server="+address.String())
	}
	existing, err := m.inspectDNS(ctx, a.spec.NetworkID)
	if err != nil && !dockerMissing(err) {
		return err
	}
	if err == nil && (!slices.Equal(existing.Config.Entrypoint, command) || existing.Config.Image != docker.ToolkitImage) {
		if err := m.config.Docker.RemoveContainer(ctx, existing.ID); err != nil {
			return err
		}
		existing = dnsInspection{}
	}
	path := "/containers/" + url.PathEscape(dnsContainer(a.spec.NetworkID))
	if existing.ID == "" {
		config := docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: command, Labels: map[string]string{guestNetworkLabel: a.spec.NetworkID, "stackd.ec2.dns.bridge": a.bridge.Device}, HostConfig: docker.ContainerHostConfig{
			NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN", "NET_RAW", "NET_BIND_SERVICE", "SETUID", "SETGID", "DAC_OVERRIDE"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32,
			Mounts: []docker.ContainerMount{{Type: "bind", Source: m.libraries, Target: "/native-lib", ReadOnly: true}, {Type: "bind", Source: m.config.DNSMasqBinary, Target: "/native-dnsmasq", ReadOnly: true}, {Type: "bind", Source: directory, Target: "/state", ReadOnly: true}}, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
		}}
		if err := m.config.Docker.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(dnsContainer(a.spec.NetworkID)), config, nil); err != nil {
			return err
		}
	}
	if !existing.State.Running {
		if err := m.config.Docker.JSON(ctx, http.MethodPost, path+"/start", nil, nil); err != nil {
			return err
		}
	}
	// HUP reloads native directories including removed entries. Inotify alone
	// does not retire deleted records from every dnsmasq input directory.
	if err := m.config.Docker.JSON(ctx, http.MethodPost, path+"/kill?signal=HUP", nil, nil); err != nil {
		return err
	}
	observed, err := m.inspectDNS(ctx, a.spec.NetworkID)
	if err != nil {
		return err
	}
	if !observed.State.Running {
		return fmt.Errorf("native dnsmasq exited (%d): %s", observed.State.ExitCode, observed.State.Error)
	}
	return a.probeDNS(ctx)
}

func (a *guestAttachment) probeDNS(ctx context.Context) error {
	if !a.spec.DNSSupport {
		return nil
	}
	names := []string{a.spec.Hostname, a.spec.PublicHostname}
	domains := strings.Fields(a.spec.DomainName)
	if names[0] != "" && !strings.Contains(names[0], ".") && len(domains) > 0 {
		names[0] += "." + domains[0]
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", net.JoinHostPort(dnsAddress(a.spec).String(), "53"))
	}}
	for _, name := range names {
		if name == "" {
			continue
		}
		addresses, err := resolver.LookupNetIP(ctx, "ip4", name+".")
		if err != nil {
			return fmt.Errorf("native VPC DNS readiness for %s: %w", name, err)
		}
		if !slices.Contains(addresses, a.spec.Address) {
			return fmt.Errorf("native VPC DNS did not resolve %s to its owned private address", name)
		}
	}
	return nil
}

// Removing a reservation and sending SIGHUP does not release dnsmasq's infinite
// MAC lease. Retire that native lease before EC2 can reuse the address.
func (m *GuestNetworkManager) releaseDHCPLease(ctx context.Context, arn string, spec network.Specification, bridge string) error {
	_, err := docker.RunHelper(ctx, m.config.Docker, "ec2-dhcp-release", docker.ContainerConfig{
		Image:      docker.ToolkitImage,
		Entrypoint: []string{m.releaseLoader, "--library-path", "/native-lib/x86_64-linux-gnu", "/native-dhcp-release", bridge, spec.Address.String(), spec.MAC},
		Labels:     map[string]string{guestNetworkLabel: arn},
		HostConfig: docker.ContainerHostConfig{
			NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN", "NET_RAW"},
			SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32,
			Mounts: []docker.ContainerMount{
				{Type: "bind", Source: m.libraries, Target: "/native-lib", ReadOnly: true},
				{Type: "bind", Source: m.config.DHCPReleaseBinary, Target: "/native-dhcp-release", ReadOnly: true},
			},
			LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
		},
	})
	return err
}

func (m *GuestNetworkManager) removeDNS(ctx context.Context, arn string, spec network.Specification) error {
	if spec.NetworkID == "" {
		return errors.New("VPC identity required for native DNS cleanup")
	}
	existing, err := m.inspectDNS(ctx, spec.NetworkID)
	if err != nil && !dockerMissing(err) {
		return err
	}
	if err == nil && existing.State.Running {
		if err := m.releaseDHCPLease(ctx, arn, spec, existing.Config.Labels["stackd.ec2.dns.bridge"]); err != nil {
			return err
		}
	}
	directory := m.dnsDirectory(spec.NetworkID)
	for _, part := range []string{"dhcp", "options", "hosts"} {
		if err := os.Remove(filepath.Join(directory, part, identifier(arn))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// A controller crash can interrupt an atomic native-config rename. These
	// ignored temporary files are not active DHCP reservations.
	for _, part := range []string{"dhcp", "options", "hosts"} {
		entries, err := os.ReadDir(filepath.Join(directory, part))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".config-") && entry.Type().IsRegular() {
				if err := os.Remove(filepath.Join(directory, part, entry.Name())); err != nil {
					return err
				}
			}
		}
	}
	remaining, err := os.ReadDir(filepath.Join(directory, "dhcp"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(remaining) > 0 {
		if err != nil || !existing.State.Running {
			return errors.New("native DHCP owner unavailable while other guests remain")
		}
		return m.config.Docker.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(existing.ID)+"/kill?signal=HUP", nil, nil)
	}
	if existing.ID != "" {
		if err := m.config.Docker.RemoveContainer(ctx, existing.ID); err != nil {
			return err
		}
	}
	filters, _ := json.Marshal(map[string][]string{"label": {network.BridgeLabel + "=" + spec.NetworkID}})
	var bridges []struct {
		ID      string `json:"Id"`
		Driver  string
		Options map[string]string
	}
	if err := m.config.Docker.JSON(ctx, http.MethodGet, "/networks?filters="+url.QueryEscape(string(filters)), nil, &bridges); err != nil {
		return err
	}
	for _, bridge := range bridges {
		if bridge.Driver != "bridge" || len(bridge.ID) < 12 {
			return errors.New("native VPC bridge has invalid identity")
		}
		device := bridge.Options["com.docker.network.bridge.name"]
		if device == "" {
			device = "br-" + bridge.ID[:12]
		}
		output, err := m.helper(ctx, arn, []string{"ip", "-j", "address", "show", "dev", device}, nil)
		if err != nil {
			return err
		}
		var links []struct {
			Addresses []struct {
				Local  string `json:"local"`
				Prefix int    `json:"prefixlen"`
			} `json:"addr_info"`
		}
		if err := json.Unmarshal(output, &links); err != nil {
			return err
		}
		for _, link := range links {
			for _, address := range link.Addresses {
				if address.Local == dnsAddress(spec).String() && address.Prefix == 32 {
					if _, err := m.helper(ctx, arn, []string{"ip", "address", "del", address.Local + "/32", "dev", device}, nil); err != nil {
						return err
					}
				}
			}
		}
	}
	if err := m.dnsFirewall(ctx, arn, spec, "", false); err != nil {
		return err
	}
	for _, part := range []string{"dhcp", "options", "hosts"} {
		if err := os.Remove(filepath.Join(directory, part)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Remove(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (m *GuestNetworkManager) dnsFirewall(ctx context.Context, arn string, spec network.Specification, bridge string, install bool) error {
	name := "stackd_dns_" + identifier(spec.NetworkID)
	rules := "destroy table ip " + name + "\n"
	if install {
		rules += fmt.Sprintf("table ip %s {\n chain input { type filter hook input priority -200; policy accept;\n", name)
		if spec.DNSSupport {
			rules += fmt.Sprintf(`  iifname "lo" ip daddr { %s, %s } udp dport 53 accept
  iifname "lo" ip daddr { %s, %s } tcp dport 53 accept
  iifname %q ip saddr %s ip daddr { %s, %s } udp dport 53 accept
  iifname %q ip saddr %s ip daddr { %s, %s } tcp dport 53 accept
`, spec.Gateway, dnsAddress(spec), spec.Gateway, dnsAddress(spec), bridge, spec.Pool, spec.Gateway, dnsAddress(spec), bridge, spec.Pool, spec.Gateway, dnsAddress(spec))
		}
		// Native lease releases arrive through loopback with an ephemeral
		// source port. Host routing selects the source address, not the bridge.
		rules += fmt.Sprintf(`  iifname "lo" ip daddr %s udp dport 67 accept
  iifname %q ip saddr { 0.0.0.0, %s } udp sport 68 udp dport 67 accept
  ip daddr { %s, %s } udp dport { 53, 67 } counter drop
  ip daddr { %s, %s } tcp dport 53 counter drop
 }
}
`, spec.Gateway, bridge, spec.Pool, spec.Gateway, dnsAddress(spec), spec.Gateway, dnsAddress(spec))
	}
	_, err := m.helper(ctx, arn, []string{"/bin/sh", "-ec", "printf '%s' \"$RULES\" | nft -f -"}, []string{"RULES=" + rules})
	return err
}
