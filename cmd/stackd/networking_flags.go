package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"stackd"
	"stackd/compute/devtls"
	"stackd/compute/docker"
	"stackd/compute/ports"
)

type networkingFlags struct {
	domain             string
	addresses          []netip.Addr
	upstreams          []netip.AddrPort
	clients            []netip.Prefix
	runtimeDNS         []string
	runtimeCA          string
	caDirectory        string
	caDomains          []string
	caIPs              []netip.Addr
	portRange          ports.Range
	portRangeText      string
	diagnostics        bool
	transparentListen  string
	transparentDomains []string
	transparentIPs     []netip.Addr
	transparentClients []netip.Prefix
	authority          *devtls.Authority
}

func registerNetworkingFlags(flags *flag.FlagSet) *networkingFlags {
	n := &networkingFlags{}
	flags.StringVar(&n.domain, "gateway-domain", "", "explicit development DNS namespace for gateway and resource hostnames")
	flags.Func("gateway-address", "repeatable reachable IP returned for gateway-domain; no address is guessed", func(value string) error { return appendNetworkIP(&n.addresses, value) })
	flags.Func("dns-upstream", "repeatable explicit DNS IP:port for unowned recursive queries; empty keeps DNS offline", func(value string) error {
		address, err := netip.ParseAddrPort(value)
		if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() {
			return fmt.Errorf("DNS upstream must be a usable IP:port")
		}
		n.upstreams = append(n.upstreams, address)
		return nil
	})
	flags.Func("dns-allow-client", "repeatable client CIDR allowed upstream recursion; empty allows loopback only", func(value string) error { return appendNetworkPrefix(&n.clients, value) })
	flags.Func("runtime-dns", "repeatable reachable IPv4 resolver for managed containers (port 53); EC2 custom DHCP remains authoritative", func(value string) error {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsLoopback() {
			return fmt.Errorf("runtime DNS must be a non-loopback reachable IPv4 address")
		}
		n.runtimeDNS = append(n.runtimeDNS, address.String())
		return nil
	})
	flags.StringVar(&n.runtimeCA, "runtime-ca", "", "public PEM CA copied into managed customer containers for AWS SDK trust")
	flags.StringVar(&n.caDirectory, "dev-ca-directory", "", "private persistent development CA directory; enables HTTPS without disabling verification")
	flags.Func("dev-ca-domain", "repeatable explicit certificate DNS suffix; does not install or change DNS", func(value string) error {
		n.caDomains = append(n.caDomains, value)
		return nil
	})
	flags.Func("dev-ca-ip", "repeatable explicit IP certificate SAN for development HTTPS", func(value string) error { return appendNetworkIP(&n.caIPs, value) })
	flags.Func("native-ports", "inclusive FIRST-LAST pool for new automatic customer TCP engine ports; retained and explicit ports remain exact", func(value string) error {
		pool, err := ports.Parse(value)
		if err != nil {
			return err
		}
		n.portRange, n.portRangeText = pool, value
		return nil
	})
	flags.BoolVar(&n.diagnostics, "network-diagnostics", false, "enable direct-loopback-only read-only /_stackd/network configuration diagnostics")
	flags.StringVar(&n.transparentListen, "transparent-listen", "", "opt-in isolated AWS HTTPS listener on explicit IPv4 IP:443; requires development CA and transparent client/domain/address")
	flags.Func("transparent-domain", "repeatable AWS endpoint DNS suffix redirected only for explicitly allowed peers", func(value string) error {
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		if value != "amazonaws.com" && value != "amazonaws.com.cn" {
			return fmt.Errorf("transparent domain must be amazonaws.com or amazonaws.com.cn")
		}
		n.transparentDomains = append(n.transparentDomains, value)
		return nil
	})
	flags.Func("transparent-address", "repeatable reachable IP for opt-in transparent AWS DNS answers", func(value string) error { return appendNetworkIP(&n.transparentIPs, value) })
	flags.Func("transparent-client", "repeatable explicit workload CIDR allowed transparent DNS and HTTPS; no global prefix", func(value string) error {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() == 0 {
			return fmt.Errorf("transparent client must be a bounded workload CIDR")
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() <= 96 {
				return fmt.Errorf("transparent client must bound its mapped IPv4 workload")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		n.transparentClients = append(n.transparentClients, prefix.Masked())
		return nil
	})
	return n
}

func appendNetworkIP(target *[]netip.Addr, value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil || address.IsUnspecified() || address.IsMulticast() {
		return fmt.Errorf("network address must be an explicit unicast IP")
	}
	*target = append(*target, address.Unmap())
	return nil
}

func appendNetworkPrefix(target *[]netip.Prefix, value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	*target = append(*target, prefix.Masked())
	return nil
}

func (n *networkingFlags) prepareTLS(ctx context.Context, listen string, existing *tls.Config, dnsListen string) (*tls.Config, error) {
	if n.domain != "" && (dnsListen == "" || len(n.addresses) == 0) {
		return nil, fmt.Errorf("gateway-domain requires dns-listen and explicit gateway-address")
	}
	if len(n.upstreams) != 0 && dnsListen == "" {
		return nil, fmt.Errorf("dns-upstream requires an explicit dns-listen")
	}
	transparent := n.transparentListen != ""
	if transparent {
		address, err := netip.ParseAddrPort(n.transparentListen)
		if err != nil || !address.Addr().Is4() || address.Port() != 443 {
			return nil, fmt.Errorf("transparent-listen requires an explicit IPv4 IP:443")
		}
		if n.caDirectory == "" || dnsListen == "" || len(n.transparentIPs) == 0 || len(n.transparentDomains) == 0 || len(n.transparentClients) == 0 {
			return nil, fmt.Errorf("transparent routing requires dev-ca-directory, dns-listen, transparent-address, transparent-domain and transparent-client")
		}
	} else if len(n.transparentIPs)+len(n.transparentDomains)+len(n.transparentClients) != 0 {
		return nil, fmt.Errorf("transparent DNS options require transparent-listen")
	}
	if n.caDirectory == "" {
		if len(n.caIPs)+len(n.caDomains) != 0 {
			return nil, fmt.Errorf("dev-ca-ip and dev-ca-domain require dev-ca-directory")
		}
		return existing, nil
	}
	if existing != nil && len(existing.Certificates) > 0 {
		return nil, fmt.Errorf("dev-ca-directory and explicit tls-cert/tls-key are alternative trust workflows")
	}
	domains := append([]string(nil), n.caDomains...)
	domains = append(domains, n.transparentDomains...)
	if n.domain != "" {
		domains = append(domains, n.domain)
	}
	ips := append([]netip.Addr(nil), n.caIPs...)
	ips = append(ips, n.addresses...)
	ips = append(ips, n.transparentIPs...)
	if host, _, err := net.SplitHostPort(listen); err == nil {
		if address, err := netip.ParseAddr(host); err == nil && !address.IsUnspecified() {
			ips = append(ips, address.Unmap())
		}
	}
	authority, err := devtls.Open(ctx, devtls.Config{Directory: n.caDirectory, Domains: domains, IPAddresses: ips})
	if err != nil {
		return nil, fmt.Errorf("open development TLS authority: %w", err)
	}
	n.authority = authority
	if n.runtimeCA == "" {
		n.runtimeCA = authority.CAFile()
	}
	return authority.TLSConfig(), nil
}

func (n *networkingFlags) runtimeNetworking() docker.Networking {
	return docker.Networking{DNS: n.runtimeDNS, CAFile: n.runtimeCA}
}

func (n *networkingFlags) configure(config *stackd.Config, listen string, tlsEnabled bool) {
	config.GatewayDomain, config.GatewayAddresses = n.domain, n.addresses
	config.DNSUpstreams, config.DNSAllowedClients = n.upstreams, n.clients
	config.TransparentDomains, config.TransparentAddresses, config.TransparentClients = n.transparentDomains, n.transparentIPs, n.transparentClients
	if n.diagnostics {
		mode := "disabled"
		if tlsEnabled {
			mode = "configured"
		}
		var names []string
		ca := ""
		if n.authority != nil {
			mode = "development_ca"
			ca = n.authority.CAFile()
			names = append(names, n.caDomains...)
			if n.domain != "" {
				names = append(names, n.domain)
			}
			names = append(names, n.transparentDomains...)
		}
		config.NetworkDiagnostics = &stackd.NetworkingInfo{ListenAddress: listen, RuntimeDNS: n.runtimeDNS, TLSMode: mode, TLSNames: names, CAFile: ca, NativePorts: n.portRangeText, TransparentAddress: n.transparentListen}
	}
}

func (n *networkingFlags) transparentHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		peer, parseErr := netip.ParseAddr(host)
		allowed := false
		if err == nil && parseErr == nil {
			for _, prefix := range n.transparentClients {
				if prefix.Contains(peer.Unmap()) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			http.Error(w, "Transparent endpoint requires an explicitly allowed workload", http.StatusForbidden)
			return
		}
		// Do not proxy or rewrite: Host, URL and signed headers stay byte-exact.
		next.ServeHTTP(w, r)
	})
}
