package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"stackd"
	"stackd/compute/devtls"
	"stackd/compute/hostdns"
)

func runNetworkCommand(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if len(args) == 0 {
		return fmt.Errorf("network requires ca init/export, dns setup/teardown/status, or diagnose")
	}
	switch args[0] {
	case "ca":
		return runNetworkCA(ctx, args[1:])
	case "dns":
		return runNetworkDNS(ctx, args[1:])
	case "diagnose":
		return runNetworkDiagnose(ctx, args[1:])
	default:
		return fmt.Errorf("unknown network command %q", args[0])
	}
}

func runNetworkCA(ctx context.Context, args []string) error {
	if len(args) == 0 || (args[0] != "init" && args[0] != "export") {
		return fmt.Errorf("network ca requires init or export")
	}
	flags := flag.NewFlagSet("network ca "+args[0], flag.ContinueOnError)
	directory := flags.String("directory", "", "private persistent development CA directory")
	output := flags.String("output", "", "public PEM certificate export path; never exports a private key")
	var domains []string
	var ips []netip.Addr
	flags.Func("domain", "repeatable explicit development DNS suffix", func(value string) error { domains = append(domains, value); return nil })
	flags.Func("ip", "repeatable explicit development IP certificate SAN", func(value string) error { return appendNetworkIP(&ips, value) })
	if err := parseNetworkFlags(flags, args[1:]); err != nil {
		return err
	}
	if *directory == "" || (args[0] == "export" && *output == "") {
		return fmt.Errorf("CA command requires directory; export additionally requires output")
	}
	authority, err := devtls.Open(ctx, devtls.Config{Directory: *directory, Domains: domains, IPAddresses: ips})
	if err != nil {
		return err
	}
	if *output != "" {
		if err := authority.Export(*output); err != nil {
			return err
		}
	}
	return printNetworkJSON(struct {
		CAFile string `json:"ca_file"`
		Export string `json:"export,omitempty"`
	}{CAFile: authority.CAFile(), Export: *output})
}

func runNetworkDNS(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("network dns requires setup, teardown or status")
	}
	flags := flag.NewFlagSet("network dns "+args[0], flag.ContinueOnError)
	state := flags.String("state-directory", "", "private durable ownership receipt directory; use the same path for teardown")
	switch args[0] {
	case "setup":
		address := flags.String("address", "", "reachable resolver IP:port")
		iface := flags.String("interface", "", "Linux link for split DNS; empty creates an owned dummy link with an isolated scope address")
		var domains []string
		flags.Func("domain", "repeatable explicit DNS suffix routed to this resolver; no global resolver replacement", func(value string) error { domains = append(domains, value); return nil })
		if err := parseNetworkFlags(flags, args[1:]); err != nil {
			return err
		}
		if err := hostdns.Setup(ctx, hostdns.Config{Address: *address, Domains: domains, Interface: *iface, StateDirectory: *state}); err != nil {
			return err
		}
	case "teardown":
		if err := parseNetworkFlags(flags, args[1:]); err != nil {
			return err
		}
		if err := hostdns.Teardown(ctx, *state); err != nil {
			return err
		}
	case "status":
		if err := parseNetworkFlags(flags, args[1:]); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown network dns command %q", args[0])
	}
	report, err := hostdns.Status(ctx, *state)
	if err != nil {
		return err
	}
	return printNetworkJSON(report)
}

func parseNetworkFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments to %s", flags.Name())
	}
	return nil
}

func printNetworkJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

type networkProbe struct {
	Name      string   `json:"name"`
	Target    string   `json:"target"`
	Addresses []string `json:"addresses,omitempty"`
	Error     string   `json:"error,omitempty"`
	Succeeded bool     `json:"succeeded"`
}

func runNetworkDiagnose(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("network diagnose", flag.ContinueOnError)
	endpoint := flags.String("endpoint", "http://127.0.0.1:4566", "direct loopback API origin with network-diagnostics enabled")
	ca := flags.String("ca", "", "public PEM CA appended to this client's system trust roots")
	dns := flags.String("dns-address", "", "explicit resolver IP:port override; defaults to the reported service DNS listener")
	if err := parseNetworkFlags(flags, args); err != nil {
		return err
	}
	origin, err := url.Parse(*endpoint)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return fmt.Errorf("diagnostic endpoint must be a complete HTTP(S) origin")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			return fmt.Errorf("read public CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("load system trust: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("public CA file contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(*endpoint, "/")+"/_stackd/network", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("reach diagnostic endpoint: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("diagnostic endpoint returned %s; enable network-diagnostics and call from direct loopback", response.Status)
	}
	var info stackd.NetworkingInfo
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&info); err != nil {
		return fmt.Errorf("decode network configuration: %w", err)
	}
	resolverAddress := *dns
	if resolverAddress == "" {
		resolverAddress = info.DNSAddress
	}
	resolver := net.DefaultResolver
	if resolverAddress != "" {
		if _, err := netip.ParseAddrPort(resolverAddress); err != nil {
			return fmt.Errorf("diagnostic DNS address must be an IP:port: %w", err)
		}
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, resolverAddress)
		}}
	}
	probes := []networkProbe{{Name: "diagnostic_https_or_http", Target: *endpoint, Succeeded: true}}
	failed := false
	if info.GatewayDomain != "" && resolverAddress != "" {
		probe := networkProbe{Name: "gateway_dns", Target: info.GatewayDomain + " via " + resolverAddress}
		addresses, err := resolver.LookupHost(ctx, info.GatewayDomain)
		probe.Addresses = addresses
		probe.Succeeded = err == nil
		if err != nil {
			probe.Error = err.Error()
			failed = true
		}
		probes = append(probes, probe)
	}
	for _, value := range []struct{ name, origin string }{{"public_tcp", info.PublicEndpoint}, {"compute_tcp", info.ComputeEndpoint}} {
		if value.origin == "" {
			continue
		}
		address, err := url.Parse(value.origin)
		if err != nil {
			return fmt.Errorf("reported %s origin is invalid: %w", value.name, err)
		}
		port := address.Port()
		if port == "" {
			if address.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		probe := networkProbe{Name: value.name, Target: net.JoinHostPort(address.Hostname(), port)}
		connection, err := (&net.Dialer{Resolver: resolver, Timeout: 5 * time.Second}).DialContext(ctx, "tcp", probe.Target)
		probe.Succeeded = err == nil
		if err != nil {
			probe.Error = err.Error()
			failed = true
		} else {
			connection.Close()
		}
		probes = append(probes, probe)
	}
	if err := printNetworkJSON(struct {
		Perspective   string                `json:"perspective"`
		Configuration stackd.NetworkingInfo `json:"configuration"`
		Probes        []networkProbe        `json:"probes"`
	}{Perspective: "CLI host; not a VPC or customer container probe", Configuration: info, Probes: probes}); err != nil {
		return err
	}
	if failed {
		return errors.New("one or more actual networking probes failed")
	}
	return nil
}
