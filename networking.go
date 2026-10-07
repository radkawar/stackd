package stackd

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"slices"

	dnsruntime "stackd/compute/dns"
)

// NetworkingInfo describes configured instance boundaries, not resource readiness.
// The optional HTTP surface is local-only and never contains keys or credentials.
type NetworkingInfo struct {
	ListenAddress      string          `json:"listen_address,omitempty"`
	PublicEndpoint     string          `json:"public_endpoint,omitempty"`
	ComputeEndpoint    string          `json:"compute_endpoint,omitempty"`
	GatewayDomain      string          `json:"gateway_domain,omitempty"`
	GatewayAddresses   []string        `json:"gateway_addresses,omitempty"`
	DNSAddress         string          `json:"dns_address,omitempty"`
	DNSUpstreams       []string        `json:"dns_upstreams,omitempty"`
	DNSAllowedClients  []string        `json:"dns_allowed_clients,omitempty"`
	RuntimeDNS         []string        `json:"runtime_dns,omitempty"`
	TLSMode            string          `json:"tls_mode,omitempty"`
	TLSNames           []string        `json:"tls_names,omitempty"`
	CAFile             string          `json:"ca_file,omitempty"`
	NativePorts        string          `json:"native_ports,omitempty"`
	TransparentAddress string          `json:"transparent_address,omitempty"`
	TransparentDomains []string        `json:"transparent_domains,omitempty"`
	TransparentClients []string        `json:"transparent_clients,omitempty"`
	Runtimes           map[string]bool `json:"runtimes"`
	Readiness          string          `json:"readiness"`
}

func networkingInfo(config Config, server *dnsruntime.Server) *NetworkingInfo {
	if config.NetworkDiagnostics == nil {
		return nil
	}
	out := *config.NetworkDiagnostics
	out.PublicEndpoint, out.ComputeEndpoint = config.PublicEndpoint, config.ComputeEndpoint
	out.GatewayDomain = config.GatewayDomain
	out.GatewayAddresses = make([]string, len(config.GatewayAddresses))
	for i, address := range config.GatewayAddresses {
		out.GatewayAddresses[i] = address.String()
	}
	out.DNSAddress = ""
	if server != nil {
		out.DNSAddress = server.Address()
	}
	out.DNSUpstreams = make([]string, len(config.DNSUpstreams))
	for i, address := range config.DNSUpstreams {
		out.DNSUpstreams[i] = address.String()
	}
	out.DNSAllowedClients = make([]string, len(config.DNSAllowedClients))
	for i, prefix := range config.DNSAllowedClients {
		out.DNSAllowedClients[i] = prefix.String()
	}
	if len(config.DNSUpstreams) > 0 && len(out.DNSAllowedClients) == 0 {
		out.DNSAllowedClients = []string{"127.0.0.0/8", "::1/128"}
	}
	out.TransparentDomains = slices.Clone(config.TransparentDomains)
	out.TransparentClients = make([]string, len(config.TransparentClients))
	for i, prefix := range config.TransparentClients {
		out.TransparentClients[i] = prefix.String()
	}
	out.RuntimeDNS, out.TLSNames = slices.Clone(out.RuntimeDNS), slices.Clone(out.TLSNames)
	out.Runtimes = map[string]bool{
		"lambda":     config.LambdaExecutor != nil,
		"ecs":        config.ECSExecutor != nil,
		"codebuild":  config.CodeBuildExecutor != nil,
		"ec2":        config.EC2Executor != nil,
		"eks":        config.EKSRuntime != nil,
		"alb":        config.ELBV2Runtime != nil,
		"dynamodb":   config.DynamoDBRuntime != nil,
		"kinesis":    config.KinesisRuntime != nil,
		"rds":        config.RDSRuntime != nil,
		"documentdb": config.DocumentDBRuntime != nil,
		"opensearch": config.OpenSearchRuntime != nil,
		"msk":        config.MSKRuntime != nil,
		"mq":         config.MQRuntime != nil,
		"valkey":     config.ValkeyRuntime != nil,
		"glue":       config.GlueRuntime != nil,
		"athena":     config.AthenaRuntime != nil,
	}
	out.Readiness = "not_probed"
	return &out
}

func (s *Stack) serveNetworking(w http.ResponseWriter, r *http.Request) {
	if s.networking == nil {
		http.NotFound(w, r)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	peer, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || !peer.Unmap().IsLoopback() || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" {
		http.Error(w, "Networking diagnostics require a direct loopback connection", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(s.networking)
}
