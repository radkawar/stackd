package valkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"stackd/compute/network"
)

func managedTestSpec() Specification {
	spec := Specification{ID: "globally-unique-incarnation", ClusterARN: "arn:aws:elasticache:us-east-1:111111111111:replicationgroup:cache", Shards: 1, Replicas: 1, TLSEnabled: true, MemoryBytes: 32 << 20}
	for i, address := range []string{"10.20.0.10", "10.20.0.11"} {
		spec.Networks = append(spec.Networks, NodeNetwork{InterfaceID: []string{"eni-primary", "eni-replica"}[i], Network: network.Specification{NetworkID: "vpc-exact", Pool: netip.MustParsePrefix("10.20.0.0/24"), Gateway: netip.MustParseAddr("10.20.0.1"), Address: netip.MustParseAddr(address), MAC: []string{"02:00:00:00:00:10", "02:00:00:00:00:11"}[i]}})
	}
	return spec
}

func TestManagedNodesUseOnlyActualAddressesAndFixed6379(t *testing.T) {
	d := &Docker{namespace: "test", image: "installed-valkey"}
	spec := managedTestSpec()
	if err := validateSpecification(spec); err != nil {
		t.Fatal(err)
	}
	m, held, err := d.newManifest(t.Context(), spec)
	if err != nil || len(held) != 0 {
		t.Fatalf("managed mode reserved host ports: %v %v", held, err)
	}
	if err = m.validatePorts(); err != nil {
		t.Fatal(err)
	}
	deployment := deployment(m)
	for i, node := range deployment.Nodes {
		if node.Endpoint.Address != spec.Networks[i].Network.Address.String() || node.Endpoint.Port != 6379 {
			t.Fatalf("node endpoint differs from real reservation: %+v", node)
		}
		config := d.managedConfig(spec, nodeRole(i))
		owned := attachment(spec, i)
		if config.HostConfig.NetworkMode != owned.Bridge || len(config.NetworkingConfig.EndpointsConfig) != 1 {
			t.Fatal("managed container has alternate/native-host networking")
		}
		ep := config.NetworkingConfig.EndpointsConfig[owned.Bridge]
		if ep.IPAMConfig.IPv4Address != owned.Address.String() || ep.MacAddress != owned.MAC {
			t.Fatal("container substitutes its EC2 address/MAC")
		}
		if !strings.HasPrefix(config.Cmd[0], "while [ ! -e "+admissionGate+" ];") {
			t.Fatal("client starts before packet admission")
		}
		if !strings.HasPrefix(admissionGate, "/dev/shm/") || strings.Contains(config.Cmd[0], "127.0.0.1") {
			t.Fatal("gate persists on the data volume or listener bypasses EC2")
		}
		text := string(managedConfiguration(spec, m, i))
		for _, required := range []string{"bind " + owned.Address.String() + "\n", "protected-mode no\n", "port 0\ntls-port 6379\n", "tls-ca-cert-file /data/ca.crt\n", "tls-replication yes\n"} {
			if !strings.Contains(text, required) {
				t.Fatalf("missing protected config %q: %s", required, text)
			}
		}
		for _, forbidden := range []string{"127.0.0.1", "0.0.0.0", "bind *", "unixsocket ", "port 6379\n"} {
			if forbidden == "port 6379\n" {
				if strings.Contains(text, "\nport 6379\n") {
					t.Fatal("TLS has an alternate plaintext listener")
				}
				continue
			}
			if strings.Contains(text, forbidden) {
				t.Fatalf("alternate listener in config: %s", text)
			}
		}
	}
	if deployment.Nodes[0].Endpoint.Address == deployment.Nodes[1].Endpoint.Address {
		t.Fatal("primary and replica share an invented address")
	}
	spec.ClusterMode = true
	m = managedManifest(spec)
	if err = m.validatePorts(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(managedConfiguration(spec, m, 1)), "cluster-announce-ip 10.20.0.11\n") || m.Nodes[0].BusPort != 16379 || m.Nodes[1].BusPort != 16379 {
		t.Fatal("cluster bus escapes actual node identity")
	}
	spec.ClusterMode, spec.TLSEnabled = false, false
	m = managedManifest(spec)
	plain := string(managedConfiguration(spec, m, 0))
	if !strings.Contains(plain, "\nport 6379\ntls-port 0\n") || strings.Contains(plain, "\nport 0\n") || strings.Contains(plain, "127.0.0.1") {
		t.Fatal("plaintext managed mode substituted or added a listener")
	}
}

func TestManagedDescriptorRetainsScopeAndNoCachedPolicy(t *testing.T) {
	d := &Docker{namespace: "test", image: "installed-valkey"}
	spec := managedTestSpec()
	owner := descriptor(spec)
	if err := owner.validate(); err != nil {
		t.Fatal(err)
	}
	if owner.Partition != "aws" || owner.AccountID != "111111111111" || owner.Region != "us-east-1" {
		t.Fatal("durable descriptor omits parsed scope")
	}
	before := d.managedLabels(spec, "ownership")[labelPrefix+"descriptor"]
	spec.Networks[0].Network.DNS = []netip.Addr{netip.MustParseAddr("10.20.0.2")}
	spec.Networks[0].Network.Policy.SecurityIngress = []network.IPRule{{CIDR: netip.MustParsePrefix("0.0.0.0/0"), Protocol: 6, FromPort: 6379, ToPort: 6379}}
	after := d.managedLabels(spec, "ownership")[labelPrefix+"descriptor"]
	if before != after {
		t.Fatal("native descriptor persists DNS or packet policy")
	}
	for _, value := range owner.Networks {
		if value.Bridge == "" || value.PolicyTable == "" || !strings.Contains(value.PolicyOwner, spec.ClusterARN+"\x00"+spec.ID+"\x00") {
			t.Fatal("ID-only deletion lost native bridge/policy ownership")
		}
	}
	for _, change := range []func(*nativeDescriptor){
		func(v *nativeDescriptor) { v.AccountID = "222222222222" },
		func(v *nativeDescriptor) { v.Region = "us-west-2" },
		func(v *nativeDescriptor) { v.Networks[0].PolicyOwner = "foreign" },
		func(v *nativeDescriptor) { v.Networks[0].PolicyTable = "foreign" },
		func(v *nativeDescriptor) { v.Networks[0].Bridge = "foreign" },
	} {
		v := descriptor(spec)
		change(&v)
		if err := v.validate(); err == nil {
			t.Fatal("conflicting durable owner accepted")
		}
	}
	for _, change := range []func(*Specification){
		func(v *Specification) { v.ID = "new-incarnation" },
		func(v *Specification) {
			v.ClusterARN = "arn:aws:elasticache:us-east-1:222222222222:replicationgroup:cache"
		},
		func(v *Specification) {
			v.ClusterARN = "arn:aws:elasticache:us-west-2:111111111111:replicationgroup:cache"
		},
	} {
		other := spec
		change(&other)
		if err := d.checkManagedOwner(d.managedLabels(spec, "node-1"), other, "node-1"); err == nil {
			t.Fatal("scope/new-incarnation mismatch adopted existing native node")
		}
	}
	if err := d.checkManagedOwner(d.managedLabels(spec, "node-1"), spec, "node-2"); err == nil {
		t.Fatal("node-role mismatch accepted")
	}
}

func TestManagedPlacementRejectsMissingAndForeignIdentity(t *testing.T) {
	for _, change := range []func(*Specification){
		func(v *Specification) { v.ClusterARN = "" },
		func(v *Specification) { v.ClusterARN = "arn:aws:elasticache::111111111111:cluster:cache" },
		func(v *Specification) { v.Networks = v.Networks[:1] },
		func(v *Specification) { v.Networks[1].InterfaceID = v.Networks[0].InterfaceID },
		func(v *Specification) { v.Networks[1].Network.Address = v.Networks[0].Network.Address },
		func(v *Specification) { v.Networks[1].Network.MAC = v.Networks[0].Network.MAC },
		func(v *Specification) { v.Networks[0].Network.Address = netip.MustParseAddr("127.0.0.1") },
		func(v *Specification) { v.Networks[0].Network.NetworkID = "" },
	} {
		spec := managedTestSpec()
		change(&spec)
		if err := validateSpecification(spec); err == nil {
			t.Fatal("managed placement accepted incomplete/foreign identity")
		}
	}
}

func configuredTestCA(t *testing.T) *Docker {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "configured-fixture-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &Docker{ca: ca, caKey: key, certificate: certificate, tlsConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, ServerName: "127.0.0.1"}}
}
func TestManagedTLSUsesConfiguredRootAndActualIP(t *testing.T) {
	d := configuredTestCA(t)
	spec := managedTestSpec()
	for i, node := range spec.Networks {
		certificate, key, err := d.managedCertificate(node.Network.Address)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(certificate, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err = leaf.Verify(x509.VerifyOptions{Roots: d.tlsConfig.RootCAs, DNSName: node.Network.Address.String()}); err != nil {
			t.Fatalf("actual IP is not CA verified: %v", err)
		}
		if err = leaf.VerifyHostname("127.0.0.1"); err == nil {
			t.Fatal("managed leaf admits a host-loopback bypass")
		}
		if err = leaf.VerifyHostname(spec.Networks[1-i].Network.Address.String()); err == nil {
			t.Fatal("managed leaf adopted another node's reserved identity")
		}
		client := d.clientFor(managedManifest(spec), i)
		options := client.Options()
		if options.Addr != net.JoinHostPort(node.Network.Address.String(), "6379") || options.TLSConfig.ServerName != node.Network.Address.String() || options.TLSConfig.RootCAs != d.tlsConfig.RootCAs || options.TLSConfig.InsecureSkipVerify {
			t.Fatal("controller bypasses real address/root verification")
		}
		client.Close()
	}
	if _, _, err := (&Docker{}).managedCertificate(spec.Networks[0].Network.Address); err == nil {
		t.Fatal("managed TLS manufactured an unconfigured trust root")
	}
}

func managedTestState(t *testing.T, d *Docker, spec Specification, role string) containerState {
	t.Helper()
	config := d.managedConfig(spec, role)
	endpoints := map[string]any{}
	if role != "configuration" {
		index := 0
		if role == "node-2" {
			index = 1
		}
		n := attachment(spec, index)
		endpoints[n.Bridge] = map[string]any{"IPAddress": n.Address.String(), "Gateway": n.Gateway.String(), "MacAddress": n.MAC, "IPAMConfig": map[string]string{"IPv4Address": n.Address.String()}}
	}
	encoded, err := json.Marshal(map[string]any{"Id": role + "-native-id", "Image": d.image, "Config": config, "HostConfig": config.HostConfig, "Mounts": []map[string]any{{"Type": "volume", "Name": d.name(spec.ID, "data"), "Destination": "/data", "RW": true}}, "State": map[string]any{"Running": role != "configuration", "Status": "running"}, "NetworkSettings": map[string]any{"Networks": endpoints}})
	if err != nil {
		t.Fatal(err)
	}
	var state containerState
	if err = json.Unmarshal(encoded, &state); err != nil {
		t.Fatal(err)
	}
	return state
}
func TestManagedReopenedConfigurationIsFullyFenced(t *testing.T) {
	d := &Docker{namespace: "test", image: "installed-valkey"}
	spec := managedTestSpec()
	if err := d.checkManagedContainer(managedTestState(t, d, spec, "node-1"), spec, "node-1"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*containerState)
	}{
		{"scope", func(s *containerState) { s.Config.Labels[labelPrefix+"account"] = "222222222222" }},
		{"incarnation", func(s *containerState) { s.Config.Labels[labelPrefix+"id"] = "replacement" }},
		{"role", func(s *containerState) { s.Config.Labels[labelPrefix+"role"] = "node-2" }},
		{"ungated-command", func(s *containerState) { s.Config.Cmd[0] = "exec valkey-server" }},
		{"host-network", func(s *containerState) { s.HostConfig.NetworkMode = "host" }},
		{"published-port", func(s *containerState) { s.HostConfig.PublishAllPorts = true }},
		{"host-ipc", func(s *containerState) { s.HostConfig.IpcMode = "host" }},
		{"root", func(s *containerState) { s.Config.User = "root" }},
		{"environment", func(s *containerState) { s.Config.Env = append(s.Config.Env, "LD_PRELOAD=/data/foreign.so") }},
		{"capabilities", func(s *containerState) { s.HostConfig.CapAdd = []string{"NET_ADMIN"} }},
		{"restart-bypass", func(s *containerState) { s.HostConfig.RestartPolicy.Name = "always" }},
		{"mount", func(s *containerState) { s.HostConfig.Mounts[0].Source = "foreign" }},
		{"address", func(s *containerState) {
			n := attachment(spec, 0)
			ep := s.NetworkSettings.Networks[n.Bridge]
			ep.IPAddress = "10.20.0.99"
			s.NetworkSettings.Networks[n.Bridge] = ep
		}},
		{"reserved-ipam", func(s *containerState) {
			n := attachment(spec, 0)
			ep := s.NetworkSettings.Networks[n.Bridge]
			ep.IPAMConfig.IPv4Address = "10.20.0.99"
			s.NetworkSettings.Networks[n.Bridge] = ep
		}},
		{"extra-interface", func(s *containerState) {
			n := attachment(spec, 0)
			s.NetworkSettings.Networks["alternate"] = s.NetworkSettings.Networks[n.Bridge]
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := managedTestState(t, d, spec, "node-1")
			test.change(&state)
			if err := d.checkManagedContainer(state, spec, "node-1"); err == nil {
				t.Fatal("conflicting reopened native resource was accepted")
			}
		})
	}
}

func TestManagedPacketPolicyHasNoControllerOrLoopbackExemption(t *testing.T) {
	spec := managedTestSpec()
	node := spec.Networks[0]
	cidr := netip.MustParsePrefix("10.20.0.0/24")
	current := node
	current.Network.DNS = []netip.Addr{netip.MustParseAddr("10.20.0.2")}
	current.Network.Policy = network.Policy{Subnet: cidr,
		SecurityIngress: []network.IPRule{{CIDR: cidr, Protocol: 6, FromPort: 6379, ToPort: 6379}},
		ACLIngress:      []network.ACLRule{{Number: 100, Allow: true, Rule: network.IPRule{CIDR: cidr, Protocol: 6, FromPort: 6379, ToPort: 6379}}},
	}
	if !sameAttachment(node, current) {
		t.Fatal("current policy/DHCP observation changed immutable reservation identity")
	}
	owner := attachment(spec, 0)
	rules, err := network.Rules(owner.PolicyTable, current.Network, current.Network.Policy, "owned-veth", network.Options{PublicOwner: owner.PolicyOwner})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"ether saddr != " + node.Network.MAC, "ip daddr " + node.Network.Address.String(), "tcp dport 6379", "jump acl_to\nct state invalid", "counter drop"} {
		if !strings.Contains(rules, required) {
			t.Fatalf("native packet policy lost exact EC2 admission %q", required)
		}
	}
	for _, forbidden := range []string{"127.0.0.1", "169.254.169.254 tcp", "tcp dport 0 return", "udp dport 53 return"} {
		if strings.Contains(rules, forbidden) {
			t.Fatalf("managed native policy has an alternate controller exemption: %q", forbidden)
		}
	}
	for _, change := range []func(*NodeNetwork){
		func(n *NodeNetwork) { n.InterfaceID = "foreign" },
		func(n *NodeNetwork) { n.Network.NetworkID = "foreign" },
		func(n *NodeNetwork) { n.Network.Pool = netip.MustParsePrefix("10.20.0.0/16") },
		func(n *NodeNetwork) { n.Network.Gateway = netip.MustParseAddr("10.20.0.2") },
		func(n *NodeNetwork) { n.Network.Address = netip.MustParseAddr("10.20.0.99") },
		func(n *NodeNetwork) { n.Network.MAC = "02:00:00:00:00:99" },
	} {
		changed := node
		change(&changed)
		if sameAttachment(node, changed) {
			t.Fatal("current observation adopted a different immutable reservation")
		}
	}
}
