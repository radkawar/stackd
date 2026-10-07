package ecs

import (
	"net/netip"
	"slices"
	"testing"

	"stackd/compute/docker"
	"stackd/compute/network"
)

func TestTaskDNSAdaptsOnlyEnabledAmazonProvidedDNS(t *testing.T) {
	spec := network.Specification{Pool: netip.MustParsePrefix("10.70.0.0/16"), DNS: []netip.Addr{netip.MustParseAddr("10.70.9.53"), netip.MustParseAddr("10.70.0.2")}, DNSSupport: true, DomainName: "ec2.internal"}
	unset := &DockerExecutor{}
	if servers, search, err := unset.taskDNS(spec); err != nil || servers != nil || search != nil {
		t.Fatalf("unset runtime DNS changed daemon resolver defaults: %v %v %v", servers, search, err)
	}
	selected := &DockerExecutor{networking: docker.Networking{DNS: []string{"192.0.2.53"}}}
	servers, search, err := selected.taskDNS(spec)
	if err != nil || !slices.Equal(servers, []string{"10.70.9.53", "192.0.2.53"}) || !slices.Equal(search, []string{"ec2.internal"}) {
		t.Fatalf("custom DHCP order or provider adaptation lost: %v %v %v", servers, search, err)
	}
	spec.DNSSupport, spec.DomainName = false, ""
	servers, search, err = selected.taskDNS(spec)
	if err != nil || !slices.Equal(servers, []string{"10.70.9.53"}) || !slices.Equal(search, []string{"."}) {
		t.Fatalf("disabled VPC DNS reached runtime resolver: %v %v %v", servers, search, err)
	}
	spec.DNS = []netip.Addr{netip.MustParseAddr("10.70.0.2")}
	if servers, _, err = selected.taskDNS(spec); err != nil || !slices.Equal(servers, []string{"127.0.0.1"}) {
		t.Fatalf("disabled AmazonProvidedDNS fell back to a resolver: %v %v", servers, err)
	}
}
