package network

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// PodRoute is a current, authoritative Kubernetes node PodCIDR and its exact
// owned Docker next hop. NetworkID is the immutable Docker network ID, not the
// logical VPC identity. NodeUID fences recreated nodes; ResourceVersion records
// observation freshness, not packet-path identity. Equality includes the receipt
// so it refreshes without replacing a still-witnessed native path.
type PodRoute struct {
	Prefix          netip.Prefix
	ClusterID       string
	OwnerToken      string
	NodeName        string
	NodeUID         string
	ResourceVersion string
	ContainerID     string
	NetworkID       string
	WorkerIP        netip.Addr
}

// PodRouteInstallError means a pod-bearing native transaction failed. The
// caller may retry the same current EC2 policy without PodRoutes to withdraw
// pod authority while retaining unrelated backends. A failed base retry must
// still use the runtime's ordinary fail-closed path.
type PodRouteInstallError struct {
	Err error
}

func (e *PodRouteInstallError) Error() string { return "install pod packet routes: " + e.Err.Error() }
func (e *PodRouteInstallError) Unwrap() error { return e.Err }

func podRouteEnvironment(routes []PodRoute) (string, error) {
	if len(routes) == 0 {
		return "POD_ROUTES=[]", nil
	}
	data, err := json.Marshal(routes)
	return "POD_ROUTES=" + string(data), err
}

// This is routing admission only. Returning from public_* still evaluates the
// attachment's ordered NACL and security groups. Unsolicited pod-originated
// connections do not acquire an inbound exemption.
func writePodAdmission(b *strings.Builder, routes []PodRoute, direction string) {
	for _, route := range routes {
		if direction == "from" {
			fmt.Fprintf(b, "ip daddr %s return\n", route.Prefix)
		} else {
			fmt.Fprintf(b, "ip saddr %s ct state established,related ct direction reply return\n", route.Prefix)
		}
	}
}
