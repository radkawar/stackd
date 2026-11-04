package eks

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestDecodePodRouteNamespace(t *testing.T) {
	const header = "owned-worker\nIface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
	const route = "cni0 00002A0A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n"
	name, prefix, err := decodePodRouteNamespace(header + "eth0 00000000 010012AC 0003 0 0 0 00000000 0 0 0\n" + route)
	if err != nil || name != "owned-worker" || prefix.String() != "10.42.0.0/24" {
		t.Fatalf("decode connected pod bridge route: %s %s %v", name, prefix, err)
	}
	for name, text := range map[string]string{
		"absent":             header,
		"foreign interface":  header + strings.Replace(route, "cni0", "flannel.1", 1),
		"ambiguous":          header + route + route,
		"down route":         header + strings.Replace(route, "0001", "0000", 1),
		"gateway route":      header + strings.Replace(route, "00000000", "01002A0A", 1),
		"noncontiguous mask": header + strings.Replace(route, "00FFFFFF", "00FF00FF", 1),
		"default route":      header + strings.Replace(route, "00FFFFFF", "00000000", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodePodRouteNamespace(text); err == nil {
				t.Fatal("accepted unauthoritative native pod prefix")
			}
		})
	}
}

func TestWitnessedPodRoutesRequireNativeIncarnation(t *testing.T) {
	state := diskState{ID: "route-cluster", Token: strings.Repeat("a", 64)}
	worker := podRouteWorker{Name: "owned-worker", ContainerID: strings.Repeat("b", 64), IP: netip.MustParseAddr("172.20.0.3"), Prefix: netip.MustParsePrefix("10.42.0.0/24")}
	workers := map[string]podRouteWorker{worker.Name: worker}
	newNode := func() podRouteNode {
		var node podRouteNode
		if err := json.Unmarshal([]byte(`{"metadata":{"name":"owned-worker","uid":"node-incarnation","resourceVersion":"19"},"spec":{"podCIDR":"10.42.0.0/24","podCIDRs":["10.42.0.0/24"]},"status":{"addresses":[{"type":"InternalIP","address":"172.20.0.3"}],"conditions":[{"type":"Ready","status":"True"}]}}`), &node); err != nil {
			t.Fatal(err)
		}
		return node
	}
	networkID := strings.Repeat("c", 64)
	routes, err := witnessedPodRoutes(state, networkID, []podRouteNode{newNode()}, workers)
	if err != nil || len(routes) != 1 {
		t.Fatalf("native matching witness: %v %#v", err, routes)
	}
	route := routes[0]
	if route.ClusterID != state.ID || route.OwnerToken != state.Token || route.NetworkID != networkID || route.ContainerID != worker.ContainerID || route.NodeUID != "node-incarnation" || route.ResourceVersion != "19" || route.WorkerIP != worker.IP || route.Prefix != worker.Prefix {
		t.Fatalf("lost incarnation witness: %#v", route)
	}
	for name, mutate := range map[string]func(*podRouteNode){
		"foreign name":        func(n *podRouteNode) { n.Metadata.Name = "foreign-worker" },
		"missing UID":         func(n *podRouteNode) { n.Metadata.UID = "" },
		"missing version":     func(n *podRouteNode) { n.Metadata.ResourceVersion = "" },
		"deleting":            func(n *podRouteNode) { value := "2030-01-01T00:00:00Z"; n.Metadata.DeletionTimestamp = &value },
		"not ready":           func(n *podRouteNode) { n.Status.Conditions[0].Status = "False" },
		"foreign address":     func(n *podRouteNode) { n.Status.Addresses[0].Address = "172.20.0.4" },
		"missing prefix":      func(n *podRouteNode) { n.Spec.PodCIDRs = nil },
		"foreign prefix":      func(n *podRouteNode) { n.Spec.PodCIDR = "10.99.0.0/24"; n.Spec.PodCIDRs[0] = n.Spec.PodCIDR },
		"noncanonical prefix": func(n *podRouteNode) { n.Spec.PodCIDR = "10.42.0.1/24"; n.Spec.PodCIDRs[0] = n.Spec.PodCIDR },
		"ambiguous prefixes":  func(n *podRouteNode) { n.Spec.PodCIDRs = append(n.Spec.PodCIDRs, "10.43.0.0/24") },
	} {
		t.Run(name, func(t *testing.T) {
			node := newNode()
			mutate(&node)
			if _, err := witnessedPodRoutes(state, networkID, []podRouteNode{node}, workers); err == nil {
				t.Fatal("accepted untrusted routing witness")
			}
		})
	}
	if _, err := witnessedPodRoutes(state, networkID, nil, workers); err == nil {
		t.Fatal("accepted disappeared node")
	}
	if _, err := witnessedPodRoutes(state, networkID, []podRouteNode{newNode(), newNode()}, workers); err == nil {
		t.Fatal("accepted duplicate node")
	}
}

func TestWitnessedPodRoutesRejectOverlappingWorkers(t *testing.T) {
	workers := make(map[string]podRouteWorker)
	var nodes []podRouteNode
	for _, name := range []string{"worker-a", "worker-b"} {
		worker := podRouteWorker{Name: name, ContainerID: strings.Repeat("b", 64), IP: netip.MustParseAddr("172.20.0.3"), Prefix: netip.MustParsePrefix("10.42.0.0/24")}
		workers[name] = worker
		var node podRouteNode
		node.Metadata.Name, node.Metadata.UID, node.Metadata.ResourceVersion = name, name+"-uid", "1"
		node.Spec.PodCIDR, node.Spec.PodCIDRs = worker.Prefix.String(), []string{worker.Prefix.String()}
		node.Status.Addresses = append(node.Status.Addresses, struct{ Type, Address string }{"InternalIP", worker.IP.String()})
		node.Status.Conditions = append(node.Status.Conditions, struct{ Type, Status string }{"Ready", "True"})
		nodes = append(nodes, node)
	}
	if _, err := witnessedPodRoutes(diskState{ID: "cluster"}, "network", nodes, workers); err == nil {
		t.Fatal("accepted overlapping native worker prefixes")
	}
}
