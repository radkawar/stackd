package eks

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"stackd/compute/network"
)

// ObservePodRoutes witnesses the live Kubernetes routing domain, rather than
// trusting provider IDs, node labels, or caller-supplied pod addresses. The EKS
// service owns AWS scope admission; this optional capability owns native facts.
func (k *K3d) ObservePodRoutes(ctx context.Context, spec Specification) ([]network.PodRoute, error) {
	k.op.Lock()
	defer k.op.Unlock()
	c, err := k.workerCluster(spec.ID)
	if err != nil {
		return nil, err
	}
	state, err := readState(c.dir, spec.ID)
	if err != nil {
		return nil, err
	}
	if !state.Ready || state.Deleting || state.Token != c.state.Token || state.DockerHost != k.config.DockerHost {
		return nil, errors.New("eks: pod routing requires the current attached cluster incarnation")
	}
	networkID, err := k.ownedNetwork(ctx, state)
	if err != nil || networkID == "" {
		return nil, fmt.Errorf("eks: pod routing network authority unavailable: %w", errors.Join(err, errors.New("owned native network required")))
	}
	containers, err := k.ownedContainers(ctx, state)
	if err != nil {
		return nil, err
	}
	var nodes podRouteNodeList
	if _, err := c.workerRequest(ctx, http.MethodGet, "/api/v1/nodes", nil, &nodes); err != nil {
		return nil, err
	}
	workers := make(map[string]podRouteWorker)
	for _, container := range containers {
		// The server deliberately has no kubelet, and tools are not workers.
		if container.Name == "/k3d-"+state.Name+"-server-0" || container.Name == "/k3d-"+state.Name+"-tools" {
			continue
		}
		worker, err := k.observePodRouteWorker(ctx, state, networkID, container.ID)
		if err != nil {
			return nil, err
		}
		if _, duplicate := workers[worker.Name]; duplicate {
			return nil, errors.New("eks: ambiguous native pod routing worker")
		}
		workers[worker.Name] = worker
	}
	routes, err := witnessedPodRoutes(state, networkID, nodes.Items, workers)
	if err != nil {
		return nil, err
	}
	// Refuse a Kubernetes replacement or prefix change during observation. A
	// resourceVersion-only change (for example a heartbeat) is not a new route.
	var current podRouteNodeList
	if _, err := c.workerRequest(ctx, http.MethodGet, "/api/v1/nodes", nil, &current); err != nil {
		return nil, err
	}
	latest, err := witnessedPodRoutes(state, networkID, current.Items, workers)
	if err != nil {
		return nil, err
	}
	if len(routes) != len(latest) {
		return nil, errors.New("eks: Kubernetes routing domain changed during observation")
	}
	for i := range routes {
		old, now := routes[i], latest[i]
		old.ResourceVersion = now.ResourceVersion
		if old != now {
			return nil, errors.New("eks: Kubernetes routing incarnation changed during observation")
		}
	}
	for _, worker := range workers {
		now, err := k.observePodRouteWorker(ctx, state, networkID, worker.ContainerID)
		if err != nil {
			return nil, err
		}
		if worker != now {
			return nil, errors.New("eks: native worker routing incarnation changed during observation")
		}
	}
	return latest, nil
}

type podRouteNodeList struct {
	Items []podRouteNode `json:"items"`
}

type podRouteNode struct {
	Metadata struct {
		Name, UID, ResourceVersion string
		DeletionTimestamp          *string
	}
	Spec struct {
		PodCIDR  string
		PodCIDRs []string
	}
	Status struct {
		Addresses  []struct{ Type, Address string }
		Conditions []struct{ Type, Status string }
	}
}

type podRouteWorker struct {
	Name, ContainerID string
	IP                netip.Addr
	Prefix            netip.Prefix
}

func (k *K3d) observePodRouteWorker(ctx context.Context, state diskState, networkID, id string) (podRouteWorker, error) {
	var worker podRouteWorker
	out, err := k.command(ctx, "docker", "container", "inspect", id)
	if err != nil {
		return worker, err
	}
	var inspected []struct {
		ID     string `json:"Id"`
		Name   string
		Config struct {
			Hostname string
			Labels   map[string]string
		}
		State           struct{ Running bool }
		NetworkSettings struct {
			Networks map[string]struct{ NetworkID, IPAddress string }
		}
	}
	if err := json.Unmarshal(out, &inspected); err != nil {
		return worker, err
	}
	if len(inspected) != 1 {
		return worker, errors.New("eks: ambiguous native worker inspection")
	}
	v := inspected[0]
	link, attached := v.NetworkSettings.Networks[state.Name]
	ip, err := netip.ParseAddr(link.IPAddress)
	if v.ID != id || !exactRouteID(id) || !v.State.Running || v.Config.Labels[ownerLabel] != state.Token || v.Config.Labels[idLabel] != state.ID || !attached || len(v.NetworkSettings.Networks) != 1 || link.NetworkID != networkID || err != nil || !ip.Is4() || ip.IsUnspecified() || v.Name != "/"+v.Config.Hostname {
		return worker, errors.New("eks: native pod routing worker ownership or network incarnation differs")
	}
	// /proc is read inside the exact native namespace. Unlike Kubernetes node
	// annotations, this observes the interface actually carrying pod traffic.
	out, err = k.command(ctx, "docker", "exec", id, "cat", "/proc/sys/kernel/hostname", "/proc/net/route")
	if err != nil {
		return worker, fmt.Errorf("eks: witness native pod routing namespace: %w", err)
	}
	name, prefix, err := decodePodRouteNamespace(string(out))
	if err != nil {
		return worker, err
	}
	if name != v.Config.Hostname {
		return worker, errors.New("eks: native worker hostname differs from owned incarnation")
	}
	return podRouteWorker{Name: name, ContainerID: id, IP: ip, Prefix: prefix}, nil
}

func exactRouteID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 32 && id == strings.ToLower(id)
}

func decodePodRouteNamespace(text string) (string, netip.Prefix, error) {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) < 3 || len(strings.Fields(lines[0])) != 1 {
		return "", netip.Prefix{}, errors.New("eks: invalid native worker routing namespace")
	}
	var prefix netip.Prefix
	for _, line := range lines[2:] {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] != "cni0" || fields[2] != "00000000" {
			continue
		}
		destination, e1 := strconv.ParseUint(fields[1], 16, 32)
		mask, e2 := strconv.ParseUint(fields[7], 16, 32)
		flags, e3 := strconv.ParseUint(fields[3], 16, 32)
		if e1 != nil || e2 != nil || e3 != nil || flags&1 == 0 {
			return "", prefix, errors.New("eks: invalid native pod bridge route")
		}
		var address, netmask [4]byte
		binary.LittleEndian.PutUint32(address[:], uint32(destination))
		binary.LittleEndian.PutUint32(netmask[:], uint32(mask))
		bits, zero := 0, false
		for _, octet := range netmask {
			for bit := 7; bit >= 0; bit-- {
				if octet&(1<<bit) == 0 {
					zero = true
				} else if zero {
					return "", prefix, errors.New("eks: noncontiguous native pod bridge mask")
				} else {
					bits++
				}
			}
		}
		next := netip.PrefixFrom(netip.AddrFrom4(address), bits)
		if bits < 1 || bits > 30 || next != next.Masked() || prefix.IsValid() {
			return "", prefix, errors.New("eks: ambiguous native pod bridge prefix")
		}
		prefix = next
	}
	if !prefix.IsValid() {
		return "", prefix, errors.New("eks: native worker has no current pod bridge route")
	}
	return strings.TrimSpace(lines[0]), prefix, nil
}

func witnessedPodRoutes(state diskState, networkID string, nodes []podRouteNode, workers map[string]podRouteWorker) ([]network.PodRoute, error) {
	if len(nodes) == 0 || len(nodes) != len(workers) {
		return nil, errors.New("eks: Kubernetes nodes do not match exact-owned native workers")
	}
	routes := make([]network.PodRoute, 0, len(nodes))
	seen := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		worker, found := workers[node.Metadata.Name]
		if !found || seen[node.Metadata.Name] || node.Metadata.UID == "" || node.Metadata.ResourceVersion == "" || node.Metadata.DeletionTimestamp != nil {
			return nil, errors.New("eks: foreign, replaced or deleting Kubernetes node")
		}
		seen[node.Metadata.Name] = true
		ready := false
		for _, condition := range node.Status.Conditions {
			if condition.Type == "Ready" {
				ready = condition.Status == "True"
			}
		}
		internal := ""
		for _, address := range node.Status.Addresses {
			if address.Type == "InternalIP" {
				if internal != "" {
					return nil, errors.New("eks: ambiguous node InternalIP")
				}
				internal = address.Address
			}
		}
		if !ready || internal != worker.IP.String() || len(node.Spec.PodCIDRs) != 1 || node.Spec.PodCIDR != node.Spec.PodCIDRs[0] {
			return nil, errors.New("eks: node readiness, address or PodCIDRs differ from native worker")
		}
		prefix, err := netip.ParsePrefix(node.Spec.PodCIDR)
		if err != nil || prefix != worker.Prefix || !prefix.Addr().Is4() {
			return nil, errors.New("eks: Kubernetes PodCIDR differs from native pod bridge")
		}
		for _, previous := range routes {
			if previous.Prefix.Overlaps(prefix) {
				return nil, errors.New("eks: ambiguous overlapping pod prefixes")
			}
		}
		routes = append(routes, network.PodRoute{Prefix: prefix, ClusterID: state.ID, OwnerToken: state.Token, NodeName: node.Metadata.Name, NodeUID: node.Metadata.UID, ResourceVersion: node.Metadata.ResourceVersion, ContainerID: worker.ContainerID, NetworkID: networkID, WorkerIP: worker.IP})
	}
	slices.SortFunc(routes, func(a, b network.PodRoute) int { return strings.Compare(a.NodeName, b.NodeName) })
	return routes, nil
}
