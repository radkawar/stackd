package valkey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"stackd/compute/docker"
	"stackd/compute/network"
)

const managedPort int32 = 6379
const managedBusPort int32 = 16379

// The descriptor contains only immutable reservation and native ownership. DNS
// and packet policy must always come from a fresh EC2 observation.
type nativeAttachment struct {
	InterfaceID, NetworkID, MAC      string
	Address, Gateway                 netip.Addr
	Pool                             netip.Prefix
	Bridge, PolicyTable, PolicyOwner string
}

type nativeDescriptor struct {
	ID, ClusterARN               string
	Partition, AccountID, Region string
	Shards, Replicas             int32
	ClusterMode, TLSEnabled      bool
	MemoryBytes                  int64
	Networks                     []nativeAttachment
}

type cacheScope struct{ partition, account, region string }

var cacheAccount = regexp.MustCompile(`^[0-9]{12}$`)
var cachePartition = regexp.MustCompile(`^aws(?:-[a-z0-9]+)*$`)
var cacheRegion = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$`)
var cacheResource = regexp.MustCompile(`^(?:cluster|replicationgroup):[a-z][a-z0-9-]*$`)

func managedScope(arn string) (cacheScope, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || !cachePartition.MatchString(parts[1]) || parts[2] != "elasticache" || !cacheRegion.MatchString(parts[3]) || !cacheAccount.MatchString(parts[4]) || !cacheResource.MatchString(parts[5]) {
		return cacheScope{}, errors.New("managed Valkey requires a complete ElastiCache cluster ARN")
	}
	return cacheScope{parts[1], parts[4], parts[3]}, nil
}

func validatePlacement(spec Specification) error {
	if spec.ClusterARN == "" {
		if len(spec.Networks) != 0 || spec.RefreshNetwork != nil {
			return errors.New("native Valkey EC2 placement requires explicit managed cluster ownership")
		}
		return nil
	}
	if _, err := managedScope(spec.ClusterARN); err != nil {
		return err
	}
	if len(spec.Networks) != int(spec.Shards*(spec.Replicas+1)) {
		return errors.New("managed Valkey requires one exact EC2 reservation per node")
	}
	interfaces, addresses, macs := map[string]bool{}, map[netip.Addr]bool{}, map[string]bool{}
	for _, node := range spec.Networks {
		n := node.Network
		mac, err := net.ParseMAC(n.MAC)
		if node.InterfaceID == "" || interfaces[node.InterfaceID] || n.NetworkID == "" || !n.Pool.IsValid() || !n.Pool.Addr().Is4() || n.Pool != n.Pool.Masked() || !n.Address.Is4() || !n.Gateway.Is4() || !n.Pool.Contains(n.Address) || !n.Pool.Contains(n.Gateway) || n.Address == n.Gateway || n.Address.IsLoopback() || n.Address.IsUnspecified() || addresses[n.Address] || err != nil || len(mac) != 6 || mac[0]&1 != 0 || macs[strings.ToLower(n.MAC)] {
			return errors.New("managed Valkey reservation has invalid or duplicated immutable network identity")
		}
		interfaces[node.InterfaceID], addresses[n.Address], macs[strings.ToLower(n.MAC)] = true, true, true
	}
	return nil
}

func nodeRole(index int) string { return "node-" + strconv.Itoa(index+1) }
func policyOwner(spec Specification, index int) string {
	return spec.ClusterARN + "\x00" + spec.ID + "\x00" + strconv.Itoa(index+1)
}
func attachment(spec Specification, index int) nativeAttachment {
	n := spec.Networks[index]
	owner := policyOwner(spec, index)
	return nativeAttachment{InterfaceID: n.InterfaceID, NetworkID: n.Network.NetworkID, MAC: strings.ToLower(n.Network.MAC), Address: n.Network.Address, Gateway: n.Network.Gateway, Pool: n.Network.Pool,
		Bridge: fmt.Sprintf("stackd-ecs-network-%x", sha256.Sum256([]byte(n.Network.NetworkID))), PolicyTable: fmt.Sprintf("stackd_elasticache_%x", sha256.Sum256([]byte(owner))), PolicyOwner: owner}
}
func descriptor(spec Specification) nativeDescriptor {
	scope, _ := managedScope(spec.ClusterARN)
	v := nativeDescriptor{ID: spec.ID, ClusterARN: spec.ClusterARN, Shards: spec.Shards, Replicas: spec.Replicas, ClusterMode: spec.ClusterMode, TLSEnabled: spec.TLSEnabled, MemoryBytes: spec.MemoryBytes, Networks: make([]nativeAttachment, len(spec.Networks))}
	v.Partition, v.AccountID, v.Region = scope.partition, scope.account, scope.region
	for i := range v.Networks {
		v.Networks[i] = attachment(spec, i)
	}
	return v
}
func (v nativeDescriptor) specification() Specification {
	s := Specification{ID: v.ID, ClusterARN: v.ClusterARN, Shards: v.Shards, Replicas: v.Replicas, ClusterMode: v.ClusterMode, TLSEnabled: v.TLSEnabled, MemoryBytes: v.MemoryBytes, Networks: make([]NodeNetwork, len(v.Networks))}
	for i, n := range v.Networks {
		s.Networks[i] = NodeNetwork{InterfaceID: n.InterfaceID, Network: network.Specification{NetworkID: n.NetworkID, Address: n.Address, Gateway: n.Gateway, Pool: n.Pool, MAC: n.MAC}}
	}
	return s
}
func (v nativeDescriptor) validate() error {
	s := v.specification()
	if v.ClusterARN == "" {
		return errors.New("managed Valkey ownership descriptor has no scope")
	}
	if err := validateSpecification(s); err != nil {
		return err
	}
	scope, err := managedScope(v.ClusterARN)
	if err != nil {
		return err
	}
	if v.Partition != scope.partition || v.AccountID != scope.account || v.Region != scope.region {
		return errors.New("managed Valkey durable parsed scope differs from its ARN")
	}
	for i, n := range v.Networks {
		if n != attachment(s, i) {
			return errors.New("managed Valkey native policy or bridge ownership differs from retained reservation")
		}
	}
	return nil
}
func (d *Docker) managedLabels(spec Specification, role string) map[string]string {
	scope, _ := managedScope(spec.ClusterARN) // admission validates before effects
	labels := d.labels(spec.ID, role)
	labels[labelPrefix+"layout"] = "managed-v1"
	labels[labelPrefix+"arn"], labels[labelPrefix+"partition"], labels[labelPrefix+"account"], labels[labelPrefix+"region"] = spec.ClusterARN, scope.partition, scope.account, scope.region
	labels[labelPrefix+"image"] = d.image
	encoded, _ := json.Marshal(descriptor(spec))
	labels[labelPrefix+"descriptor"] = string(encoded)
	return labels
}
func (d *Docker) checkManagedOwner(labels map[string]string, spec Specification, role string) error {
	for key, value := range d.managedLabels(spec, role) {
		if labels[key] != value {
			return errors.New("refusing foreign, cross-scope or replaced managed Valkey resource")
		}
	}
	return nil
}
func (d *Docker) managedVolume(ctx context.Context, spec Specification, role string, create bool) (volumeState, error) {
	name := d.name(spec.ID, role)
	var v volumeState
	err := d.client.JSON(ctx, "GET", "/volumes/"+url.PathEscape(name), nil, &v)
	if dockerStatus(err, 404) && create {
		err = d.client.JSON(ctx, "POST", "/volumes/create", docker.VolumeConfig{Name: name, Driver: "local", Labels: d.managedLabels(spec, role)}, &v)
	}
	if err != nil {
		return v, err
	}
	if err = d.checkManagedOwner(v.Labels, spec, role); err != nil {
		return v, err
	}
	if v.Name != name || v.Driver != "local" || len(v.Options) != 0 {
		return v, errors.New("conflicting managed Valkey native storage")
	}
	return v, nil
}

// Ownership outlives data and processes until native policy/bridge retirement
// completes, so ID-only Delete works without any EC2 observation or live node.
func (d *Docker) managedDescriptor(ctx context.Context, id string) (nativeDescriptor, bool, error) {
	var v volumeState
	role := "ownership"
	err := d.client.JSON(ctx, "GET", "/volumes/"+url.PathEscape(d.name(id, "ownership")), nil, &v)
	if dockerStatus(err, 404) {
		role = "data"
		err = d.client.JSON(ctx, "GET", "/volumes/"+url.PathEscape(d.name(id, role)), nil, &v)
		if dockerStatus(err, 404) {
			return nativeDescriptor{}, false, nil
		}
		if err == nil && v.Labels[labelPrefix+"layout"] == "native-v1" {
			return nativeDescriptor{}, false, nil
		}
	}
	if err != nil {
		return nativeDescriptor{}, false, err
	}
	var owner nativeDescriptor
	if err = json.Unmarshal([]byte(v.Labels[labelPrefix+"descriptor"]), &owner); err != nil {
		return owner, false, err
	}
	if owner.ID != id {
		return owner, false, errors.New("managed Valkey durable incarnation differs")
	}
	if err = owner.validate(); err != nil {
		return owner, false, err
	}
	if _, err = d.managedVolume(ctx, owner.specification(), role, false); err != nil {
		return owner, false, err
	}
	return owner, true, nil
}
func managedManifest(spec Specification) manifest {
	v := descriptor(spec)
	m := manifest{ID: spec.ID, ClusterARN: spec.ClusterARN, Secret: rand.Text(), Shards: spec.Shards, Replicas: spec.Replicas, ClusterMode: spec.ClusterMode, TLSEnabled: spec.TLSEnabled, MemoryBytes: spec.MemoryBytes, Networks: v.Networks, Nodes: make([]nativeNode, len(spec.Networks))}
	m.Partition, m.AccountID, m.Region = v.Partition, v.AccountID, v.Region
	for i, n := range spec.Networks {
		m.Nodes[i] = nativeNode{Address: n.Network.Address.String(), Port: managedPort}
		if spec.ClusterMode {
			m.Nodes[i].BusPort = managedBusPort
		}
	}
	return m
}
func (m manifest) address(index int) string {
	if m.ClusterARN != "" {
		return m.Nodes[index].Address
	}
	return "127.0.0.1"
}
func (m manifest) validateManagedPorts() error {
	seen := map[string]bool{}
	for _, node := range m.Nodes {
		address, err := netip.ParseAddr(node.Address)
		if err != nil || !address.Is4() || address.IsLoopback() || seen[node.Address] || node.Port != managedPort || (m.ClusterMode && node.BusPort != managedBusPort) || (!m.ClusterMode && node.BusPort != 0) {
			return errors.New("managed Valkey must use distinct actual IPv4 addresses and fixed native ports")
		}
		seen[node.Address] = true
	}
	return nil
}
func validateManagedManifest(m manifest, spec Specification) error {
	scope, err := managedScope(spec.ClusterARN)
	if err != nil {
		return err
	}
	if m.Partition != scope.partition || m.AccountID != scope.account || m.Region != scope.region || len(m.Networks) != len(spec.Networks) {
		return errors.New("managed Valkey retained parsed scope or network topology differs")
	}
	for i, n := range m.Networks {
		if n != attachment(spec, i) {
			return errors.New("managed Valkey retained reservation ownership differs")
		}
	}
	for i, n := range m.Nodes {
		if n.Address != spec.Networks[i].Network.Address.String() {
			return errors.New("managed Valkey manifest address differs from EC2 reservation")
		}
	}
	return nil
}
