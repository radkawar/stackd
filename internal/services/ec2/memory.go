package ec2

import (
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
	"strings"
)

type memoryState struct {
	vpcs                   map[ResourceKey]VPCRecord
	publicAddresses        map[ResourceKey]PublicAddressRecord
	subnets                map[ResourceKey]SubnetRecord
	groups                 map[ResourceKey]SecurityGroupRecord
	rules                  map[ResourceKey]SecurityGroupRuleRecord
	routes                 map[ResourceKey]RouteTableRecord
	gateways               map[ResourceKey]InternetGatewayRecord
	natGateways            map[ResourceKey]NatGatewayRecord
	vpcEndpoints           map[ResourceKey]VPCEndpointRecord
	networkOwnerCreations  map[NetworkCreationKey]NetworkOwnerCreationRecord
	networkInterfaces      map[ResourceKey]NetworkInterfaceRecord
	interfaceCreations     map[NetworkInterfaceCreationKey]NetworkInterfaceCreationRecord
	acls                   map[ResourceKey]NetworkACLRecord
	dhcp                   map[ResourceKey]DHCPOptionsRecord
	dhcpDefaults           map[Scope]DHCPDefaultsRecord
	creations              map[NetworkCreationKey]NetworkCreationRecord
	keyPairs               map[ResourceKey]KeyPairRecord
	images                 map[ResourceKey]ImageRecord
	instances              map[ResourceKey]InstanceRecord
	profileAssociations    map[ResourceKey]InstanceProfileAssociationRecord
	reservations           map[ResourceKey]ReservationRecord
	creditDefaults         map[instanceCreditDefaultKey]InstanceCreditDefaultRecord
	creditLaunches         map[Scope]InstanceCreditLaunchRecord
	creditModifications    map[InstanceCreditModificationKey]InstanceCreditModificationRecord
	identitySigningKeys    map[string]IdentitySigningKeyRecord
	launchTemplates        map[ResourceKey]LaunchTemplateRecord
	launchTemplateVersions map[LaunchTemplateVersionKey]LaunchTemplateVersionRecord
	launchTemplateTokens   map[LaunchTemplateTokenKey]LaunchTemplateTokenRecord
	counters               map[ResourceKey]uint64
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{vpcs: map[ResourceKey]VPCRecord{}, subnets: map[ResourceKey]SubnetRecord{}, groups: map[ResourceKey]SecurityGroupRecord{}, rules: map[ResourceKey]SecurityGroupRuleRecord{}, routes: map[ResourceKey]RouteTableRecord{}, gateways: map[ResourceKey]InternetGatewayRecord{}, networkInterfaces: map[ResourceKey]NetworkInterfaceRecord{}, interfaceCreations: map[NetworkInterfaceCreationKey]NetworkInterfaceCreationRecord{}, acls: map[ResourceKey]NetworkACLRecord{}, dhcp: map[ResourceKey]DHCPOptionsRecord{}, dhcpDefaults: map[Scope]DHCPDefaultsRecord{}, creations: map[NetworkCreationKey]NetworkCreationRecord{}, keyPairs: map[ResourceKey]KeyPairRecord{}, counters: map[ResourceKey]uint64{}}
	initial.images = map[ResourceKey]ImageRecord{}
	initial.publicAddresses = map[ResourceKey]PublicAddressRecord{}
	initial.instances = map[ResourceKey]InstanceRecord{}
	initial.profileAssociations = map[ResourceKey]InstanceProfileAssociationRecord{}
	initial.reservations = map[ResourceKey]ReservationRecord{}
	initial.creditDefaults = map[instanceCreditDefaultKey]InstanceCreditDefaultRecord{}
	initial.creditLaunches = map[Scope]InstanceCreditLaunchRecord{}
	initial.creditModifications = map[InstanceCreditModificationKey]InstanceCreditModificationRecord{}
	initial.identitySigningKeys = map[string]IdentitySigningKeyRecord{}
	initial.launchTemplates = map[ResourceKey]LaunchTemplateRecord{}
	initial.launchTemplateVersions = map[LaunchTemplateVersionKey]LaunchTemplateVersionRecord{}
	initial.launchTemplateTokens = map[LaunchTemplateTokenKey]LaunchTemplateTokenRecord{}
	initial.natGateways = map[ResourceKey]NatGatewayRecord{}
	initial.vpcEndpoints = map[ResourceKey]VPCEndpointRecord{}
	initial.networkOwnerCreations = map[NetworkCreationKey]NetworkOwnerCreationRecord{}
	return &MemoryRepository{memory.New(domain, initial, func(v memoryState) memoryState {
		v.launchTemplates = maps.Clone(v.launchTemplates)
		v.launchTemplateVersions = maps.Clone(v.launchTemplateVersions)
		v.launchTemplateTokens = maps.Clone(v.launchTemplateTokens)
		natGateways := maps.Clone(v.natGateways)
		vpcEndpoints := maps.Clone(v.vpcEndpoints)
		networkOwnerCreations := maps.Clone(v.networkOwnerCreations)
		return memoryState{natGateways: natGateways, vpcEndpoints: vpcEndpoints, networkOwnerCreations: networkOwnerCreations, publicAddresses: maps.Clone(v.publicAddresses), vpcs: maps.Clone(v.vpcs), subnets: maps.Clone(v.subnets), groups: maps.Clone(v.groups), rules: maps.Clone(v.rules), routes: maps.Clone(v.routes), gateways: maps.Clone(v.gateways), networkInterfaces: maps.Clone(v.networkInterfaces), interfaceCreations: maps.Clone(v.interfaceCreations), acls: maps.Clone(v.acls), dhcp: maps.Clone(v.dhcp), dhcpDefaults: maps.Clone(v.dhcpDefaults), creations: maps.Clone(v.creations), keyPairs: maps.Clone(v.keyPairs), images: maps.Clone(v.images), instances: maps.Clone(v.instances), profileAssociations: maps.Clone(v.profileAssociations), reservations: maps.Clone(v.reservations), creditDefaults: maps.Clone(v.creditDefaults), creditLaunches: maps.Clone(v.creditLaunches), creditModifications: maps.Clone(v.creditModifications), identitySigningKeys: maps.Clone(v.identitySigningKeys), counters: maps.Clone(v.counters), launchTemplates: v.launchTemplates, launchTemplateVersions: v.launchTemplateVersions, launchTemplateTokens: v.launchTemplateTokens}
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func getRecord[K comparable, T any](tx *memory.Transaction, table map[K]T, k K, clone func(T) T) (T, error) {
	var zero T
	if err := tx.Check(false); err != nil {
		return zero, err
	}
	v, ok := table[k]
	if !ok {
		return zero, ErrNotFound
	}
	return clone(v), nil
}
func listRecords[T any](tx *memory.Transaction, table map[ResourceKey]T, scope Scope, clone func(T) T) ([]T, error) {
	if err := tx.Check(false); err != nil {
		return nil, err
	}
	keys := []ResourceKey{}
	for k := range table {
		if k.Scope == scope {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b ResourceKey) int { return strings.Compare(a.ID, b.ID) })
	out := make([]T, 0, len(keys))
	for _, k := range keys {
		out = append(out, clone(table[k]))
	}
	return out, nil
}
func putRecord[K comparable, T any](tx *memory.Transaction, table map[K]T, k K, v T, clone func(T) T) error {
	if err := tx.Check(true); err != nil {
		return err
	}
	table[k] = clone(v)
	return nil
}
func deleteRecord[T any](tx *memory.Transaction, table map[ResourceKey]T, k ResourceKey) error {
	if err := tx.Check(true); err != nil {
		return err
	}
	if _, ok := table[k]; !ok {
		return ErrNotFound
	}
	delete(table, k)
	return nil
}
func (r memoryReader) VPC(k ResourceKey) (VPCRecord, error) {
	return getRecord(r.tx, r.s.vpcs, k, cloneVPC)
}
func (r memoryReader) VPCs(s Scope) ([]VPCRecord, error) {
	return listRecords(r.tx, r.s.vpcs, s, cloneVPC)
}
func (w memoryWriter) PutVPC(v VPCRecord) error {
	return putClaimed(w.tx, w.s.vpcs, v.Key, v, cloneVPC)
}
func (w memoryWriter) DeleteVPC(k ResourceKey) error { return deleteRecord(w.tx, w.s.vpcs, k) }
func (r memoryReader) Subnet(k ResourceKey) (SubnetRecord, error) {
	return getRecord(r.tx, r.s.subnets, k, cloneSubnet)
}
func (r memoryReader) Subnets(s Scope) ([]SubnetRecord, error) {
	return listRecords(r.tx, r.s.subnets, s, cloneSubnet)
}
func (w memoryWriter) PutSubnet(v SubnetRecord) error {
	return putClaimed(w.tx, w.s.subnets, v.Key, v, cloneSubnet)
}
func (w memoryWriter) DeleteSubnet(k ResourceKey) error { return deleteRecord(w.tx, w.s.subnets, k) }
func (r memoryReader) SecurityGroup(k ResourceKey) (SecurityGroupRecord, error) {
	return getRecord(r.tx, r.s.groups, k, cloneGroup)
}
func (r memoryReader) SecurityGroups(s Scope) ([]SecurityGroupRecord, error) {
	return listRecords(r.tx, r.s.groups, s, cloneGroup)
}
func (w memoryWriter) PutSecurityGroup(v SecurityGroupRecord) error {
	return putClaimed(w.tx, w.s.groups, v.Key, v, cloneGroup)
}
func (w memoryWriter) DeleteSecurityGroup(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.groups, k)
}
func (r memoryReader) SecurityGroupRule(k ResourceKey) (SecurityGroupRuleRecord, error) {
	return getRecord(r.tx, r.s.rules, k, cloneRule)
}
func (r memoryReader) SecurityGroupRules(s Scope) ([]SecurityGroupRuleRecord, error) {
	return listRecords(r.tx, r.s.rules, s, cloneRule)
}
func (w memoryWriter) PutSecurityGroupRule(v SecurityGroupRuleRecord) error {
	return putClaimed(w.tx, w.s.rules, v.Key, v, cloneRule)
}
func (w memoryWriter) DeleteSecurityGroupRule(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.rules, k)
}
func (r memoryReader) RouteTable(k ResourceKey) (RouteTableRecord, error) {
	return getRecord(r.tx, r.s.routes, k, cloneRouteTable)
}
func (r memoryReader) RouteTables(s Scope) ([]RouteTableRecord, error) {
	return listRecords(r.tx, r.s.routes, s, cloneRouteTable)
}
func (w memoryWriter) PutRouteTable(v RouteTableRecord) error {
	return putClaimed(w.tx, w.s.routes, v.Key, v, cloneRouteTable)
}
func (w memoryWriter) DeleteRouteTable(k ResourceKey) error { return deleteRecord(w.tx, w.s.routes, k) }
func (r memoryReader) InternetGateway(k ResourceKey) (InternetGatewayRecord, error) {
	return getRecord(r.tx, r.s.gateways, k, cloneInternetGateway)
}
func (r memoryReader) InternetGateways(s Scope) ([]InternetGatewayRecord, error) {
	return listRecords(r.tx, r.s.gateways, s, cloneInternetGateway)
}
func (w memoryWriter) PutInternetGateway(v InternetGatewayRecord) error {
	return putClaimed(w.tx, w.s.gateways, v.Key, v, cloneInternetGateway)
}
func (w memoryWriter) DeleteInternetGateway(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.gateways, k)
}
func (r memoryReader) NetworkInterface(k ResourceKey) (NetworkInterfaceRecord, error) {
	return getRecord(r.tx, r.s.networkInterfaces, k, cloneNetworkInterface)
}
func (r memoryReader) NetworkInterfaces(s Scope) ([]NetworkInterfaceRecord, error) {
	return listRecords(r.tx, r.s.networkInterfaces, s, cloneNetworkInterface)
}
func (r memoryReader) RegionalNetworkInterfaces(scope Scope) ([]NetworkInterfaceRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []NetworkInterfaceRecord
	for k, v := range r.s.networkInterfaces {
		if k.Scope.Partition == scope.Partition && k.Scope.Region == scope.Region {
			out = append(out, cloneNetworkInterface(v))
		}
	}
	slices.SortFunc(out, func(a, b NetworkInterfaceRecord) int { return strings.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}

func (r memoryReader) RegionalSecurityGroups(scope Scope) ([]SecurityGroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []SecurityGroupRecord
	for k, v := range r.s.groups {
		if k.Scope.Partition == scope.Partition && k.Scope.Region == scope.Region {
			out = append(out, cloneGroup(v))
		}
	}
	slices.SortFunc(out, func(a, b SecurityGroupRecord) int { return strings.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (w memoryWriter) PutNetworkInterface(v NetworkInterfaceRecord) error {
	return putClaimed(w.tx, w.s.networkInterfaces, v.Key, v, cloneNetworkInterface)
}
func (w memoryWriter) DeleteNetworkInterface(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.networkInterfaces, k)
}
func (r memoryReader) NetworkInterfaceCreation(k NetworkInterfaceCreationKey) (NetworkInterfaceCreationRecord, error) {
	return getRecord(r.tx, r.s.interfaceCreations, k, cloneNetworkInterfaceCreation)
}
func (w memoryWriter) PutNetworkInterfaceCreation(v NetworkInterfaceCreationRecord) error {
	return putRecord(w.tx, w.s.interfaceCreations, v.Key, v, cloneNetworkInterfaceCreation)
}
func (r memoryReader) NetworkACL(k ResourceKey) (NetworkACLRecord, error) {
	return getRecord(r.tx, r.s.acls, k, cloneACL)
}
func (r memoryReader) NetworkACLs(s Scope) ([]NetworkACLRecord, error) {
	return listRecords(r.tx, r.s.acls, s, cloneACL)
}
func (w memoryWriter) PutNetworkACL(v NetworkACLRecord) error {
	return putClaimed(w.tx, w.s.acls, v.Key, v, cloneACL)
}
func (w memoryWriter) DeleteNetworkACL(k ResourceKey) error { return deleteRecord(w.tx, w.s.acls, k) }

func (r memoryReader) DHCPOptions(k ResourceKey) (DHCPOptionsRecord, error) {
	return getRecord(r.tx, r.s.dhcp, k, cloneDHCPOptions)
}
func (r memoryReader) DHCPOptionsSets(s Scope) ([]DHCPOptionsRecord, error) {
	return listRecords(r.tx, r.s.dhcp, s, cloneDHCPOptions)
}
func (w memoryWriter) PutDHCPOptions(v DHCPOptionsRecord) error {
	return putClaimed(w.tx, w.s.dhcp, v.Key, v, cloneDHCPOptions)
}
func (w memoryWriter) DeleteDHCPOptions(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.dhcp, k)
}
func (r memoryReader) DHCPDefaults(scope Scope) (DHCPDefaultsRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DHCPDefaultsRecord{}, err
	}
	v, ok := r.s.dhcpDefaults[scope]
	if !ok {
		return DHCPDefaultsRecord{}, ErrNotFound
	}
	return v, nil
}
func (w memoryWriter) PutDHCPDefaults(v DHCPDefaultsRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.dhcpDefaults[v.Scope] = v
	return nil
}
func (r memoryReader) NetworkCreation(k NetworkCreationKey) (NetworkCreationRecord, error) {
	return getRecord(r.tx, r.s.creations, k, cloneNetworkCreation)
}
func (w memoryWriter) PutNetworkCreation(record NetworkCreationRecord) error {
	return putRecord(w.tx, w.s.creations, record.Key, record, cloneNetworkCreation)
}
func (r memoryReader) KeyPair(k ResourceKey) (KeyPairRecord, error) {
	return getRecord(r.tx, r.s.keyPairs, k, cloneKeyPair)
}
func (r memoryReader) KeyPairs(s Scope) ([]KeyPairRecord, error) {
	return listRecords(r.tx, r.s.keyPairs, s, cloneKeyPair)
}
func (w memoryWriter) PutKeyPair(v KeyPairRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k, existing := range w.s.keyPairs {
		if k.Scope == v.Key.Scope && k != v.Key && str(existing.Data.KeyName) == str(v.Data.KeyName) {
			return duplicateKeyPair()
		}
	}
	return putClaimed(w.tx, w.s.keyPairs, v.Key, v, cloneKeyPair)
}
func (w memoryWriter) DeleteKeyPair(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.keyPairs, k)
}
func (w memoryWriter) NextID(scope Scope, prefix string) (string, error) {
	if err := w.tx.Check(true); err != nil {
		return "", err
	}
	k := ResourceKey{scope, prefix}
	n := w.s.counters[k] + 1
	id, err := FormatResourceID(scope, prefix, n)
	if err != nil {
		return "", err
	}
	w.s.counters[k] = n
	return id, nil
}
