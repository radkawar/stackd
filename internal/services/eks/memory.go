package eks

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type accessKey struct {
	Key
	principal string
}
type policyKey struct {
	accessKey
	policy string
}
type mutationKey struct {
	accessKey
	token string
}
type updateKey struct {
	Key
	id string
}
type memoryState struct {
	clusters                map[Key]Cluster
	entries                 map[accessKey]AccessEntry
	policies                map[policyKey]AccessPolicy
	updates                 map[updateKey]Update
	mutations               map[mutationKey]AccessMutation
	nodegroups              map[NodegroupKey]Nodegroup
	nodegroupUpdates        map[nodegroupUpdateKey]NodegroupUpdate
	addons                  map[addonKey]Addon
	fargateProfiles         map[fargateKey]FargateProfile
	podIdentities           map[updateKey]PodIdentityAssociation
	cloudFormationCreations map[CloudFormationCreationKey]CloudFormationCreation
}

// MemoryRepository retains detached typed records in the shared transaction domain.
// Deleting a cluster removes its exact-scoped access, mutation ledger and update records.
type MemoryRepository struct {
	store *memory.Store[memoryState]
}

// NewMemoryRepository joins the supplied transaction domain, or creates one if nil.
func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{store: memory.New(domain, memoryState{
		clusters: map[Key]Cluster{}, entries: map[accessKey]AccessEntry{},
		policies: map[policyKey]AccessPolicy{}, updates: map[updateKey]Update{},
		mutations:               map[mutationKey]AccessMutation{},
		nodegroups:              map[NodegroupKey]Nodegroup{},
		nodegroupUpdates:        map[nodegroupUpdateKey]NodegroupUpdate{},
		addons:                  map[addonKey]Addon{},
		fargateProfiles:         map[fargateKey]FargateProfile{},
		podIdentities:           map[updateKey]PodIdentityAssociation{},
		cloudFormationCreations: map[CloudFormationCreationKey]CloudFormationCreation{},
	}, func(v memoryState) memoryState {
		// Nested records are immutable; readers and writers detach mutable fields.
		return memoryState{
			clusters: maps.Clone(v.clusters), entries: maps.Clone(v.entries),
			policies: maps.Clone(v.policies), updates: maps.Clone(v.updates),
			mutations: maps.Clone(v.mutations), nodegroups: maps.Clone(v.nodegroups),
			nodegroupUpdates: maps.Clone(v.nodegroupUpdates), addons: maps.Clone(v.addons),
			fargateProfiles: maps.Clone(v.fargateProfiles), podIdentities: maps.Clone(v.podIdentities),
			cloudFormationCreations: maps.Clone(v.cloudFormationCreations),
		}
	})}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(v *memoryState, tx *memory.Transaction) error {
		return fn(memoryReader{v, tx})
	})
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(v *memoryState, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{v, tx}})
	})
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(v *memoryState, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{v, tx}})
	})
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

func compareKey(a, b Key) int {
	return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.Name, b.Name))
}
func cloneCluster(v Cluster) Cluster {
	v.Subnets = slices.Clone(v.Subnets)
	v.SecurityGroups = slices.Clone(v.SecurityGroups)
	v.Tags = maps.Clone(v.Tags)
	v.EnabledLogTypes = slices.Clone(v.EnabledLogTypes)
	return v
}
func cloneAccessEntry(v AccessEntry) AccessEntry {
	v.Groups = slices.Clone(v.Groups)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func cloneAccessPolicy(v AccessPolicy) AccessPolicy {
	v.Namespaces = slices.Clone(v.Namespaces)
	return v
}
func cloneUpdate(v Update) Update {
	v.EnabledLogTypes = slices.Clone(v.EnabledLogTypes)
	v.Params = slices.Clone(v.Params)
	if v.DeletionProtection != nil {
		value := *v.DeletionProtection
		v.DeletionProtection = &value
	}
	return v
}

func (r memoryReader) Cluster(k Key) (Cluster, error) {
	if err := r.tx.Check(false); err != nil {
		return Cluster{}, err
	}
	v, ok := r.s.clusters[k]
	if !ok {
		return Cluster{}, ErrNotFound
	}
	return cloneCluster(v), nil
}
func (r memoryReader) Clusters(scope Scope) ([]Cluster, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Cluster{}
	for k, v := range r.s.clusters {
		if k.Scope == scope {
			out = append(out, cloneCluster(v))
		}
	}
	slices.SortFunc(out, func(a, b Cluster) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (r memoryReader) AllClusters() ([]Cluster, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]Cluster, 0, len(r.s.clusters))
	for _, v := range r.s.clusters {
		out = append(out, cloneCluster(v))
	}
	slices.SortFunc(out, func(a, b Cluster) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (w memoryWriter) PutCluster(v Cluster) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.clusters[v.Key] = cloneCluster(v)
	return nil
}
func (w memoryWriter) DeleteCluster(k Key) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.clusters, k)
	for key := range w.s.entries {
		if key.Key == k {
			delete(w.s.entries, key)
		}
	}
	for key := range w.s.policies {
		if key.Key == k {
			delete(w.s.policies, key)
		}
	}
	for key := range w.s.updates {
		if key.Key == k {
			delete(w.s.updates, key)
		}
	}
	for key := range w.s.mutations {
		if key.Key == k {
			delete(w.s.mutations, key)
		}
	}
	if err := w.deleteClusterPodIdentities(k); err != nil {
		return err
	}
	if err := w.deleteClusterNodegroups(k); err != nil {
		return err
	}
	for key := range w.s.addons {
		if key.Key == k {
			delete(w.s.addons, key)
		}
	}
	for key := range w.s.fargateProfiles {
		if key.Key == k {
			delete(w.s.fargateProfiles, key)
		}
	}
	return nil
}

func (r memoryReader) AccessEntry(k Key, principal string) (AccessEntry, error) {
	if err := r.tx.Check(false); err != nil {
		return AccessEntry{}, err
	}
	v, ok := r.s.entries[accessKey{k, principal}]
	if !ok {
		return AccessEntry{}, ErrNotFound
	}
	return cloneAccessEntry(v), nil
}
func (r memoryReader) AccessEntries(k Key) ([]AccessEntry, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []AccessEntry{}
	for key, v := range r.s.entries {
		if key.Key == k {
			out = append(out, cloneAccessEntry(v))
		}
	}
	slices.SortFunc(out, func(a, b AccessEntry) int { return cmp.Compare(a.PrincipalARN, b.PrincipalARN) })
	return out, nil
}
func (w memoryWriter) PutAccessEntry(v AccessEntry) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.entries[accessKey{v.Key, v.PrincipalARN}] = cloneAccessEntry(v)
	return nil
}
func (w memoryWriter) DeleteAccessEntry(k Key, principal string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	key := accessKey{k, principal}
	delete(w.s.entries, key)
	for policy := range w.s.policies {
		if policy.accessKey == key {
			delete(w.s.policies, policy)
		}
	}
	for mutation := range w.s.mutations {
		if mutation.accessKey == key {
			delete(w.s.mutations, mutation)
		}
	}
	return nil
}
func (r memoryReader) AccessPolicies(k Key, principal string) ([]AccessPolicy, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []AccessPolicy{}
	key := accessKey{k, principal}
	for policy, v := range r.s.policies {
		if policy.accessKey == key {
			out = append(out, cloneAccessPolicy(v))
		}
	}
	slices.SortFunc(out, func(a, b AccessPolicy) int { return cmp.Compare(a.PolicyARN, b.PolicyARN) })
	return out, nil
}
func (w memoryWriter) PutAccessPolicy(v AccessPolicy) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.policies[policyKey{accessKey{v.Key, v.PrincipalARN}, v.PolicyARN}] = cloneAccessPolicy(v)
	return nil
}
func (w memoryWriter) DeleteAccessPolicy(k Key, principal, policy string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.policies, policyKey{accessKey{k, principal}, policy})
	return nil
}

func (r memoryReader) AccessMutation(k Key, principal, token string) (AccessMutation, error) {
	if err := r.tx.Check(false); err != nil {
		return AccessMutation{}, err
	}
	v, ok := r.s.mutations[mutationKey{accessKey{k, principal}, token}]
	if !ok {
		return AccessMutation{}, ErrNotFound
	}
	return v, nil
}

func (w memoryWriter) PutAccessMutation(v AccessMutation) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.mutations[mutationKey{accessKey{v.Key, v.PrincipalARN}, v.Token}] = v
	return nil
}
func (r memoryReader) ClusterUpdate(k Key, id string) (Update, error) {
	if err := r.tx.Check(false); err != nil {
		return Update{}, err
	}
	v, ok := r.s.updates[updateKey{k, id}]
	if !ok {
		return Update{}, ErrNotFound
	}
	return cloneUpdate(v), nil
}
func (r memoryReader) ClusterUpdates(k Key) ([]Update, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Update{}
	for key, v := range r.s.updates {
		if key.Key == k {
			out = append(out, cloneUpdate(v))
		}
	}
	slices.SortFunc(out, func(a, b Update) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (w memoryWriter) PutClusterUpdate(v Update) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.updates[updateKey{v.Key, v.ID}] = cloneUpdate(v)
	return nil
}

var (
	_ Repository  = (*MemoryRepository)(nil)
	_ Transaction = memoryWriter{}
)
