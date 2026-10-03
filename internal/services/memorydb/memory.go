package memorydb

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
)

type memoryState struct {
	clusters        map[Key]Cluster
	users           map[Key]User
	acls            map[Key]ACL
	parameterGroups map[Key]ParameterGroup
	subnetGroups    map[Key]SubnetGroup
	snapshots       map[Key]Snapshot
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(domain, memoryState{map[Key]Cluster{}, map[Key]User{}, map[Key]ACL{}, map[Key]ParameterGroup{}, map[Key]SubnetGroup{}, map[Key]Snapshot{}}, func(v memoryState) memoryState {
		return memoryState{maps.Clone(v.clusters), maps.Clone(v.users), maps.Clone(v.acls), maps.Clone(v.parameterGroups), maps.Clone(v.subnetGroups), maps.Clone(v.snapshots)}
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(v *memoryState, tx *memory.Transaction) error { return fn(memoryReader{v, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(v *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{v, tx}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(v *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{v, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func compareKey(a, b Key) int {
	return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
}
func cloneCluster(v Cluster) Cluster {
	v.Tags = maps.Clone(v.Tags)
	v.Deployment.Nodes = slices.Clone(v.Deployment.Nodes)
	return v
}
func (r memoryReader) Cluster(k Key) (Cluster, error) {
	if e := r.tx.Check(false); e != nil {
		return Cluster{}, e
	}
	v, ok := r.s.clusters[k]
	if !ok {
		return Cluster{}, ErrNotFound
	}
	return cloneCluster(v), nil
}
func (r memoryReader) Clusters(sc Scope) ([]Cluster, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Cluster{}
	for k, v := range r.s.clusters {
		if k.Scope == sc {
			out = append(out, cloneCluster(v))
		}
	}
	slices.SortFunc(out, func(a, b Cluster) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (w memoryWriter) PutCluster(v Cluster) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.clusters[v.Key] = cloneCluster(v)
	return nil
}
func (w memoryWriter) DeleteCluster(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.clusters, k)
	return nil
}
func (r memoryReader) AllClusters() ([]Cluster, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Cluster{}
	for _, v := range r.s.clusters {
		out = append(out, cloneCluster(v))
	}
	slices.SortFunc(out, func(a, b Cluster) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func cloneUser(v User) User {
	v.Tags = maps.Clone(v.Tags)
	v.PasswordHashes = slices.Clone(v.PasswordHashes)
	return v
}
func (r memoryReader) User(k Key) (User, error) {
	if e := r.tx.Check(false); e != nil {
		return User{}, e
	}
	v, ok := r.s.users[k]
	if !ok {
		return User{}, ErrNotFound
	}
	return cloneUser(v), nil
}
func (r memoryReader) Users(sc Scope) ([]User, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []User{}
	for k, v := range r.s.users {
		if k.Scope == sc {
			out = append(out, cloneUser(v))
		}
	}
	slices.SortFunc(out, func(a, b User) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (w memoryWriter) PutUser(v User) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.users[v.Key] = cloneUser(v)
	return nil
}
func (w memoryWriter) DeleteUser(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.users, k)
	return nil
}
func cloneACL(v ACL) ACL { v.Tags = maps.Clone(v.Tags); v.Users = slices.Clone(v.Users); return v }
func (r memoryReader) ACL(k Key) (ACL, error) {
	if e := r.tx.Check(false); e != nil {
		return ACL{}, e
	}
	v, ok := r.s.acls[k]
	if !ok {
		return ACL{}, ErrNotFound
	}
	return cloneACL(v), nil
}
func (r memoryReader) ACLs(sc Scope) ([]ACL, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []ACL{}
	for k, v := range r.s.acls {
		if k.Scope == sc {
			out = append(out, cloneACL(v))
		}
	}
	slices.SortFunc(out, func(a, b ACL) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (w memoryWriter) PutACL(v ACL) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.acls[v.Key] = cloneACL(v)
	return nil
}
func (w memoryWriter) DeleteACL(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.acls, k)
	return nil
}
func cloneParameterGroup(v ParameterGroup) ParameterGroup {
	v.Tags = maps.Clone(v.Tags)
	v.Parameters = maps.Clone(v.Parameters)
	return v
}
func (r memoryReader) ParameterGroup(k Key) (ParameterGroup, error) {
	if e := r.tx.Check(false); e != nil {
		return ParameterGroup{}, e
	}
	v, ok := r.s.parameterGroups[k]
	if !ok {
		return ParameterGroup{}, ErrNotFound
	}
	return cloneParameterGroup(v), nil
}
func (r memoryReader) ParameterGroups(sc Scope) ([]ParameterGroup, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []ParameterGroup{}
	for k, v := range r.s.parameterGroups {
		if k.Scope == sc {
			out = append(out, cloneParameterGroup(v))
		}
	}
	slices.SortFunc(out, func(a, b ParameterGroup) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (w memoryWriter) PutParameterGroup(v ParameterGroup) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.parameterGroups[v.Key] = cloneParameterGroup(v)
	return nil
}
func (w memoryWriter) DeleteParameterGroup(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.parameterGroups, k)
	return nil
}
func cloneSubnetGroup(v SubnetGroup) SubnetGroup {
	v.Tags = maps.Clone(v.Tags)
	v.Subnets = slices.Clone(v.Subnets)
	return v
}
func (r memoryReader) SubnetGroup(k Key) (SubnetGroup, error) {
	if e := r.tx.Check(false); e != nil {
		return SubnetGroup{}, e
	}
	v, ok := r.s.subnetGroups[k]
	if !ok {
		return SubnetGroup{}, ErrNotFound
	}
	return cloneSubnetGroup(v), nil
}
func (r memoryReader) SubnetGroups(sc Scope) ([]SubnetGroup, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []SubnetGroup{}
	for k, v := range r.s.subnetGroups {
		if k.Scope == sc {
			out = append(out, cloneSubnetGroup(v))
		}
	}
	slices.SortFunc(out, func(a, b SubnetGroup) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (w memoryWriter) PutSubnetGroup(v SubnetGroup) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.subnetGroups[v.Key] = cloneSubnetGroup(v)
	return nil
}
func (w memoryWriter) DeleteSubnetGroup(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.subnetGroups, k)
	return nil
}
func cloneSnapshot(v Snapshot) Snapshot { v.Tags = maps.Clone(v.Tags); ; return v }
func (r memoryReader) Snapshot(k Key) (Snapshot, error) {
	if e := r.tx.Check(false); e != nil {
		return Snapshot{}, e
	}
	v, ok := r.s.snapshots[k]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	return cloneSnapshot(v), nil
}
func (r memoryReader) Snapshots(sc Scope) ([]Snapshot, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Snapshot{}
	for k, v := range r.s.snapshots {
		if k.Scope == sc {
			out = append(out, cloneSnapshot(v))
		}
	}
	slices.SortFunc(out, func(a, b Snapshot) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (w memoryWriter) PutSnapshot(v Snapshot) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.snapshots[v.Key] = cloneSnapshot(v)
	return nil
}
func (w memoryWriter) DeleteSnapshot(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.snapshots, k)
	return nil
}
func (r memoryReader) AllSnapshots() ([]Snapshot, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Snapshot{}
	for _, v := range r.s.snapshots {
		out = append(out, cloneSnapshot(v))
	}
	slices.SortFunc(out, func(a, b Snapshot) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
