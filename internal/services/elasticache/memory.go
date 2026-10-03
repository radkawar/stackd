package elasticache

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
)

type memoryState struct {
	clusters        map[Key]Cluster
	snapshots       map[Key]Snapshot
	users           map[Key]User
	usergroups      map[Key]UserGroup
	parametergroups map[Key]ParameterGroup
	subnetgroups    map[Key]SubnetGroup
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{clusters: map[Key]Cluster{}, snapshots: map[Key]Snapshot{}, users: map[Key]User{}, usergroups: map[Key]UserGroup{}, parametergroups: map[Key]ParameterGroup{}, subnetgroups: map[Key]SubnetGroup{}}, func(v memoryState) memoryState {
		return memoryState{clusters: maps.Clone(v.clusters), snapshots: maps.Clone(v.snapshots), users: maps.Clone(v.users), usergroups: maps.Clone(v.usergroups), parametergroups: maps.Clone(v.parametergroups), subnetgroups: maps.Clone(v.subnetgroups)}
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
	v.Nodes = slices.Clone(v.Nodes)
	v.AuthHashes = slices.Clone(v.AuthHashes)
	v.Parameters = maps.Clone(v.Parameters)
	v.Tags = maps.Clone(v.Tags)
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
func cloneSnapshot(v Snapshot) Snapshot {
	v.Parameters = maps.Clone(v.Parameters)
	v.Tags = maps.Clone(v.Tags)
	return v
}
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
func cloneUser(v User) User {
	v.PasswordHashes = slices.Clone(v.PasswordHashes)
	v.Tags = maps.Clone(v.Tags)
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
func cloneUserGroup(v UserGroup) UserGroup {
	v.UserIDs = slices.Clone(v.UserIDs)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func (r memoryReader) UserGroup(k Key) (UserGroup, error) {
	if e := r.tx.Check(false); e != nil {
		return UserGroup{}, e
	}
	v, ok := r.s.usergroups[k]
	if !ok {
		return UserGroup{}, ErrNotFound
	}
	return cloneUserGroup(v), nil
}
func (r memoryReader) UserGroups(sc Scope) ([]UserGroup, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []UserGroup{}
	for k, v := range r.s.usergroups {
		if k.Scope == sc {
			out = append(out, cloneUserGroup(v))
		}
	}
	slices.SortFunc(out, func(a, b UserGroup) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (w memoryWriter) PutUserGroup(v UserGroup) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.usergroups[v.Key] = cloneUserGroup(v)
	return nil
}
func (w memoryWriter) DeleteUserGroup(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.usergroups, k)
	return nil
}
func cloneParameterGroup(v ParameterGroup) ParameterGroup {
	v.Parameters = maps.Clone(v.Parameters)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func (r memoryReader) ParameterGroup(k Key) (ParameterGroup, error) {
	if e := r.tx.Check(false); e != nil {
		return ParameterGroup{}, e
	}
	v, ok := r.s.parametergroups[k]
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
	for k, v := range r.s.parametergroups {
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
	w.s.parametergroups[v.Key] = cloneParameterGroup(v)
	return nil
}
func (w memoryWriter) DeleteParameterGroup(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.parametergroups, k)
	return nil
}
func cloneSubnetGroup(v SubnetGroup) SubnetGroup {
	v.Subnets = slices.Clone(v.Subnets)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func (r memoryReader) SubnetGroup(k Key) (SubnetGroup, error) {
	if e := r.tx.Check(false); e != nil {
		return SubnetGroup{}, e
	}
	v, ok := r.s.subnetgroups[k]
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
	for k, v := range r.s.subnetgroups {
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
	w.s.subnetgroups[v.Key] = cloneSubnetGroup(v)
	return nil
}
func (w memoryWriter) DeleteSubnetGroup(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.subnetgroups, k)
	return nil
}
