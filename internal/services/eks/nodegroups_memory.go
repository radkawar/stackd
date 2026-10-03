package eks

import (
	"cmp"
	"context"
	"slices"
)

func compareNodegroupKey(a, b NodegroupKey) int {
	return cmp.Or(compareKey(a.Cluster, b.Cluster), cmp.Compare(a.Name, b.Name))
}
func (r memoryReader) Nodegroup(k NodegroupKey) (Nodegroup, error) {
	if e := r.tx.Check(false); e != nil {
		return Nodegroup{}, e
	}
	v, ok := r.s.nodegroups[k]
	if !ok {
		return Nodegroup{}, ErrNotFound
	}
	return cloneNodegroup(v), nil
}
func (r memoryReader) Nodegroups(k Key) ([]Nodegroup, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Nodegroup{}
	for key, v := range r.s.nodegroups {
		if key.Cluster == k {
			out = append(out, cloneNodegroup(v))
		}
	}
	slices.SortFunc(out, func(a, b Nodegroup) int { return compareNodegroupKey(a.Key, b.Key) })
	return out, nil
}
func (r memoryReader) AllNodegroups() ([]Nodegroup, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := make([]Nodegroup, 0, len(r.s.nodegroups))
	for _, v := range r.s.nodegroups {
		out = append(out, cloneNodegroup(v))
	}
	slices.SortFunc(out, func(a, b Nodegroup) int { return compareNodegroupKey(a.Key, b.Key) })
	return out, nil
}
func (w memoryWriter) PutNodegroup(v Nodegroup) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.nodegroups[v.Key] = cloneNodegroup(v)
	return nil
}
func (w memoryWriter) DeleteNodegroup(k NodegroupKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.nodegroups, k)
	for key := range w.s.nodegroupUpdates {
		if key.Key == k {
			delete(w.s.nodegroupUpdates, key)
		}
	}
	return nil
}
func (w memoryWriter) deleteClusterNodegroups(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	for key := range w.s.nodegroups {
		if key.Cluster == k {
			if e := w.DeleteNodegroup(key); e != nil {
				return e
			}
		}
	}
	return nil
}
func (r memoryReader) NodegroupUpdate(k NodegroupKey, id string) (NodegroupUpdate, error) {
	if e := r.tx.Check(false); e != nil {
		return NodegroupUpdate{}, e
	}
	v, ok := r.s.nodegroupUpdates[nodegroupUpdateKey{k, id}]
	if !ok {
		return NodegroupUpdate{}, ErrNotFound
	}
	return cloneNodegroupUpdate(v), nil
}
func (r memoryReader) NodegroupUpdates(k NodegroupKey) ([]NodegroupUpdate, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []NodegroupUpdate{}
	for key, v := range r.s.nodegroupUpdates {
		if key.Key == k {
			out = append(out, cloneNodegroupUpdate(v))
		}
	}
	slices.SortFunc(out, func(a, b NodegroupUpdate) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (w memoryWriter) PutNodegroupUpdate(v NodegroupUpdate) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.nodegroupUpdates[nodegroupUpdateKey{v.Key, v.ID}] = cloneNodegroupUpdate(v)
	return nil
}

// WithNodegroupRoleUsage fences the resource set while IAM commits role deletion
// in the same writable transaction.
func (s *Service) WithNodegroupRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		all, e := tx.AllNodegroups()
		if e != nil {
			return e
		}
		resources := []string{}
		for _, n := range all {
			if n.Key.Cluster.Partition == partition && n.Key.Cluster.AccountID == account {
				resources = append(resources, n.Key.ARN(n.ID))
			}
		}
		slices.Sort(resources)
		return fn(tx.Context(), resources)
	})
}

var _ NodegroupTransaction = memoryWriter{}
