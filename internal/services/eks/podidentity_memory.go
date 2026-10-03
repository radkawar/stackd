package eks

import (
	"cmp"
	"maps"
	"slices"
)

func clonePodIdentity(a PodIdentityAssociation) PodIdentityAssociation {
	a.Tags = maps.Clone(a.Tags)
	return a
}
func (r memoryReader) PodIdentityAssociation(k Key, id string) (PodIdentityAssociation, error) {
	if err := r.tx.Check(false); err != nil {
		return PodIdentityAssociation{}, err
	}
	a, ok := r.s.podIdentities[updateKey{k, id}]
	if !ok {
		return a, ErrNotFound
	}
	return clonePodIdentity(a), nil
}
func (r memoryReader) PodIdentityAssociations(k Key) ([]PodIdentityAssociation, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []PodIdentityAssociation{}
	for key, a := range r.s.podIdentities {
		if key.Key == k {
			out = append(out, clonePodIdentity(a))
		}
	}
	slices.SortFunc(out, func(a, b PodIdentityAssociation) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (w memoryWriter) PutPodIdentityAssociation(a PodIdentityAssociation) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.podIdentities[updateKey{a.Key, a.ID}] = clonePodIdentity(a)
	return nil
}
func (w memoryWriter) DeletePodIdentityAssociation(k Key, id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.podIdentities, updateKey{k, id})
	return nil
}
func (w memoryWriter) deleteClusterPodIdentities(k Key) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key := range w.s.podIdentities {
		if key.Key == k {
			delete(w.s.podIdentities, key)
		}
	}
	return nil
}

var _ PodIdentityTransaction = memoryWriter{}
