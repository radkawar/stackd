package eks

import (
	"cmp"
	"maps"
	"slices"
)

type fargateKey struct {
	Key
	name string
}

func cloneFargateProfile(p FargateProfile) FargateProfile {
	p.Tags = maps.Clone(p.Tags)
	p.Subnets = slices.Clone(p.Subnets)
	p.Selectors = cloneFargateSelectors(p.Selectors)
	return p
}
func (r memoryReader) FargateProfile(k Key, name string) (FargateProfile, error) {
	if err := r.tx.Check(false); err != nil {
		return FargateProfile{}, err
	}
	p, ok := r.s.fargateProfiles[fargateKey{k, name}]
	if !ok {
		return FargateProfile{}, ErrNotFound
	}
	return cloneFargateProfile(p), nil
}
func (r memoryReader) FargateProfiles(k Key) ([]FargateProfile, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []FargateProfile{}
	for key, p := range r.s.fargateProfiles {
		if key.Key == k {
			out = append(out, cloneFargateProfile(p))
		}
	}
	slices.SortFunc(out, func(a, b FargateProfile) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}
func (w memoryWriter) PutFargateProfile(p FargateProfile) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.fargateProfiles[fargateKey{p.Key, p.Name}] = cloneFargateProfile(p)
	return nil
}
func (w memoryWriter) DeleteFargateProfile(k Key, name string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.fargateProfiles, fargateKey{k, name})
	return nil
}
