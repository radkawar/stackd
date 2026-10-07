package apigatewayv2

import (
	"cmp"
	"maps"
	"slices"
)

func cloneDomain(v DomainRecord) DomainRecord {
	v.Tags = maps.Clone(v.Tags)
	v.TruststorePEM = slices.Clone(v.TruststorePEM)
	return v
}
func (r memoryReader) Domain(k DomainKey) (DomainRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return DomainRecord{}, e
	}
	v, ok := r.s.domains[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneDomain(v), nil
}
func (r memoryReader) DomainByHost(host string) (DomainRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return DomainRecord{}, e
	}
	for k, v := range r.s.domains {
		if k.Name == host {
			return cloneDomain(v), nil
		}
	}
	return DomainRecord{}, ErrNotFound
}
func (r memoryReader) Domains(sc Scope) ([]DomainRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []DomainRecord{}
	for k, v := range r.s.domains {
		if k.Scope == sc {
			out = append(out, cloneDomain(v))
		}
	}
	slices.SortFunc(out, func(a, b DomainRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) Mapping(k MappingKey) (MappingRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return MappingRecord{}, e
	}
	v, ok := r.s.mappings[k]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) Mappings(k DomainKey) ([]MappingRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []MappingRecord{}
	for key, v := range r.s.mappings {
		if key.DomainKey == k {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b MappingRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (w memoryWriter) PutDomain(v DomainRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	for k := range w.s.domains {
		if k.Name == v.Key.Name && k != v.Key {
			return failure("ConflictException", "Domain name is already in use", 409)
		}
	}
	w.s.domains[v.Key] = cloneDomain(v)
	return nil
}
func (w memoryWriter) DeleteDomain(k DomainKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.domains, k)
	for key := range w.s.mappings {
		if key.DomainKey == k {
			delete(w.s.mappings, key)
		}
	}
	return nil
}
func (w memoryWriter) PutMapping(v MappingRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.mappings[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteMapping(k MappingKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.mappings, k)
	return nil
}
