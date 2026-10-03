package servicecatalogappregistry

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"stackd/storage/memory"
)

type attributeLink struct{ applicationARN, attributeGroupARN string }
type associationKey struct{ applicationARN, resourceARN string }

type memoryState struct {
	applications    map[string]Application
	attributeGroups map[string]AttributeGroup
	attributeLinks  map[attributeLink]struct{}
	associations    map[associationKey]Association
	configurations  map[Scope]Configuration
}

// Values in the staging maps are immutable. Only input/output tag maps need deep copies.
func cloneMemory(s memoryState) memoryState {
	return memoryState{
		applications:    maps.Clone(s.applications),
		attributeGroups: maps.Clone(s.attributeGroups),
		attributeLinks:  maps.Clone(s.attributeLinks),
		associations:    maps.Clone(s.associations),
		configurations:  maps.Clone(s.configurations),
	}
}

func cloneApplication(a Application) Application {
	a.Tags = maps.Clone(a.Tags)
	return a
}
func cloneAttributeGroup(g AttributeGroup) AttributeGroup {
	g.Tags = maps.Clone(g.Tags)
	return g
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{store: memory.New(domain, memoryState{
		applications:    map[string]Application{},
		attributeGroups: map[string]AttributeGroup{},
		attributeLinks:  map[attributeLink]struct{}{},
		associations:    map[associationKey]Association{},
		configurations:  map[Scope]Configuration{},
	}, cloneMemory)}
}

func (r *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return r.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (r *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}
func (r *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return r.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

func (r memoryReader) AccountApplications(partition, accountID string) ([]Application, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Application{}
	for _, a := range r.state.applications {
		if a.Partition == partition && a.AccountID == accountID {
			out = append(out, cloneApplication(a))
		}
	}
	slices.SortFunc(out, func(a, b Application) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil
}

type memoryReader struct {
	state *memoryState
	tx    *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func (r memoryReader) findApplication(scope Scope, identifier string) (Application, bool) {
	if a, ok := r.state.applications[identifier]; ok && a.Scope == scope {
		return a, true
	}
	var named Application
	found := false
	for _, a := range r.state.applications {
		if a.Scope != scope {
			continue
		}
		if a.ID == identifier {
			return a, true
		}
		if a.Name == identifier {
			named, found = a, true
		}
	}
	return named, found
}
func (r memoryReader) Application(scope Scope, identifier string) (Application, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return Application{}, false, err
	}
	a, ok := r.findApplication(scope, identifier)
	return cloneApplication(a), ok, nil
}
func (r memoryReader) Applications(scope Scope) ([]Application, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Application{}
	for _, a := range r.state.applications {
		if a.Scope == scope {
			out = append(out, cloneApplication(a))
		}
	}
	slices.SortFunc(out, func(a, b Application) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) PutApplication(a Application) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if current, ok := w.state.applications[a.ARN]; ok && (current.Scope != a.Scope || current.ID != a.ID) {
		return errors.New("application ARN belongs to another scope or ID")
	}
	for arn, current := range w.state.applications {
		if arn != a.ARN && current.Scope == a.Scope && (current.Name == a.Name || current.ID == a.ID) {
			return errors.New("application name or ID already exists")
		}
	}
	w.state.applications[a.ARN] = cloneApplication(a)
	return nil
}
func (w memoryWriter) DeleteApplication(scope Scope, identifier string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	a, ok := w.findApplication(scope, identifier)
	if !ok {
		return nil
	}
	delete(w.state.applications, a.ARN)
	for link := range w.state.attributeLinks {
		if link.applicationARN == a.ARN {
			delete(w.state.attributeLinks, link)
		}
	}
	for key := range w.state.associations {
		if key.applicationARN == a.ARN {
			delete(w.state.associations, key)
		}
	}
	return nil
}
func (r memoryReader) findAttributeGroup(scope Scope, identifier string) (AttributeGroup, bool) {
	if g, ok := r.state.attributeGroups[identifier]; ok && g.Scope == scope {
		return g, true
	}
	var named AttributeGroup
	found := false
	for _, g := range r.state.attributeGroups {
		if g.Scope != scope {
			continue
		}
		if g.ID == identifier {
			return g, true
		}
		if g.Name == identifier {
			named, found = g, true
		}
	}
	return named, found
}
func (r memoryReader) AttributeGroup(scope Scope, identifier string) (AttributeGroup, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return AttributeGroup{}, false, err
	}
	g, ok := r.findAttributeGroup(scope, identifier)
	return cloneAttributeGroup(g), ok, nil
}
func (r memoryReader) AttributeGroups(scope Scope) ([]AttributeGroup, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []AttributeGroup{}
	for _, g := range r.state.attributeGroups {
		if g.Scope == scope {
			out = append(out, cloneAttributeGroup(g))
		}
	}
	slices.SortFunc(out, func(a, b AttributeGroup) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) PutAttributeGroup(g AttributeGroup) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if current, ok := w.state.attributeGroups[g.ARN]; ok && (current.Scope != g.Scope || current.ID != g.ID) {
		return errors.New("attribute group ARN belongs to another scope or ID")
	}
	for arn, current := range w.state.attributeGroups {
		if arn != g.ARN && current.Scope == g.Scope && (current.Name == g.Name || current.ID == g.ID) {
			return errors.New("attribute group name or ID already exists")
		}
	}
	w.state.attributeGroups[g.ARN] = cloneAttributeGroup(g)
	return nil
}
func (w memoryWriter) DeleteAttributeGroup(scope Scope, identifier string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	g, ok := w.findAttributeGroup(scope, identifier)
	if !ok {
		return nil
	}
	delete(w.state.attributeGroups, g.ARN)
	for link := range w.state.attributeLinks {
		if link.attributeGroupARN == g.ARN {
			delete(w.state.attributeLinks, link)
		}
	}
	return nil
}
func (r memoryReader) AttributeGroupAssociations(applicationARN string) ([]string, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []string{}
	for link := range r.state.attributeLinks {
		if link.applicationARN == applicationARN {
			out = append(out, link.attributeGroupARN)
		}
	}
	slices.Sort(out)
	return out, nil
}
func (w memoryWriter) AssociateAttributeGroup(applicationARN, attributeGroupARN string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	a, appExists := w.state.applications[applicationARN]
	g, groupExists := w.state.attributeGroups[attributeGroupARN]
	if !appExists || !groupExists || a.Scope != g.Scope {
		return errors.New("application and attribute group must exist in the same scope")
	}
	w.state.attributeLinks[attributeLink{applicationARN, attributeGroupARN}] = struct{}{}
	return nil
}
func (w memoryWriter) DisassociateAttributeGroup(applicationARN, attributeGroupARN string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.attributeLinks, attributeLink{applicationARN, attributeGroupARN})
	return nil
}
func (r memoryReader) Associations(applicationARN string) ([]Association, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Association{}
	for key, a := range r.state.associations {
		if key.applicationARN == applicationARN {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(a, b Association) int { return strings.Compare(a.ResourceARN, b.ResourceARN) })
	return out, nil
}
func (w memoryWriter) PutAssociation(a Association) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.state.applications[a.ApplicationARN]; !ok {
		return errors.New("application does not exist")
	}
	w.state.associations[associationKey{a.ApplicationARN, a.ResourceARN}] = a
	return nil
}
func (w memoryWriter) DeleteAssociation(applicationARN, resourceARN string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.associations, associationKey{applicationARN, resourceARN})
	return nil
}
func (r memoryReader) Configuration(scope Scope) (Configuration, error) {
	if err := r.tx.Check(false); err != nil {
		return Configuration{}, err
	}
	if c, ok := r.state.configurations[scope]; ok {
		return c, nil
	}
	return Configuration{Scope: scope}, nil
}
func (w memoryWriter) PutConfiguration(c Configuration) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.configurations[c.Scope] = c
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
