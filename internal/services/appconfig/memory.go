package appconfig

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type memoryApplicationKey struct {
	Scope
	ID string
}
type memoryEnvironmentKey struct {
	Scope
	ApplicationID string
	ID            string
}
type memoryProfileKey struct {
	Scope
	ApplicationID string
	ID            string
}
type memoryHostedVersionKey struct {
	Scope
	ApplicationID string
	ProfileID     string
	Number        int32
}
type memoryStrategyKey struct {
	Scope
	ID string
}
type memoryDeploymentKey struct {
	Scope
	ApplicationID string
	EnvironmentID string
	Number        int32
}
type memorySessionKey struct {
	Scope
	Token string
}
type memoryExtensionKey struct {
	Scope
	ID      string
	Version int32
}
type memoryAssociationKey struct {
	Scope
	ID string
}
type memoryTagKey struct {
	Scope
	ARN string
}

type memoryState struct {
	experimentState
	applications   map[memoryApplicationKey]Application
	environments   map[memoryEnvironmentKey]Environment
	profiles       map[memoryProfileKey]Profile
	hostedVersions map[memoryHostedVersionKey]HostedVersion
	strategies     map[memoryStrategyKey]Strategy
	deployments    map[memoryDeploymentKey]Deployment
	sessions       map[memorySessionKey]Session
	extensions     map[memoryExtensionKey]Extension
	associations   map[memoryAssociationKey]Association
	tags           map[memoryTagKey]map[string]string
	settings       map[Scope]Settings
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{store: memory.New(d, memoryState{
		experimentState: newExperimentState(),
		applications:    map[memoryApplicationKey]Application{},
		environments:    map[memoryEnvironmentKey]Environment{},
		profiles:        map[memoryProfileKey]Profile{},
		hostedVersions:  map[memoryHostedVersionKey]HostedVersion{},
		strategies:      map[memoryStrategyKey]Strategy{},
		deployments:     map[memoryDeploymentKey]Deployment{},
		sessions:        map[memorySessionKey]Session{},
		extensions:      map[memoryExtensionKey]Extension{},
		associations:    map[memoryAssociationKey]Association{},
		tags:            map[memoryTagKey]map[string]string{}, settings: map[Scope]Settings{},
	}, func(s memoryState) memoryState {
		// Nested values are immutable in storage; all writes and reads clone them.
		s.experimentState = cloneExperimentState(s.experimentState)
		s.applications = maps.Clone(s.applications)
		s.environments = maps.Clone(s.environments)
		s.profiles = maps.Clone(s.profiles)
		s.hostedVersions = maps.Clone(s.hostedVersions)
		s.strategies = maps.Clone(s.strategies)
		s.deployments = maps.Clone(s.deployments)
		s.sessions = maps.Clone(s.sessions)
		s.extensions = maps.Clone(s.extensions)
		s.associations = maps.Clone(s.associations)
		s.tags = maps.Clone(s.tags)
		s.settings = maps.Clone(s.settings)
		return s
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryReader{s, t}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, t}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, t}}) })
}

type memoryReader struct {
	s *memoryState
	t *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.t.Context() }

func cloneEnvironment(v Environment) Environment       { v.Monitors = slices.Clone(v.Monitors); return v }
func cloneProfile(v Profile) Profile                   { v.Validators = slices.Clone(v.Validators); return v }
func cloneHostedVersion(v HostedVersion) HostedVersion { v.Content = slices.Clone(v.Content); return v }
func cloneExtension(v Extension) Extension {
	v.Actions = slices.Clone(v.Actions)
	v.Parameters = slices.Clone(v.Parameters)
	return v
}
func cloneAssociation(v Association) Association { v.Parameters = maps.Clone(v.Parameters); return v }
func cloneDeployment(v Deployment) Deployment {
	v.Content = slices.Clone(v.Content)
	v.Events = slices.Clone(v.Events)
	for i := range v.Events {
		v.Events[i].Invocations = slices.Clone(v.Events[i].Invocations)
	}
	v.Extensions = slices.Clone(v.Extensions)
	for i := range v.Extensions {
		v.Extensions[i].Parameters = maps.Clone(v.Extensions[i].Parameters)
		v.Extensions[i].Actions = slices.Clone(v.Extensions[i].Actions)
	}
	v.DynamicParameters = maps.Clone(v.DynamicParameters)
	for k, values := range v.DynamicParameters {
		v.DynamicParameters[k] = slices.Clone(values)
	}
	return v
}
func compareMemoryScope(a, b Scope) int {
	if n := cmp.Compare(a.Partition, b.Partition); n != 0 {
		return n
	}
	if n := cmp.Compare(a.AccountID, b.AccountID); n != 0 {
		return n
	}
	return cmp.Compare(a.Region, b.Region)
}

func (r memoryReader) Applications(s Scope) ([]Application, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Application{}
	for _, v := range r.s.applications {
		if v.Scope == s {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Application) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}
func (w memoryWriter) PutApplication(v Application) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.applications[memoryApplicationKey{Scope: v.Scope, ID: v.ID}] = v
	return nil
}
func (w memoryWriter) DeleteApplication(s Scope, iD string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.applications, memoryApplicationKey{Scope: s, ID: iD})
	return nil
}

func (r memoryReader) Environments(s Scope, applicationID string) ([]Environment, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Environment{}
	for _, v := range r.s.environments {
		if v.Scope == s && v.ApplicationID == applicationID {
			out = append(out, cloneEnvironment(v))
		}
	}
	slices.SortFunc(out, func(a, b Environment) int {
		if n := cmp.Compare(a.ApplicationID, b.ApplicationID); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}
func (w memoryWriter) PutEnvironment(v Environment) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.environments[memoryEnvironmentKey{Scope: v.Scope, ApplicationID: v.ApplicationID, ID: v.ID}] = cloneEnvironment(v)
	return nil
}
func (w memoryWriter) DeleteEnvironment(s Scope, applicationID string, iD string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.environments, memoryEnvironmentKey{Scope: s, ApplicationID: applicationID, ID: iD})
	return nil
}

func (r memoryReader) Profiles(s Scope, applicationID string) ([]Profile, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Profile{}
	for _, v := range r.s.profiles {
		if v.Scope == s && v.ApplicationID == applicationID {
			out = append(out, cloneProfile(v))
		}
	}
	slices.SortFunc(out, func(a, b Profile) int {
		if n := cmp.Compare(a.ApplicationID, b.ApplicationID); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}
func (w memoryWriter) PutProfile(v Profile) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.profiles[memoryProfileKey{Scope: v.Scope, ApplicationID: v.ApplicationID, ID: v.ID}] = cloneProfile(v)
	return nil
}
func (w memoryWriter) DeleteProfile(s Scope, applicationID string, iD string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.profiles, memoryProfileKey{Scope: s, ApplicationID: applicationID, ID: iD})
	return nil
}

func (r memoryReader) HostedVersions(s Scope, applicationID string, profileID string) ([]HostedVersion, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []HostedVersion{}
	for _, v := range r.s.hostedVersions {
		if v.Scope == s && v.ApplicationID == applicationID && v.ProfileID == profileID {
			out = append(out, cloneHostedVersion(v))
		}
	}
	slices.SortFunc(out, func(a, b HostedVersion) int {
		if n := cmp.Compare(a.ApplicationID, b.ApplicationID); n != 0 {
			return n
		}
		if n := cmp.Compare(a.ProfileID, b.ProfileID); n != 0 {
			return n
		}
		return cmp.Compare(a.Number, b.Number)
	})
	return out, nil
}
func (w memoryWriter) PutHostedVersion(v HostedVersion) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.hostedVersions[memoryHostedVersionKey{Scope: v.Scope, ApplicationID: v.ApplicationID, ProfileID: v.ProfileID, Number: v.Number}] = cloneHostedVersion(v)
	return nil
}
func (w memoryWriter) DeleteHostedVersion(s Scope, applicationID string, profileID string, number int32) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.hostedVersions, memoryHostedVersionKey{Scope: s, ApplicationID: applicationID, ProfileID: profileID, Number: number})
	return nil
}

func (r memoryReader) Strategies(s Scope) ([]Strategy, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Strategy{}
	for _, v := range r.s.strategies {
		if v.Scope == s {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Strategy) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}
func (w memoryWriter) PutStrategy(v Strategy) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.strategies[memoryStrategyKey{Scope: v.Scope, ID: v.ID}] = v
	return nil
}
func (w memoryWriter) DeleteStrategy(s Scope, iD string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.strategies, memoryStrategyKey{Scope: s, ID: iD})
	return nil
}

func (r memoryReader) Deployments(s Scope, applicationID string, environmentID string) ([]Deployment, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Deployment{}
	for _, v := range r.s.deployments {
		if v.Scope == s && v.ApplicationID == applicationID && v.EnvironmentID == environmentID {
			out = append(out, cloneDeployment(v))
		}
	}
	slices.SortFunc(out, func(a, b Deployment) int {
		if n := cmp.Compare(a.ApplicationID, b.ApplicationID); n != 0 {
			return n
		}
		if n := cmp.Compare(a.EnvironmentID, b.EnvironmentID); n != 0 {
			return n
		}
		return cmp.Compare(a.Number, b.Number)
	})
	return out, nil
}
func (w memoryWriter) PutDeployment(v Deployment) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.deployments[memoryDeploymentKey{Scope: v.Scope, ApplicationID: v.ApplicationID, EnvironmentID: v.EnvironmentID, Number: v.Number}] = cloneDeployment(v)
	return nil
}
func (w memoryWriter) DeleteDeployment(s Scope, applicationID string, environmentID string, number int32) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.deployments, memoryDeploymentKey{Scope: s, ApplicationID: applicationID, EnvironmentID: environmentID, Number: number})
	return nil
}

func (r memoryReader) Session(s Scope, token string) (Session, bool, error) {
	if err := r.t.Check(false); err != nil {
		return Session{}, false, err
	}
	v, ok := r.s.sessions[memorySessionKey{Scope: s, Token: token}]
	return v, ok, nil
}

func (r memoryReader) Sessions(s Scope) ([]Session, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Session{}
	for _, v := range r.s.sessions {
		if v.Scope == s {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Session) int {
		return cmp.Compare(a.Token, b.Token)
	})
	return out, nil
}
func (w memoryWriter) PutSession(v Session) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.sessions[memorySessionKey{Scope: v.Scope, Token: v.Token}] = v
	return nil
}
func (w memoryWriter) DeleteSession(s Scope, token string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.sessions, memorySessionKey{Scope: s, Token: token})
	return nil
}

func (r memoryReader) Extensions(s Scope) ([]Extension, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Extension{}
	for _, v := range r.s.extensions {
		if v.Scope == s {
			out = append(out, cloneExtension(v))
		}
	}
	slices.SortFunc(out, func(a, b Extension) int {
		if n := cmp.Compare(a.ID, b.ID); n != 0 {
			return n
		}
		return cmp.Compare(a.Version, b.Version)
	})
	return out, nil
}
func (w memoryWriter) PutExtension(v Extension) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.extensions[memoryExtensionKey{Scope: v.Scope, ID: v.ID, Version: v.Version}] = cloneExtension(v)
	return nil
}
func (w memoryWriter) DeleteExtension(s Scope, iD string, version int32) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.extensions, memoryExtensionKey{Scope: s, ID: iD, Version: version})
	return nil
}

func (r memoryReader) Associations(s Scope) ([]Association, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Association{}
	for _, v := range r.s.associations {
		if v.Scope == s {
			out = append(out, cloneAssociation(v))
		}
	}
	slices.SortFunc(out, func(a, b Association) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}
func (w memoryWriter) PutAssociation(v Association) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.associations[memoryAssociationKey{Scope: v.Scope, ID: v.ID}] = cloneAssociation(v)
	return nil
}
func (w memoryWriter) DeleteAssociation(s Scope, iD string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.associations, memoryAssociationKey{Scope: s, ID: iD})
	return nil
}

// PendingDeployments scans all scopes in deadline order for scheduler recovery.
func (r memoryReader) PendingDeployments() ([]Deployment, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Deployment{}
	for _, v := range r.s.deployments {
		if !v.Due.IsZero() {
			out = append(out, cloneDeployment(v))
		}
	}
	slices.SortFunc(out, func(a, b Deployment) int {
		if n := a.Due.Compare(b.Due); n != 0 {
			return n
		}
		if n := compareMemoryScope(a.Scope, b.Scope); n != 0 {
			return n
		}
		if n := cmp.Compare(a.ApplicationID, b.ApplicationID); n != 0 {
			return n
		}
		if n := cmp.Compare(a.EnvironmentID, b.EnvironmentID); n != 0 {
			return n
		}
		return cmp.Compare(a.Number, b.Number)
	})
	return out, nil
}
func (r memoryReader) Tags(s Scope, arn string) (map[string]string, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	return maps.Clone(r.s.tags[memoryTagKey{s, arn}]), nil
}
func (w memoryWriter) PutTags(s Scope, arn string, tags map[string]string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	key := memoryTagKey{s, arn}
	if len(tags) == 0 {
		delete(w.s.tags, key)
	} else {
		w.s.tags[key] = maps.Clone(tags)
	}
	return nil
}
func (r memoryReader) Settings(s Scope) (Settings, bool, error) {
	if err := r.t.Check(false); err != nil {
		return Settings{}, false, err
	}
	v, ok := r.s.settings[s]
	return v, ok, nil
}
func (w memoryWriter) PutSettings(v Settings) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.settings[v.Scope] = v
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
var _ Transaction = memoryWriter{}
