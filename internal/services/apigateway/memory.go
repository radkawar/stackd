package apigateway

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"stackd/internal/services/apigatewayexec"
	"stackd/storage/memory"
	"time"
)

type memoryState struct {
	accounts         map[Scope]AccountRecord
	apis             map[APIKey]APIRecord
	resources        map[ResourceKey]ResourceRecord
	methods          map[MethodKey]MethodRecord
	integrations     map[MethodKey]IntegrationRecord
	authorizers      map[AuthorizerKey]AuthorizerRecord
	deployments      map[DeploymentKey]DeploymentRecord
	stages           map[StageKey]StageRecord
	stageSequence    map[Scope]uint64
	authorizerCache  map[AuthorizerCacheKey]AuthorizerCacheRecord
	clientKeys       map[ClientKey]ClientKeyRecord
	clientKeyValues  map[clientKeyValue]ClientKey
	usagePlans       map[PlanKey]UsagePlanRecord
	usageMemberships map[ClientKey]map[PlanKey]UsagePlanMembership
	usageDays        map[ClientKey]map[PlanKey]map[time.Time]int64
	metricSamples    map[MetricPublicationKey]map[metricSampleKey]int64
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{apis: map[APIKey]APIRecord{}, resources: map[ResourceKey]ResourceRecord{}, methods: map[MethodKey]MethodRecord{}, integrations: map[MethodKey]IntegrationRecord{}, authorizers: map[AuthorizerKey]AuthorizerRecord{}, deployments: map[DeploymentKey]DeploymentRecord{}, stages: map[StageKey]StageRecord{}}
	initial.accounts = map[Scope]AccountRecord{}
	initial.stageSequence = map[Scope]uint64{}
	initial.authorizerCache = map[AuthorizerCacheKey]AuthorizerCacheRecord{}
	initial.clientKeys = map[ClientKey]ClientKeyRecord{}
	initial.clientKeyValues = map[clientKeyValue]ClientKey{}
	initial.usagePlans = map[PlanKey]UsagePlanRecord{}
	initial.usageMemberships = map[ClientKey]map[PlanKey]UsagePlanMembership{}
	initial.usageDays = map[ClientKey]map[PlanKey]map[time.Time]int64{}
	initial.metricSamples = map[MetricPublicationKey]map[metricSampleKey]int64{}
	return &MemoryRepository{store: memory.New(domain, initial, func(s memoryState) memoryState {
		s.accounts = maps.Clone(s.accounts)
		s.apis = maps.Clone(s.apis)
		s.resources = maps.Clone(s.resources)
		s.methods = maps.Clone(s.methods)
		s.integrations = maps.Clone(s.integrations)
		s.authorizers = maps.Clone(s.authorizers)
		s.deployments = maps.Clone(s.deployments)
		s.stages = maps.Clone(s.stages)
		s.stageSequence = maps.Clone(s.stageSequence)
		s.authorizerCache = maps.Clone(s.authorizerCache)
		s.clientKeys = maps.Clone(s.clientKeys)
		s.clientKeyValues = maps.Clone(s.clientKeyValues)
		s.usagePlans = maps.Clone(s.usagePlans)
		s.usageMemberships = maps.Clone(s.usageMemberships)
		s.usageDays = maps.Clone(s.usageDays)
		s.metricSamples = maps.Clone(s.metricSamples)
		return s
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

func (r memoryReader) Account(scope Scope) (AccountRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AccountRecord{}, err
	}
	row, ok := r.s.accounts[scope]
	if !ok {
		return AccountRecord{}, ErrNotFound
	}
	return row, nil
}

func (w memoryWriter) PutAccount(row AccountRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.accounts[row.Scope] = row
	return nil
}

func cloneAPI(v APIRecord) APIRecord                         { v.Tags = maps.Clone(v.Tags); return v }
func cloneResource(v ResourceRecord) ResourceRecord          { return v }
func cloneMethod(v MethodRecord) MethodRecord                { v.Scopes = slices.Clone(v.Scopes); return v }
func cloneIntegration(v IntegrationRecord) IntegrationRecord { return v }
func cloneAuthorizer(v AuthorizerRecord) AuthorizerRecord {
	v.ProviderARNs = slices.Clone(v.ProviderARNs)
	v.LambdaAuthorizer = cloneLambdaAuthorizer(v.LambdaAuthorizer)
	return v
}
func cloneDeployment(v DeploymentRecord) DeploymentRecord {
	v.Resources = slices.Clone(v.Resources)
	v.Routes = slices.Clone(v.Routes)
	for i := range v.Routes {
		v.Routes[i].Scopes = slices.Clone(v.Routes[i].Scopes)
		v.Routes[i].UserPoolARNs = slices.Clone(v.Routes[i].UserPoolARNs)
		v.Routes[i].LambdaAuthorizer = cloneLambdaAuthorizer(v.Routes[i].LambdaAuthorizer)
	}
	return v
}
func cloneStage(v StageRecord) StageRecord {
	v.Variables = maps.Clone(v.Variables)
	v.Tags = maps.Clone(v.Tags)
	v.MethodSettings = maps.Clone(v.MethodSettings)
	return v
}
func cloneLambdaAuthorizer(v *apigatewayexec.LambdaAuthorizer) *apigatewayexec.LambdaAuthorizer {
	if v == nil {
		return nil
	}
	out := *v
	out.IdentitySources = slices.Clone(v.IdentitySources)
	return &out
}
func cloneAuthorizerCache(v AuthorizerCacheRecord) AuthorizerCacheRecord {
	if v.Result.PrincipalID != nil {
		v.Result.PrincipalID = new(*v.Result.PrincipalID)
	}
	v.Result.PolicyDocument = slices.Clone(v.Result.PolicyDocument)
	v.Result.Context = maps.Clone(v.Result.Context)
	for k, raw := range v.Result.Context {
		v.Result.Context[k] = slices.Clone(raw)
	}
	if v.Result.IsAuthorized != nil {
		authorized := *v.Result.IsAuthorized
		v.Result.IsAuthorized = &authorized
	}
	return v
}
func (r memoryReader) AuthorizerCache(key AuthorizerCacheKey) (AuthorizerCacheRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AuthorizerCacheRecord{}, err
	}
	row, ok := r.s.authorizerCache[key]
	if !ok {
		return AuthorizerCacheRecord{}, ErrNotFound
	}
	return cloneAuthorizerCache(row), nil
}
func (w memoryWriter) PutAuthorizerCache(row AuthorizerCacheRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, err := w.Stage(row.Key.StageKey); err != nil {
		return err
	}
	if _, err := w.Authorizer(AuthorizerKey{APIKey: row.Key.APIKey, AuthorizerID: row.Key.AuthorizerID}); err != nil {
		return err
	}
	w.s.authorizerCache[row.Key] = cloneAuthorizerCache(row)
	return nil
}
func (w memoryWriter) DeleteStageAuthorizerCache(key StageKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k := range w.s.authorizerCache {
		if k.StageKey == key {
			delete(w.s.authorizerCache, k)
		}
	}
	return nil
}
func (w memoryWriter) PruneAuthorizerCache(key StageKey, now time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k, row := range w.s.authorizerCache {
		if k.StageKey == key && !now.Before(row.ExpiresAt) {
			delete(w.s.authorizerCache, k)
		}
	}
	return nil
}
func (r memoryReader) API(key APIKey) (APIRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return APIRecord{}, e
	}
	v, ok := r.s.apis[key]
	if !ok {
		return APIRecord{}, ErrNotFound
	}
	return cloneAPI(v), nil
}
func (w memoryWriter) PutAPI(v APIRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.apis[v.Key] = cloneAPI(v)
	return nil
}
func (r memoryReader) APIs(key Scope) ([]APIRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []APIRecord{}
	for k, v := range r.s.apis {
		if k.Scope == key {
			out = append(out, cloneAPI(v))
		}
	}
	slices.SortFunc(out, func(a, b APIRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (r memoryReader) Resource(key ResourceKey) (ResourceRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return ResourceRecord{}, e
	}
	v, ok := r.s.resources[key]
	if !ok {
		return ResourceRecord{}, ErrNotFound
	}
	return cloneResource(v), nil
}
func (w memoryWriter) PutResource(v ResourceRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.resources[v.Key] = cloneResource(v)
	return nil
}
func (r memoryReader) Resources(key APIKey) ([]ResourceRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []ResourceRecord{}
	for k, v := range r.s.resources {
		if k.APIKey == key {
			out = append(out, cloneResource(v))
		}
	}
	slices.SortFunc(out, func(a, b ResourceRecord) int { return cmp.Compare(a.Key.ResourceID, b.Key.ResourceID) })
	return out, nil
}
func (r memoryReader) Method(key MethodKey) (MethodRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return MethodRecord{}, e
	}
	v, ok := r.s.methods[key]
	if !ok {
		return MethodRecord{}, ErrNotFound
	}
	return cloneMethod(v), nil
}
func (w memoryWriter) PutMethod(v MethodRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.methods[v.Key] = cloneMethod(v)
	return nil
}
func (r memoryReader) Methods(key APIKey) ([]MethodRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []MethodRecord{}
	for k, v := range r.s.methods {
		if k.APIKey == key {
			out = append(out, cloneMethod(v))
		}
	}
	slices.SortFunc(out, func(a, b MethodRecord) int {
		return cmp.Or(cmp.Compare(a.Key.ResourceID, b.Key.ResourceID), cmp.Compare(a.Key.HTTPMethod, b.Key.HTTPMethod))
	})
	return out, nil
}
func (r memoryReader) Integration(key MethodKey) (IntegrationRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return IntegrationRecord{}, e
	}
	v, ok := r.s.integrations[key]
	if !ok {
		return IntegrationRecord{}, ErrNotFound
	}
	return cloneIntegration(v), nil
}
func (w memoryWriter) PutIntegration(v IntegrationRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.integrations[v.Key] = cloneIntegration(v)
	return nil
}
func (r memoryReader) Authorizer(key AuthorizerKey) (AuthorizerRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return AuthorizerRecord{}, e
	}
	v, ok := r.s.authorizers[key]
	if !ok {
		return AuthorizerRecord{}, ErrNotFound
	}
	return cloneAuthorizer(v), nil
}
func (w memoryWriter) PutAuthorizer(v AuthorizerRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.authorizers[v.Key] = cloneAuthorizer(v)
	return nil
}
func (r memoryReader) Authorizers(key APIKey) ([]AuthorizerRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []AuthorizerRecord{}
	for k, v := range r.s.authorizers {
		if k.APIKey == key {
			out = append(out, cloneAuthorizer(v))
		}
	}
	slices.SortFunc(out, func(a, b AuthorizerRecord) int { return cmp.Compare(a.Key.AuthorizerID, b.Key.AuthorizerID) })
	return out, nil
}
func (r memoryReader) Deployment(key DeploymentKey) (DeploymentRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return DeploymentRecord{}, e
	}
	v, ok := r.s.deployments[key]
	if !ok {
		return DeploymentRecord{}, ErrNotFound
	}
	return cloneDeployment(v), nil
}
func (w memoryWriter) PutDeployment(v DeploymentRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.deployments[v.Key] = cloneDeployment(v)
	return nil
}
func (r memoryReader) Deployments(key APIKey) ([]DeploymentRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []DeploymentRecord{}
	for k, v := range r.s.deployments {
		if k.APIKey == key {
			out = append(out, cloneDeployment(v))
		}
	}
	slices.SortFunc(out, func(a, b DeploymentRecord) int { return cmp.Compare(a.Key.DeploymentID, b.Key.DeploymentID) })
	return out, nil
}
func (r memoryReader) Stage(key StageKey) (StageRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return StageRecord{}, e
	}
	v, ok := r.s.stages[key]
	if !ok {
		return StageRecord{}, ErrNotFound
	}
	return cloneStage(v), nil
}
func (w memoryWriter) PutStage(v StageRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.stages[v.Key] = cloneStage(v)
	return nil
}
func (r memoryReader) Stages(key APIKey) ([]StageRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []StageRecord{}
	for k, v := range r.s.stages {
		if k.APIKey == key {
			out = append(out, cloneStage(v))
		}
	}
	slices.SortFunc(out, func(a, b StageRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) Owner(id string) (APIRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return APIRecord{}, e
	}
	for k, v := range r.s.apis {
		if k.ID == id {
			return cloneAPI(v), nil
		}
	}
	return APIRecord{}, ErrNotFound
}
func (w memoryWriter) DeleteAPI(key APIKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.apis, key)
	w.deleteUsageStages(func(stage StageKey) bool { return stage.APIKey == key })
	for k := range w.s.resources {
		if k.APIKey == key {
			delete(w.s.resources, k)
		}
	}
	for k := range w.s.methods {
		if k.APIKey == key {
			delete(w.s.methods, k)
		}
	}
	for k := range w.s.integrations {
		if k.APIKey == key {
			delete(w.s.integrations, k)
		}
	}
	for k := range w.s.authorizers {
		if k.APIKey == key {
			delete(w.s.authorizers, k)
		}
	}
	for k := range w.s.deployments {
		if k.APIKey == key {
			delete(w.s.deployments, k)
		}
	}
	for k := range w.s.stages {
		if k.APIKey == key {
			delete(w.s.stages, k)
		}
	}
	for k := range w.s.authorizerCache {
		if k.APIKey == key {
			delete(w.s.authorizerCache, k)
		}
	}
	return nil
}
func (w memoryWriter) DeleteResource(key ResourceKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.resources, key)
	for k := range w.s.methods {
		if k.ResourceKey == key {
			delete(w.s.methods, k)
			delete(w.s.integrations, k)
		}
	}
	return nil
}
func (w memoryWriter) DeleteMethod(key MethodKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.methods, key)
	delete(w.s.integrations, key)
	return nil
}
func (w memoryWriter) DeleteIntegration(key MethodKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.integrations, key)
	return nil
}
func (w memoryWriter) DeleteAuthorizer(key AuthorizerKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.authorizers, key)
	for k := range w.s.authorizerCache {
		if k.APIKey == key.APIKey && k.AuthorizerID == key.AuthorizerID {
			delete(w.s.authorizerCache, k)
		}
	}
	return nil
}
func (w memoryWriter) DeleteDeployment(key DeploymentKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.deployments, key)
	return nil
}
func (w memoryWriter) DeleteStage(key StageKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.stages, key)
	w.deleteUsageStages(func(stage StageKey) bool { return stage == key })
	return w.DeleteStageAuthorizerCache(key)
}

var _ Repository = (*MemoryRepository)(nil)
var _ Transaction = memoryWriter{}
