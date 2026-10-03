package apigatewayv2

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"stackd/internal/services/apigatewayexec"
	"stackd/storage/memory"
	"time"
)

type memoryState struct {
	apis            map[APIKey]APIRecord
	integrations    map[ResourceKey]IntegrationRecord
	authorizers     map[ResourceKey]AuthorizerRecord
	routes          map[ResourceKey]RouteRecord
	routeResponses  map[ResourceKey]RouteResponseRecord
	stages          map[ResourceKey]StageRecord
	deployments     map[ResourceKey]DeploymentRecord
	snapshots       map[ResourceKey]map[string]DeployedRoute
	authorizerCache map[AuthorizerCacheKey]AuthorizerCacheRecord
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{apis: map[APIKey]APIRecord{}, integrations: map[ResourceKey]IntegrationRecord{}, authorizers: map[ResourceKey]AuthorizerRecord{}, routes: map[ResourceKey]RouteRecord{}, stages: map[ResourceKey]StageRecord{}, deployments: map[ResourceKey]DeploymentRecord{}, snapshots: map[ResourceKey]map[string]DeployedRoute{}}
	initial.authorizerCache = map[AuthorizerCacheKey]AuthorizerCacheRecord{}
	initial.routeResponses = map[ResourceKey]RouteResponseRecord{}
	return &MemoryRepository{store: memory.New(domain, initial, func(s memoryState) memoryState {
		s.apis = maps.Clone(s.apis)
		s.integrations = maps.Clone(s.integrations)
		s.authorizers = maps.Clone(s.authorizers)
		s.routes = maps.Clone(s.routes)
		s.routeResponses = maps.Clone(s.routeResponses)
		s.stages = maps.Clone(s.stages)
		s.deployments = maps.Clone(s.deployments)
		s.snapshots = maps.Clone(s.snapshots)
		s.authorizerCache = maps.Clone(s.authorizerCache)
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

func (r memoryReader) Context() context.Context              { return r.tx.Context() }
func cloneAPI(v APIRecord) APIRecord                         { v.Tags = maps.Clone(v.Tags); return v }
func cloneIntegration(v IntegrationRecord) IntegrationRecord { return v }
func cloneAuthorizer(v AuthorizerRecord) AuthorizerRecord {
	v.Audiences = slices.Clone(v.Audiences)
	v.LambdaAuthorizer = cloneLambdaAuthorizer(v.LambdaAuthorizer)
	return v
}
func cloneRoute(v RouteRecord) RouteRecord { v.Scopes = slices.Clone(v.Scopes); return v }
func cloneStage(v StageRecord) StageRecord {
	v.Tags = maps.Clone(v.Tags)
	v.Variables = maps.Clone(v.Variables)
	v.DefaultRouteSettings = cloneRouteSettings(v.DefaultRouteSettings)
	v.RouteSettings = maps.Clone(v.RouteSettings)
	for key, settings := range v.RouteSettings {
		v.RouteSettings[key] = cloneRouteSettings(settings)
	}
	return v
}

func cloneRouteSettings(v RouteSettings) RouteSettings {
	if v.DetailedMetricsEnabled != nil {
		v.DetailedMetricsEnabled = new(*v.DetailedMetricsEnabled)
	}
	if v.DataTraceEnabled != nil {
		v.DataTraceEnabled = new(*v.DataTraceEnabled)
	}
	return v
}
func cloneDeployment(v DeploymentRecord) DeploymentRecord { return v }
func cloneDeployed(v DeployedRoute) DeployedRoute {
	v.Audiences = slices.Clone(v.Audiences)
	v.Scopes = slices.Clone(v.Scopes)
	v.LambdaAuthorizer = cloneLambdaAuthorizer(v.LambdaAuthorizer)
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
	if v.PrincipalID != nil {
		v.PrincipalID = new(*v.PrincipalID)
	}
	v.PolicyDocument = slices.Clone(v.PolicyDocument)
	v.Context = maps.Clone(v.Context)
	for k, raw := range v.Context {
		v.Context[k] = slices.Clone(raw)
	}
	if v.IsAuthorized != nil {
		v.IsAuthorized = new(*v.IsAuthorized)
	}
	return v
}

func (r memoryReader) API(key APIKey) (APIRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return APIRecord{}, err
	}
	v, ok := r.s.apis[key]
	if !ok {
		return APIRecord{}, ErrNotFound
	}
	return cloneAPI(v), nil
}
func (r memoryReader) APIs(key Scope) ([]APIRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := []APIRecord{}
	for k, v := range r.s.apis {
		if k.Scope == key {
			rows = append(rows, cloneAPI(v))
		}
	}
	slices.SortFunc(rows, func(a, b APIRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}
func (w memoryWriter) PutAPI(v APIRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k := range w.s.apis {
		if k.ID == v.Key.ID && k != v.Key {
			return errors.New("API ID is already owned")
		}
	}
	w.s.apis[v.Key] = cloneAPI(v)
	return nil
}

func (r memoryReader) Integration(key ResourceKey) (IntegrationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return IntegrationRecord{}, err
	}
	v, ok := r.s.integrations[key]
	if !ok {
		return IntegrationRecord{}, ErrNotFound
	}
	return cloneIntegration(v), nil
}
func (r memoryReader) Integrations(key APIKey) ([]IntegrationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := []IntegrationRecord{}
	for k, v := range r.s.integrations {
		if k.APIKey == key {
			rows = append(rows, cloneIntegration(v))
		}
	}
	slices.SortFunc(rows, func(a, b IntegrationRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}
func (w memoryWriter) PutIntegration(v IntegrationRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.integrations[v.Key] = cloneIntegration(v)
	return nil
}
func (w memoryWriter) DeleteIntegration(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.integrations, key)
	return nil
}

func (r memoryReader) Authorizer(key ResourceKey) (AuthorizerRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AuthorizerRecord{}, err
	}
	v, ok := r.s.authorizers[key]
	if !ok {
		return AuthorizerRecord{}, ErrNotFound
	}
	return cloneAuthorizer(v), nil
}
func (r memoryReader) Authorizers(key APIKey) ([]AuthorizerRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := []AuthorizerRecord{}
	for k, v := range r.s.authorizers {
		if k.APIKey == key {
			rows = append(rows, cloneAuthorizer(v))
		}
	}
	slices.SortFunc(rows, func(a, b AuthorizerRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}
func (w memoryWriter) PutAuthorizer(v AuthorizerRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.authorizers[v.Key] = cloneAuthorizer(v)
	return nil
}
func (w memoryWriter) DeleteAuthorizer(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.authorizers, key)
	for k := range w.s.authorizerCache {
		if k.Stage.APIKey == key.APIKey && k.AuthorizerID == key.ID {
			delete(w.s.authorizerCache, k)
		}
	}
	return nil
}

func (r memoryReader) Route(key ResourceKey) (RouteRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return RouteRecord{}, err
	}
	v, ok := r.s.routes[key]
	if !ok {
		return RouteRecord{}, ErrNotFound
	}
	return cloneRoute(v), nil
}
func (r memoryReader) Routes(key APIKey) ([]RouteRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := []RouteRecord{}
	for k, v := range r.s.routes {
		if k.APIKey == key {
			rows = append(rows, cloneRoute(v))
		}
	}
	slices.SortFunc(rows, func(a, b RouteRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}
func (w memoryWriter) PutRoute(v RouteRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.routes[v.Key] = cloneRoute(v)
	return nil
}
func (w memoryWriter) DeleteRoute(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.routes, key)
	for k, v := range w.s.routeResponses {
		if k.APIKey == key.APIKey && v.RouteID == key.ID {
			delete(w.s.routeResponses, k)
		}
	}
	return nil
}

func (r memoryReader) RouteResponse(key ResourceKey) (RouteResponseRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return RouteResponseRecord{}, err
	}
	v, ok := r.s.routeResponses[key]
	if !ok {
		return RouteResponseRecord{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) RouteResponses(key ResourceKey) ([]RouteResponseRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := []RouteResponseRecord{}
	for k, v := range r.s.routeResponses {
		if k.APIKey == key.APIKey && v.RouteID == key.ID {
			rows = append(rows, v)
		}
	}
	slices.SortFunc(rows, func(a, b RouteResponseRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}
func (w memoryWriter) PutRouteResponse(v RouteResponseRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, err := w.Route(ResourceKey{v.Key.APIKey, v.RouteID}); err != nil {
		return err
	}
	w.s.routeResponses[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteRouteResponse(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.routeResponses, key)
	return nil
}

func (r memoryReader) Stage(key ResourceKey) (StageRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return StageRecord{}, err
	}
	v, ok := r.s.stages[key]
	if !ok {
		return StageRecord{}, ErrNotFound
	}
	return cloneStage(v), nil
}
func (r memoryReader) Stages(key APIKey) ([]StageRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := []StageRecord{}
	for k, v := range r.s.stages {
		if k.APIKey == key {
			rows = append(rows, cloneStage(v))
		}
	}
	slices.SortFunc(rows, func(a, b StageRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}
func (w memoryWriter) PutStage(v StageRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.stages[v.Key] = cloneStage(v)
	return nil
}
func (w memoryWriter) DeleteStage(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.stages, key)
	return w.DeleteStageAuthorizerCache(key)
}

func (r memoryReader) Deployment(key ResourceKey) (DeploymentRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DeploymentRecord{}, err
	}
	v, ok := r.s.deployments[key]
	if !ok {
		return DeploymentRecord{}, ErrNotFound
	}
	return cloneDeployment(v), nil
}
func (r memoryReader) Deployments(key APIKey) ([]DeploymentRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := []DeploymentRecord{}
	for k, v := range r.s.deployments {
		if k.APIKey == key {
			rows = append(rows, cloneDeployment(v))
		}
	}
	slices.SortFunc(rows, func(a, b DeploymentRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}
func (w memoryWriter) PutDeployment(v DeploymentRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.deployments[v.Key] = cloneDeployment(v)
	return nil
}
func (w memoryWriter) DeleteDeployment(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.deployments, key)
	delete(w.s.snapshots, key)
	return nil
}

func (r memoryReader) APIByID(id string) (APIRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return APIRecord{}, err
	}
	for k, v := range r.s.apis {
		if k.ID == id {
			return cloneAPI(v), nil
		}
	}
	return APIRecord{}, ErrNotFound
}
func (w memoryWriter) DeleteAPI(key APIKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.apis, key)
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
	for k := range w.s.routes {
		if k.APIKey == key {
			delete(w.s.routes, k)
		}
	}
	for k := range w.s.routeResponses {
		if k.APIKey == key {
			delete(w.s.routeResponses, k)
		}
	}
	for k := range w.s.stages {
		if k.APIKey == key {
			delete(w.s.stages, k)
		}
	}
	for k := range w.s.deployments {
		if k.APIKey == key {
			delete(w.s.deployments, k)
		}
	}
	for k := range w.s.snapshots {
		if k.APIKey == key {
			delete(w.s.snapshots, k)
		}
	}
	for k := range w.s.authorizerCache {
		if k.Stage.APIKey == key {
			delete(w.s.authorizerCache, k)
		}
	}
	return nil
}
func (r memoryReader) DeployedRoutes(key ResourceKey) ([]DeployedRoute, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []DeployedRoute{}
	for _, v := range r.s.snapshots[key] {
		out = append(out, cloneDeployed(v))
	}
	slices.SortFunc(out, func(a, b DeployedRoute) int { return cmp.Compare(a.RouteID, b.RouteID) })
	return out, nil
}
func (w memoryWriter) PutDeployedRoute(v DeployedRoute) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	rows := maps.Clone(w.s.snapshots[v.Key])
	if rows == nil {
		rows = map[string]DeployedRoute{}
	}
	if _, exists := rows[v.RouteID]; exists {
		return errors.New("deployment route is immutable")
	}
	rows[v.RouteID] = cloneDeployed(v)
	w.s.snapshots[v.Key] = rows
	return nil
}

func (r memoryReader) AuthorizerCache(key AuthorizerCacheKey) (AuthorizerCacheRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AuthorizerCacheRecord{}, err
	}
	v, ok := r.s.authorizerCache[key]
	if !ok {
		return AuthorizerCacheRecord{}, ErrNotFound
	}
	return cloneAuthorizerCache(v), nil
}

func (w memoryWriter) PutAuthorizerCache(v AuthorizerCacheRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, err := w.Stage(v.Key.Stage); err != nil {
		return err
	}
	if _, err := w.Authorizer(ResourceKey{v.Key.Stage.APIKey, v.Key.AuthorizerID}); err != nil {
		return err
	}
	w.s.authorizerCache[v.Key] = cloneAuthorizerCache(v)
	return nil
}

func (w memoryWriter) DeleteStageAuthorizerCache(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k := range w.s.authorizerCache {
		if k.Stage == key {
			delete(w.s.authorizerCache, k)
		}
	}
	return nil
}

func (w memoryWriter) PruneAuthorizerCache(key APIKey, now time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k, v := range w.s.authorizerCache {
		if k.Stage.APIKey == key && !now.Before(v.ExpiresAt) {
			delete(w.s.authorizerCache, k)
		}
	}
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
var _ Transaction = memoryWriter{}
