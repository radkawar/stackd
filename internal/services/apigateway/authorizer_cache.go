package apigateway

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/services/apigatewayexec"
)

func authorizerCacheKey(route *apigatewayexec.Route, identity string) AuthorizerCacheKey {
	return AuthorizerCacheKey{StageKey: StageKey{APIKey: APIKey{Scope: Scope{Partition: route.Partition, AccountID: route.AccountID, Region: route.Region}, ID: route.APIID}, Name: route.Stage}, AuthorizerID: route.LambdaAuthorizer.ID, IdentityKey: identity}
}

// cacheOwner checks live ownership without recreating resources for an invocation
// which completed after control-plane deletion or a stage deployment change.
func cacheOwner(r Reader, key AuthorizerCacheKey, deploymentID string) (bool, error) {
	stage, err := r.Stage(key.StageKey)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if stage.DeploymentID != deploymentID {
		return false, nil
	}
	_, err = r.Authorizer(AuthorizerKey{APIKey: key.APIKey, AuthorizerID: key.AuthorizerID})
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (s *Service) LoadAuthorizerResult(ctx context.Context, route *apigatewayexec.Route, identity string) (apigatewayexec.AuthorizerResult, bool, error) {
	var result apigatewayexec.AuthorizerResult
	if route == nil || route.LambdaAuthorizer == nil || route.LambdaAuthorizer.TTLSeconds <= 0 {
		return result, false, nil
	}
	key := authorizerCacheKey(route, identity)
	found := false
	err := s.repository.View(ctx, func(r Reader) error {
		live, err := cacheOwner(r, key, route.DeploymentID)
		if err != nil || !live {
			return err
		}
		row, err := r.AuthorizerCache(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if s.clock.Now().Before(row.ExpiresAt) {
			result, found = row.Result, true
		}
		return nil
	})
	return result, found, err
}

func (s *Service) StoreAuthorizerResult(ctx context.Context, route *apigatewayexec.Route, identity string, result apigatewayexec.AuthorizerResult) error {
	if route == nil || route.LambdaAuthorizer == nil || route.LambdaAuthorizer.TTLSeconds <= 0 {
		return nil
	}
	key := authorizerCacheKey(route, identity)
	return s.repository.Update(ctx, func(tx Transaction) error {
		live, err := cacheOwner(tx, key, route.DeploymentID)
		if err != nil || !live {
			return err
		}
		now := s.clock.Now()
		if err := tx.PruneAuthorizerCache(key.StageKey, now); err != nil {
			return err
		}
		return tx.PutAuthorizerCache(AuthorizerCacheRecord{Key: key, Result: result, ExpiresAt: now.Add(time.Duration(route.LambdaAuthorizer.TTLSeconds) * time.Second)})
	})
}

func (s *Service) flushStageAuthorizersCache(tx Transaction, in *api.FlushStageAuthorizersCacheRequest) (*api.Unit, error) {
	owner, err := s.api(tx, value(in.RestApiId), "DELETE", "/stages/"+value(in.StageName)+"/cache/authorizers")
	if err != nil {
		return nil, err
	}
	key := StageKey{APIKey: owner.Key, Name: value(in.StageName)}
	if _, err := tx.Stage(key); err != nil {
		return nil, err
	}
	// TODO: Comeback model regional cache propagation. Native returns 202 and
	// can alternate fresh and old results; local invalidation is deterministic.
	return &api.Unit{}, tx.DeleteStageAuthorizerCache(key)
}
