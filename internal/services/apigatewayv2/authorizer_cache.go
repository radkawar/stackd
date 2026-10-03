package apigatewayv2

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/apigatewayv2"
	"stackd/internal/services/apigatewayexec"
)

func authorizerCacheKey(route *apigatewayexec.Route, identityKey string) AuthorizerCacheKey {
	return AuthorizerCacheKey{Stage: ResourceKey{APIKey: APIKey{Scope: Scope{Partition: route.Partition, AccountID: route.AccountID, Region: route.Region}, ID: route.APIID}, ID: route.Stage}, AuthorizerID: route.LambdaAuthorizer.ID, IdentityKey: identityKey}
}

func (s *Service) LoadAuthorizerResult(ctx context.Context, route *apigatewayexec.Route, identityKey string) (apigatewayexec.AuthorizerResult, bool, error) {
	var result apigatewayexec.AuthorizerResult
	if route == nil || route.LambdaAuthorizer == nil || route.LambdaAuthorizer.TTLSeconds <= 0 {
		return result, false, nil
	}
	found := false
	err := s.repository.View(ctx, func(r Reader) error {
		row, err := r.AuthorizerCache(authorizerCacheKey(route, identityKey))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if s.clock.Now().Before(row.ExpiresAt) {
			result, found = row.AuthorizerResult, true
		}
		return nil
	})
	return result, found, err
}

func (s *Service) StoreAuthorizerResult(ctx context.Context, route *apigatewayexec.Route, identityKey string, result apigatewayexec.AuthorizerResult) error {
	if route == nil || route.LambdaAuthorizer == nil || route.LambdaAuthorizer.TTLSeconds <= 0 {
		return nil
	}
	key := authorizerCacheKey(route, identityKey)
	return s.repository.Update(ctx, func(tx Transaction) error {
		// Invocation happened outside this transaction. A deleted stage or authorizer
		// must not be recreated by its completion; reset has no in-flight fencing.
		if _, err := tx.Stage(key.Stage); errors.Is(err, ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		if _, err := tx.Authorizer(ResourceKey{key.Stage.APIKey, key.AuthorizerID}); errors.Is(err, ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		now := s.clock.Now()
		if err := tx.PruneAuthorizerCache(key.Stage.APIKey, now); err != nil {
			return err
		}
		return tx.PutAuthorizerCache(AuthorizerCacheRecord{Key: key, AuthorizerResult: result, ExpiresAt: now.Add(time.Duration(route.LambdaAuthorizer.TTLSeconds) * time.Second)})
	})
}

func (s *Service) resetAuthorizersCache(tx Transaction, in *api.ResetAuthorizersCacheInput) (*api.ResetAuthorizersCacheOutput, error) {
	owner, err := s.ownedAPI(tx, "DELETE", value(in.ApiId), "/stages/"+value(in.StageName)+"/cache/authorizers")
	if err != nil {
		return nil, err
	}
	key := ResourceKey{owner.Key, value(in.StageName)}
	if _, err := tx.Stage(key); errors.Is(err, ErrNotFound) {
		return nil, failure("NotFoundException", "Invalid stage identifier specified", 404)
	} else if err != nil {
		return nil, err
	}
	// TODO: Comeback model regional cache propagation. Native 204 resets only
	// partially converged; deterministic local invalidation does not emulate
	// asynchronous, nonmonotonic propagation or promise an in-flight barrier.
	if err := tx.DeleteStageAuthorizerCache(key); err != nil {
		return nil, err
	}
	return &api.ResetAuthorizersCacheOutput{}, nil
}
