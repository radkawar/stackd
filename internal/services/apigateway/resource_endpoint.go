package apigateway

import (
	"context"
	"errors"
	"net/http"

	"stackd/internal/endpoints"
	"stackd/internal/services/apigatewayexec"
)

// ResourceExecution resolves the live global API owner, never caller account
// metadata. The execution handler retains all deployed-stage and IAM admission.
func (s *Service) ResourceExecution(r *http.Request) (apigatewayexec.ExecutionTarget, bool, error) {
	id, region, matched := endpoints.ResourceHost(r.Host, s.endpointDomain, "execute-api")
	if !matched {
		return apigatewayexec.ExecutionTarget{}, false, nil
	}
	var target apigatewayexec.ExecutionTarget
	err := s.repository.View(r.Context(), func(reader Reader) error {
		owner, err := reader.Owner(id)
		if err != nil {
			return err
		}
		if region == "" || owner.Key.Region != region {
			return ErrNotFound
		}
		target = apigatewayexec.ExecutionTarget{APIID: id, Path: r.URL.Path, DefaultEndpoint: true, REST: true}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		err = apigatewayexec.ErrUnknownAPI
	}
	return target, true, err
}

// ResourceURL exposes a REST API's current public invocation origin. REST's AWS
// control response has no endpoint field; consumers can use this owner-backed API.
func (s *Service) ResourceURL(ctx context.Context, id string) (string, error) {
	var origin string
	err := s.repository.View(ctx, func(reader Reader) error {
		owner, err := reader.Owner(id)
		if err != nil {
			return err
		}
		if s.endpointDomain == "" {
			origin = s.endpoint + apigatewayexec.Prefix + id + "/"
			return nil
		}
		origin, err = endpoints.ResourceURL(s.endpoint, s.endpointDomain, "execute-api", owner.Key.Region, id)
		return err
	})
	return origin, err
}
