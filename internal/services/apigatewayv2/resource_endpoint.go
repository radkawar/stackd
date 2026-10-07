package apigatewayv2

import (
	"errors"
	"net/http"
	"strings"

	"stackd/internal/endpoints"
	"stackd/internal/services/apigatewayexec"
)

// ResourceExecution binds the generated host to the current regional API owner.
// It deliberately does not bypass DisableExecuteApiEndpoint like a custom domain.
func (s *Service) ResourceExecution(r *http.Request) (apigatewayexec.ExecutionTarget, bool, error) {
	id, region, matched := endpoints.ResourceHost(r.Host, s.endpointDomain, "execute-api")
	if !matched {
		return apigatewayexec.ExecutionTarget{}, false, nil
	}
	var target apigatewayexec.ExecutionTarget
	err := s.repository.View(r.Context(), func(reader Reader) error {
		owner, err := reader.APIByID(id)
		if err != nil {
			return err
		}
		if region == "" || owner.Key.Region != region {
			return ErrNotFound
		}
		target = apigatewayexec.ExecutionTarget{APIID: id, Path: r.URL.Path, DefaultEndpoint: true}
		if owner.ProtocolType == "WEBSOCKET" {
			stage, path, _ := strings.Cut(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/")
			target.Stage, target.Path = stage, "/"+path
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		err = apigatewayexec.ErrUnknownAPI
	}
	return target, true, err
}
