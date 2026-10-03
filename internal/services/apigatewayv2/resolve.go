package apigatewayv2

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/services/apigatewayexec"
)

// Resolve selects the retained owner by global API ID, not caller credentials.
// Empty stage selects a named first segment, then falls back to $default without
// consuming an application path segment. Explicit stage receives a relative path.
func (s *Service) Resolve(ctx context.Context, apiID, stage, method, path string) (*apigatewayexec.Route, error) {
	var out *apigatewayexec.Route
	err := s.repository.View(ctx, func(r Reader) error {
		owner, err := r.APIByID(apiID)
		if errors.Is(err, ErrNotFound) {
			return apigatewayexec.ErrUnknownAPI
		}
		if err != nil {
			return err
		}
		if owner.ProtocolType == "WEBSOCKET" {
			return apigatewayexec.ErrUnknownAPI
		}
		if owner.Disabled {
			return failure("ForbiddenException", "Forbidden", 403)
		}
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		var selected StageRecord
		if stage == "" {
			first, rest, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
			if first != "" && first != "$default" {
				selected, err = r.Stage(ResourceKey{owner.Key, first})
			} else {
				err = ErrNotFound
			}
			if err == nil {
				stage = first
				path = "/" + rest
			} else if errors.Is(err, ErrNotFound) {
				stage = "$default"
				selected, err = r.Stage(ResourceKey{owner.Key, stage})
			}
		} else {
			selected, err = r.Stage(ResourceKey{owner.Key, stage})
		}
		if errors.Is(err, ErrNotFound) {
			return failure("NotFoundException", "Not Found", 404)
		}
		if err != nil {
			return err
		}
		if selected.DeploymentID == "" {
			return failure("NotFoundException", "Not Found", 404)
		}
		rows, err := r.DeployedRoutes(ResourceKey{owner.Key, selected.DeploymentID})
		if err != nil {
			return err
		}
		var best *DeployedRoute
		var bestParams map[string]string
		bestScore := ""
		resourcePath := ""
		for i := range rows {
			row := &rows[i]
			params, score, resource, ok := matchRoute(row.RouteKey, method, path)
			if ok && (best == nil || score > bestScore) {
				best = row
				bestParams = params
				bestScore = score
				resourcePath = resource
			}
		}
		if best == nil {
			return failure("NotFoundException", "Not Found", 404)
		}
		out = &apigatewayexec.Route{Partition: owner.Key.Partition, AccountID: owner.Key.AccountID, Region: owner.Key.Region, APIID: owner.Key.ID, APIName: owner.Name, Stage: stage, DeploymentID: selected.DeploymentID, ResourceID: best.RouteID, ResourcePath: resourcePath, RouteKey: best.RouteKey, FunctionARN: best.FunctionARN, PayloadVersion: best.PayloadVersion, AuthorizationType: best.AuthorizationType, Issuer: best.Issuer, Audiences: best.Audiences, Scopes: best.Scopes, StageVariables: selected.Variables, PathParameters: bestParams}
		out.ProtocolType = owner.ProtocolType
		out.DetailedMetricsEnabled = selected.detailedMetrics(best.RouteKey)
		out.Logging = selected.logging(best.RouteKey)
		out.LambdaAuthorizer = best.LambdaAuthorizer
		out.IntegrationTimeoutMillis = best.TimeoutMillis
		out.IntegrationCredentialsARN = best.CredentialsARN
		return nil
	})
	return out, err
}

// ResolveWebSocket follows the stage's current deployment for every event,
// including messages sent on connections established before a redeployment.
// An absent reserved route or message route returns owner/stage metadata with
// no FunctionARN, so the transport can distinguish these cases from a bad API.
func (s *Service) ResolveWebSocket(ctx context.Context, apiID, stage, routeKey string, body []byte) (*apigatewayexec.Route, error) {
	var out *apigatewayexec.Route
	err := s.repository.View(ctx, func(r Reader) error {
		owner, err := r.APIByID(apiID)
		if errors.Is(err, ErrNotFound) {
			return apigatewayexec.ErrUnknownAPI
		}
		if err != nil {
			return err
		}
		if owner.ProtocolType != "WEBSOCKET" {
			return apigatewayexec.ErrUnknownAPI
		}
		if owner.Disabled {
			return failure("ForbiddenException", "Forbidden", 403)
		}
		selected, err := r.Stage(ResourceKey{owner.Key, stage})
		if errors.Is(err, ErrNotFound) {
			return failure("ForbiddenException", "Forbidden", 403)
		}
		if err != nil {
			return err
		}
		out = &apigatewayexec.Route{Partition: owner.Key.Partition, AccountID: owner.Key.AccountID, Region: owner.Key.Region, APIID: owner.Key.ID, APIName: owner.Name, Stage: stage, DeploymentID: selected.DeploymentID, StageVariables: selected.Variables, RouteKey: routeKey, ProtocolType: owner.ProtocolType}
		if routeKey == "POST /@connections/{connectionId}" || routeKey == "GET /@connections/{connectionId}" || routeKey == "DELETE /@connections/{connectionId}" {
			out.DetailedMetricsEnabled = selected.detailedMetrics(routeKey)
			out.Logging = selected.logging(routeKey)
			return nil
		}
		if selected.DeploymentID == "" {
			return failure("NotFoundException", "Not Found", 404)
		}
		deployment, err := r.Deployment(ResourceKey{owner.Key, selected.DeploymentID})
		if errors.Is(err, ErrNotFound) {
			return failure("NotFoundException", "Not Found", 404)
		}
		if err != nil {
			return err
		}
		message := routeKey == ""
		if message {
			routeKey, err = selectWebSocketRoute(deployment.RouteSelectionExpression, body)
			if err != nil {
				return err
			}
		} else if routeKey != "$connect" && routeKey != "$disconnect" {
			return bad("WebSocket events must be $connect, $disconnect or MESSAGE")
		}
		rows, err := r.DeployedRoutes(deployment.Key)
		if err != nil {
			return err
		}
		var best, fallback *DeployedRoute
		for i := range rows {
			row := &rows[i]
			if message && (row.RouteKey == "$connect" || row.RouteKey == "$disconnect") {
				continue
			}
			if row.RouteKey == routeKey {
				best = row
				break
			}
			if message && row.RouteKey == "$default" {
				fallback = row
			}
		}
		if best == nil {
			best = fallback
		}
		out.RouteKey = routeKey
		if best != nil {
			out.ResourceID = best.RouteID
			out.RouteKey = best.RouteKey
			out.FunctionARN = best.FunctionARN
			out.PayloadVersion = best.PayloadVersion
			out.AuthorizationType = best.AuthorizationType
			out.LambdaAuthorizer = best.LambdaAuthorizer
			out.WebSocketResponseEnabled = best.WebSocketResponseEnabled
			out.IntegrationTimeoutMillis = best.TimeoutMillis
			out.IntegrationCredentialsARN = best.CredentialsARN
		}
		out.DetailedMetricsEnabled = selected.detailedMetrics(out.RouteKey)
		out.Logging = selected.logging(out.RouteKey)
		return nil
	})
	return out, err
}

// The rank is lexicographic by path specificity, then exact method over ANY.
// A nongreedy complete match wins over every greedy match and $default.
func matchRoute(key, method, path string) (map[string]string, string, string, bool) {
	if key == "$default" {
		return map[string]string{}, "0", "$default", true
	}
	verb, pattern, _ := strings.Cut(key, " ")
	if verb != method && verb != "ANY" {
		return nil, "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	values := strings.Split(strings.TrimPrefix(path, "/"), "/")
	params := map[string]string{}
	rank := "2"
	specificity := ""
	greedy := false
	for i, p := range parts {
		if i >= len(values) {
			return nil, "", "", false
		}
		if strings.HasPrefix(p, "{") {
			name := strings.TrimSuffix(strings.TrimPrefix(p, "{"), "}")
			if strings.HasSuffix(name, "+") {
				if values[i] == "" {
					return nil, "", "", false
				}
				params[strings.TrimSuffix(name, "+")] = strings.Join(values[i:], "/")
				rank = "1"
				specificity += "0"
				greedy = true
				break
			}
			if values[i] == "" {
				return nil, "", "", false
			}
			params[name] = values[i]
			specificity += "1"
		} else {
			if p != values[i] {
				return nil, "", "", false
			}
			specificity += "2"
		}
	}
	if !greedy && len(parts) != len(values) {
		return nil, "", "", false
	}
	exact := "0"
	if verb == method {
		exact = "1"
	}
	return params, rank + specificity + "/" + exact, pattern, true
}
