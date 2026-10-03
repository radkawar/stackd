package apigateway

import (
	"context"
	"errors"
	"stackd/internal/services/apigatewayexec"
	"strings"
)

// Resolve selects a retained owner, stage and immutable deployed path. An empty
// stage consumes the first URL segment; an explicit stage uses a relative path.
func (s *Service) Resolve(ctx context.Context, apiID, stage, method, path string) (*apigatewayexec.Route, error) {
	var out *apigatewayexec.Route
	err := s.repository.View(ctx, func(r Reader) error {
		owner, err := r.Owner(apiID)
		if errors.Is(err, ErrNotFound) {
			return apigatewayexec.ErrUnknownAPI
		}
		if err != nil {
			return err
		}
		missing := func() error {
			return failure("MissingAuthenticationTokenException", "Missing Authentication Token", 403)
		}
		if owner.EffectiveDisabled {
			return failure("ForbiddenException", "Forbidden", 403)
		}
		if stage == "" {
			first, rest, ok := strings.Cut(strings.TrimPrefix(path, "/"), "/")
			stage = first
			path = "/"
			if ok {
				path += rest
			}
		}
		if stage == "" {
			return missing()
		}
		if path == "" {
			path = "/"
		}
		selected, err := r.Stage(StageKey{APIKey: owner.Key, Name: stage})
		if errors.Is(err, ErrNotFound) {
			return missing()
		}
		if err != nil {
			return err
		}
		deployment, err := r.Deployment(DeploymentKey{APIKey: owner.Key, DeploymentID: selected.DeploymentID})
		if errors.Is(err, ErrNotFound) {
			return missing()
		}
		if err != nil {
			return err
		}
		// First select the most specific resource, independent of method availability:
		// an absent method on a literal resource must not fall through to a greedy one.
		bestPath, parameters, ok := selectResource(deployment.Resources, path)
		if !ok {
			return missing()
		}
		var exact, fallback *DeploymentRoute
		for i := range deployment.Routes {
			route := &deployment.Routes[i]
			if route.Path != bestPath {
				continue
			}
			if route.HTTPMethod == method {
				exact = route
			}
			if route.HTTPMethod == "ANY" {
				fallback = route
			}
		}
		if exact == nil {
			exact = fallback
		}
		if exact == nil {
			return missing()
		}
		out = &apigatewayexec.Route{Partition: owner.Key.Partition, AccountID: owner.Key.AccountID, Region: owner.Key.Region, APIID: apiID, APIName: owner.Name, Stage: stage, DeploymentID: deployment.Key.DeploymentID, ResourceID: exact.ResourceID, ResourcePath: exact.Path, RouteKey: exact.HTTPMethod + " " + exact.Path, FunctionARN: exact.FunctionARN, PayloadVersion: "1.0", AuthorizationType: exact.AuthorizationType, Scopes: exact.Scopes, UserPoolARNs: exact.UserPoolARNs, StageVariables: selected.Variables, PathParameters: parameters}
		out.ProtocolType = "REST"
		settings := effectiveMethodSettings(selected.MethodSettings, exact.Path, exact.HTTPMethod)
		out.DetailedMetricsEnabled = settings.MetricsEnabled
		out.Logging = apigatewayexec.LoggingSettings{Access: selected.AccessLogs, Level: settings.LoggingLevel, DataTrace: settings.DataTraceEnabled}
		out.LambdaAuthorizer = cloneLambdaAuthorizer(exact.LambdaAuthorizer)
		out.IntegrationCredentialsARN = exact.CredentialsARN
		out.APIKeyRequired, out.APIKeySource = exact.APIKeyRequired, deployment.APIKeySource
		return nil
	})
	return out, err
}
func selectResource(resources []DeploymentResource, path string) (string, map[string]string, bool) {
	if path == "/" {
		for _, resource := range resources {
			if resource.Path == "/" {
				return "/", nil, true
			}
		}
		return "", nil, false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	parent := "/"
	var parameters map[string]string
	for i, part := range parts {
		if part == "" {
			return "", nil, false
		}
		var literal, parameter, greedy *DeploymentResource
		for index := range resources {
			candidate := &resources[index]
			if candidate.Path == "/" {
				continue
			}
			slash := strings.LastIndexByte(candidate.Path, '/')
			candidateParent := candidate.Path[:slash]
			if candidateParent == "" {
				candidateParent = "/"
			}
			if candidateParent != parent {
				continue
			}
			name := candidate.Path[slash+1:]
			switch {
			case name == part:
				literal = candidate
			case variablePart(name) && strings.HasSuffix(name, "+}"):
				greedy = candidate
			case variablePart(name):
				parameter = candidate
			}
		}
		selected := literal
		if selected == nil {
			selected = parameter
		}
		if selected == nil {
			selected = greedy
		}
		if selected == nil {
			return "", nil, false
		}
		name := selected.Path[strings.LastIndexByte(selected.Path, '/')+1:]
		if variablePart(name) {
			if parameters == nil {
				parameters = map[string]string{}
			}
			key := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(name, "{"), "}"), "+")
			if selected == greedy {
				parameters[key] = strings.Join(parts[i:], "/")
				return selected.Path, parameters, true
			}
			parameters[key] = part
		}
		parent = selected.Path
	}
	return parent, parameters, true
}

var _ apigatewayexec.Resolver = (*Service)(nil)
