package apigatewayv2

import (
	"errors"
	"regexp"
	api "stackd/internal/awsapi/apigatewayv2"
	"strings"
)

var routePart = regexp.MustCompile(`^(\{[\w.:-]+\+?\}|[a-zA-Z0-9.:_-]+)$`)

func routeOutput(v RouteRecord) api.Route {
	out := api.Route{}
	text(&out.RouteId, v.Key.ID)
	text(&out.RouteKey, v.RouteKey)
	text(&out.AuthorizationType, v.AuthorizationType)
	flag(&out.ApiKeyRequired, false)
	if v.Target != "" {
		text(&out.Target, "integrations/"+v.Target)
	}
	if v.AuthorizerID != "" {
		text(&out.AuthorizerId, v.AuthorizerID)
	}
	if v.OperationName != "" {
		text(&out.OperationName, v.OperationName)
	}
	if len(v.Scopes) > 0 {
		stringList(&out.AuthorizationScopes, v.Scopes)
	}
	if v.RouteResponseSelectionExpression != "" {
		text(&out.RouteResponseSelectionExpression, v.RouteResponseSelectionExpression)
	}
	return out
}
func routePattern(key string) (string, error) {
	if key == "$default" {
		return key, nil
	}
	method, path, ok := strings.Cut(key, " ")
	if !ok || !strings.HasPrefix(path, "/") || !strings.Contains(" GET POST PUT PATCH DELETE HEAD OPTIONS ANY ", " "+method+" ") {
		return "", bad("RouteKey must be $default or an HTTP method and path")
	}
	if path == "/" {
		return key, nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	names := map[string]bool{}
	for i, p := range parts {
		if !routePart.MatchString(p) {
			return "", bad("One or more path parts appear to be invalid. Parts are validated against this regular expression: ^(\\{[\\w.:-]+\\+?\\}|[a-zA-Z0-9.:_-]+)$")
		}
		if strings.HasPrefix(p, "{") {
			name := strings.TrimSuffix(strings.TrimPrefix(p, "{"), "}")
			greedy := strings.HasSuffix(name, "+")
			name = strings.TrimSuffix(name, "+")
			if names[name] {
				return "", bad("Path parameter names must be unique")
			}
			names[name] = true
			if greedy && i != len(parts)-1 {
				return "", bad("A greedy path parameter must be the last path part")
			}
			parts[i] = "{}"
			if greedy {
				parts[i] = "{+}"
			}
		}
	}
	return method + " /" + strings.Join(parts, "/"), nil
}
func validateRouteInput(in *api.CreateRouteInput, protocol string) error {
	// TODO: Comeback implement API keys and request model/parameter admission.
	if boolean(in.ApiKeyRequired) || in.ModelSelectionExpression != nil || len(in.RequestModels) > 0 || len(in.RequestParameters) > 0 {
		return unsupported("API keys, request models and request parameters are not implemented")
	}
	if in.RouteResponseSelectionExpression != nil {
		if protocol != "WEBSOCKET" {
			return bad("Route response selection is only supported for WebSocket APIs")
		}
		if value(in.RouteResponseSelectionExpression) != "$default" {
			return bad("RouteResponseSelectionExpression must be $default")
		}
	}
	return nil
}
func routeKeyPattern(key, protocol string) (string, error) {
	if protocol != "WEBSOCKET" {
		return routePattern(key)
	}
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "\r\n\t") {
		return "", bad("Invalid WebSocket route key")
	}
	if strings.HasPrefix(key, "$") && key != "$connect" && key != "$disconnect" && key != "$default" {
		return "", bad("The $ prefix is reserved for $connect, $disconnect and $default routes")
	}
	return key, nil
}
func validateRoute(r Reader, v RouteRecord, protocol string) error {
	pattern, err := routeKeyPattern(v.RouteKey, protocol)
	if err != nil {
		return err
	}
	rows, err := r.Routes(v.Key.APIKey)
	if err != nil {
		return err
	}
	for _, row := range rows {
		p, _ := routeKeyPattern(row.RouteKey, protocol)
		if row.Key.ID != v.Key.ID && p == pattern {
			return failure("ConflictException", "A route with this method and path already exists", 409)
		}
	}
	if v.Target != "" {
		if _, err := r.Integration(ResourceKey{v.Key.APIKey, v.Target}); errors.Is(err, ErrNotFound) {
			return bad("Invalid integration target")
		} else if err != nil {
			return err
		}
	}
	if protocol == "WEBSOCKET" {
		if v.AuthorizationType != "NONE" && v.AuthorizationType != "AWS_IAM" && v.AuthorizationType != "CUSTOM" {
			return bad("WebSocket routes support NONE, AWS_IAM or CUSTOM authorization")
		}
		if v.AuthorizationType != "NONE" && v.RouteKey != "$connect" {
			return bad("Currently, authorization is restricted to the $connect route only")
		}
	}
	switch v.AuthorizationType {
	case "NONE", "AWS_IAM":
		if v.AuthorizerID != "" || len(v.Scopes) > 0 {
			return bad("AuthorizerId requires JWT or CUSTOM authorization; authorization scopes require JWT authorization")
		}
	case "JWT", "CUSTOM":
		if v.AuthorizerID == "" {
			return bad(v.AuthorizationType + " routes require an authorizer")
		}
		auth, err := r.Authorizer(ResourceKey{v.Key.APIKey, v.AuthorizerID})
		if errors.Is(err, ErrNotFound) {
			return bad("Invalid authorizer")
		}
		if err != nil {
			return err
		}
		if (v.AuthorizationType == "CUSTOM") != (auth.LambdaAuthorizer != nil) {
			return bad("Authorizer type must match route authorization type")
		}
		if protocol == "WEBSOCKET" && auth.LambdaAuthorizer.Type != "REQUEST" {
			return bad("WebSocket CUSTOM routes require a REQUEST authorizer")
		}
		if v.AuthorizationType == "CUSTOM" && len(v.Scopes) > 0 {
			return bad("Authorization scopes require JWT authorization")
		}
	default:
		return unsupported("Only NONE, AWS_IAM, JWT and CUSTOM route authorization are implemented")
	}
	return nil
}
func routeTarget(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	target, ok := strings.CutPrefix(v, "integrations/")
	if !ok || target == "" || strings.Contains(target, "/") {
		return "", bad("Target must identify an integration")
	}
	return target, nil
}
func (s *Service) createRoute(tx Transaction, in *api.CreateRouteInput) (*api.CreateRouteOutput, error) {
	owner, err := s.ownedAPI(tx, "POST", value(in.ApiId), "/routes")
	if err != nil {
		return nil, err
	}
	if err := validateRouteInput(in, owner.ProtocolType); err != nil {
		return nil, err
	}
	target, err := routeTarget(value(in.Target))
	if err != nil {
		return nil, err
	}
	if v, found, err := recoverOwnedResource(tx, owner.Key, tx.Routes); err != nil {
		return nil, err
	} else if found {
		return new(api.CreateRouteOutput(routeOutput(v))), nil
	}
	id, err := controlID()
	if err != nil {
		return nil, err
	}
	v := RouteRecord{Key: ResourceKey{owner.Key, id}, RouteKey: value(in.RouteKey), Target: target, AuthorizationType: value(in.AuthorizationType), AuthorizerID: value(in.AuthorizerId), OperationName: value(in.OperationName), Scopes: stringsOf(in.AuthorizationScopes)}
	v.RouteResponseSelectionExpression = value(in.RouteResponseSelectionExpression)
	if v.AuthorizationType == "" {
		v.AuthorizationType = "NONE"
	}
	if err := validateRoute(tx, v, owner.ProtocolType); err != nil {
		return nil, err
	}
	if err := tx.PutRoute(v); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, owner.Key); err != nil {
		return nil, err
	}
	return new(api.CreateRouteOutput(routeOutput(v))), nil
}
func (s *Service) updateRoute(tx Transaction, in *api.UpdateRouteInput) (*api.UpdateRouteOutput, error) {
	owner, err := s.ownedAPI(tx, "PATCH", value(in.ApiId), "/routes/"+value(in.RouteId))
	if err != nil {
		return nil, err
	}
	v, err := tx.Route(ResourceKey{owner.Key, value(in.RouteId)})
	if err != nil {
		return nil, err
	}
	if err := validateRouteInput(&api.CreateRouteInput{ApiKeyRequired: in.ApiKeyRequired, ModelSelectionExpression: in.ModelSelectionExpression, RequestModels: in.RequestModels, RequestParameters: in.RequestParameters, RouteResponseSelectionExpression: in.RouteResponseSelectionExpression}, owner.ProtocolType); err != nil {
		return nil, err
	}
	if in.RouteKey != nil {
		v.RouteKey = value(in.RouteKey)
	}
	if in.Target != nil {
		v.Target, err = routeTarget(value(in.Target))
		if err != nil {
			return nil, err
		}
	}
	if in.AuthorizationType != nil {
		v.AuthorizationType = value(in.AuthorizationType)
		if v.AuthorizationType != "JWT" && v.AuthorizationType != "CUSTOM" {
			v.AuthorizerID = ""
			v.Scopes = nil
		}
	}
	if in.AuthorizerId != nil {
		v.AuthorizerID = value(in.AuthorizerId)
	}
	if in.AuthorizationScopes != nil {
		v.Scopes = stringsOf(in.AuthorizationScopes)
	}
	if in.OperationName != nil {
		v.OperationName = value(in.OperationName)
	}
	if in.RouteResponseSelectionExpression != nil {
		v.RouteResponseSelectionExpression = value(in.RouteResponseSelectionExpression)
	}
	if err := validateRoute(tx, v, owner.ProtocolType); err != nil {
		return nil, err
	}
	if err := tx.PutRoute(v); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, owner.Key); err != nil {
		return nil, err
	}
	return new(api.UpdateRouteOutput(routeOutput(v))), nil
}
