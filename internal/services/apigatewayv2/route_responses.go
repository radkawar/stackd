package apigatewayv2

import api "stackd/internal/awsapi/apigatewayv2"

func routeResponseOutput(v RouteResponseRecord) api.RouteResponse {
	out := api.RouteResponse{}
	text(&out.RouteResponseId, v.Key.ID)
	text(&out.RouteResponseKey, v.ResponseKey)
	return out
}

func validateRouteResponse(in *api.CreateRouteResponseInput) error {
	if value(in.RouteResponseKey) != "$default" {
		return bad("RouteResponseKey must be $default")
	}
	// TODO: Comeback implement route response models and parameter mappings.
	if in.ModelSelectionExpression != nil || len(in.ResponseModels) > 0 || len(in.ResponseParameters) > 0 {
		return unsupported("Route response models, model selection and parameter mappings are not implemented")
	}
	return nil
}

func (s *Service) routeResponseParent(tx Transaction, method, apiID, routeID, responseID string) (RouteRecord, error) {
	path := "/routes/" + routeID + "/routeresponses"
	if responseID != "" {
		path += "/" + responseID
	}
	owner, err := s.ownedAPI(tx, method, apiID, path)
	if err != nil {
		return RouteRecord{}, err
	}
	if owner.ProtocolType != "WEBSOCKET" {
		return RouteRecord{}, bad("Route responses are only supported for WebSocket APIs")
	}
	return tx.Route(ResourceKey{owner.Key, routeID})
}

func readRouteResponse(r Reader, route ResourceKey, id string) (RouteResponseRecord, error) {
	v, err := r.RouteResponse(ResourceKey{route.APIKey, id})
	if err != nil {
		return RouteResponseRecord{}, err
	}
	if v.RouteID != route.ID {
		return RouteResponseRecord{}, ErrNotFound
	}
	return v, nil
}

func (s *Service) createRouteResponse(tx Transaction, in *api.CreateRouteResponseInput) (*api.CreateRouteResponseOutput, error) {
	route, err := s.routeResponseParent(tx, "POST", value(in.ApiId), value(in.RouteId), "")
	if err != nil {
		return nil, err
	}
	if err := validateRouteResponse(in); err != nil {
		return nil, err
	}
	rows, err := tx.RouteResponses(route.Key)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.ResponseKey == value(in.RouteResponseKey) {
			return nil, failure("ConflictException", "A route response with this key already exists", 409)
		}
	}
	id, err := controlID()
	if err != nil {
		return nil, err
	}
	v := RouteResponseRecord{Key: ResourceKey{route.Key.APIKey, id}, RouteID: route.Key.ID, ResponseKey: value(in.RouteResponseKey)}
	if err := tx.PutRouteResponse(v); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, route.Key.APIKey); err != nil {
		return nil, err
	}
	return new(api.CreateRouteResponseOutput(routeResponseOutput(v))), nil
}

func (s *Service) getRouteResponse(tx Transaction, in *api.GetRouteResponseInput) (*api.GetRouteResponseOutput, error) {
	route, err := s.routeResponseParent(tx, "GET", value(in.ApiId), value(in.RouteId), value(in.RouteResponseId))
	if err != nil {
		return nil, err
	}
	v, err := readRouteResponse(tx, route.Key, value(in.RouteResponseId))
	if err != nil {
		return nil, err
	}
	return new(api.GetRouteResponseOutput(routeResponseOutput(v))), nil
}

func (s *Service) getRouteResponses(tx Transaction, in *api.GetRouteResponsesInput) (*api.GetRouteResponsesOutput, error) {
	route, err := s.routeResponseParent(tx, "GET", value(in.ApiId), value(in.RouteId), "")
	if err != nil {
		return nil, err
	}
	rows, err := tx.RouteResponses(route.Key)
	if err != nil {
		return nil, err
	}
	binding := pageBinding(tx, "/apis/"+route.Key.APIKey.ID+"/routes/"+route.Key.ID+"/routeresponses")
	rows, next, err := page(rows, value(in.MaxResults), value(in.NextToken), binding, func(v RouteResponseRecord) string { return v.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.GetRouteResponsesOutput{}
	for _, v := range rows {
		out.Items = append(out.Items, routeResponseOutput(v))
	}
	if out.Items == nil {
		out.Items = []api.RouteResponse{}
	}
	if next != nil {
		text(&out.NextToken, *next)
	}
	return out, nil
}

func (s *Service) updateRouteResponse(tx Transaction, in *api.UpdateRouteResponseInput) (*api.UpdateRouteResponseOutput, error) {
	route, err := s.routeResponseParent(tx, "PATCH", value(in.ApiId), value(in.RouteId), value(in.RouteResponseId))
	if err != nil {
		return nil, err
	}
	v, err := readRouteResponse(tx, route.Key, value(in.RouteResponseId))
	if err != nil {
		return nil, err
	}
	check := api.CreateRouteResponseInput{RouteResponseKey: new(api.SelectionKey(v.ResponseKey)), ModelSelectionExpression: in.ModelSelectionExpression, ResponseModels: in.ResponseModels, ResponseParameters: in.ResponseParameters}
	if in.RouteResponseKey != nil {
		check.RouteResponseKey = in.RouteResponseKey
	}
	if err := validateRouteResponse(&check); err != nil {
		return nil, err
	}
	v.ResponseKey = value(check.RouteResponseKey)
	if err := tx.PutRouteResponse(v); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, route.Key.APIKey); err != nil {
		return nil, err
	}
	return new(api.UpdateRouteResponseOutput(routeResponseOutput(v))), nil
}

func (s *Service) deleteRouteResponse(tx Transaction, in *api.DeleteRouteResponseInput) (*api.DeleteRouteResponseOutput, error) {
	route, err := s.routeResponseParent(tx, "DELETE", value(in.ApiId), value(in.RouteId), value(in.RouteResponseId))
	if err != nil {
		return nil, err
	}
	v, err := readRouteResponse(tx, route.Key, value(in.RouteResponseId))
	if err != nil {
		return nil, err
	}
	if err := tx.DeleteRouteResponse(v.Key); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, route.Key.APIKey); err != nil {
		return nil, err
	}
	return &api.DeleteRouteResponseOutput{}, nil
}
