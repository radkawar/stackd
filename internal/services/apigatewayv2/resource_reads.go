package apigatewayv2

import (
	api "stackd/internal/awsapi/apigatewayv2"
)

func (s *Service) getIntegration(tx Transaction, in *api.GetIntegrationInput) (*api.GetIntegrationOutput, error) {
	owner, err := s.ownedAPI(tx, "GET", value(in.ApiId), "/integrations/"+value(in.IntegrationId))
	if err != nil {
		return nil, err
	}
	v, err := tx.Integration(ResourceKey{owner.Key, value(in.IntegrationId)})
	if err != nil {
		return nil, err
	}
	return new(api.GetIntegrationOutput(integrationOutput(v))), nil
}
func (s *Service) getIntegrations(tx Transaction, in *api.GetIntegrationsInput) (*api.GetIntegrationsOutput, error) {
	owner, err := s.ownedAPI(tx, "GET", value(in.ApiId), "/integrations")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Integrations(owner.Key)
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, value(in.MaxResults), value(in.NextToken), pageBinding(tx, "/apis/"+owner.Key.ID+"/integrations"), func(v IntegrationRecord) string { return v.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.GetIntegrationsOutput{}
	for _, v := range rows {
		out.Items = append(out.Items, integrationOutput(v))
	}
	if out.Items == nil {
		out.Items = []api.Integration{}
	}
	if next != nil {
		text(&out.NextToken, *next)
	}
	return out, nil
}

func (s *Service) deleteIntegration(tx Transaction, in *api.DeleteIntegrationInput) (*api.DeleteIntegrationOutput, error) {
	owner, err := s.ownedAPI(tx, "DELETE", value(in.ApiId), "/integrations/"+value(in.IntegrationId))
	if err != nil {
		return nil, err
	}
	key := ResourceKey{owner.Key, value(in.IntegrationId)}
	if _, err := tx.Integration(key); err != nil {
		return nil, err
	}

	if err := tx.DeleteIntegration(key); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, owner.Key); err != nil {
		return nil, err
	}
	return &api.DeleteIntegrationOutput{}, nil
}

func (s *Service) getAuthorizer(tx Transaction, in *api.GetAuthorizerInput) (*api.GetAuthorizerOutput, error) {
	owner, err := s.ownedAPI(tx, "GET", value(in.ApiId), "/authorizers/"+value(in.AuthorizerId))
	if err != nil {
		return nil, err
	}
	v, err := tx.Authorizer(ResourceKey{owner.Key, value(in.AuthorizerId)})
	if err != nil {
		return nil, err
	}
	return new(api.GetAuthorizerOutput(authorizerOutput(v, owner.ProtocolType))), nil
}
func (s *Service) getAuthorizers(tx Transaction, in *api.GetAuthorizersInput) (*api.GetAuthorizersOutput, error) {
	owner, err := s.ownedAPI(tx, "GET", value(in.ApiId), "/authorizers")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Authorizers(owner.Key)
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, value(in.MaxResults), value(in.NextToken), pageBinding(tx, "/apis/"+owner.Key.ID+"/authorizers"), func(v AuthorizerRecord) string { return v.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.GetAuthorizersOutput{}
	for _, v := range rows {
		out.Items = append(out.Items, authorizerOutput(v, owner.ProtocolType))
	}
	if out.Items == nil {
		out.Items = []api.Authorizer{}
	}
	if next != nil {
		text(&out.NextToken, *next)
	}
	return out, nil
}

func (s *Service) deleteAuthorizer(tx Transaction, in *api.DeleteAuthorizerInput) (*api.DeleteAuthorizerOutput, error) {
	owner, err := s.ownedAPI(tx, "DELETE", value(in.ApiId), "/authorizers/"+value(in.AuthorizerId))
	if err != nil {
		return nil, err
	}
	key := ResourceKey{owner.Key, value(in.AuthorizerId)}
	authorizer, err := tx.Authorizer(key)
	if err != nil {
		return nil, err
	}
	routes, err := tx.Routes(owner.Key)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if route.AuthorizerID == key.ID {
			if owner.ProtocolType == "WEBSOCKET" {
				return nil, failure("ConflictException", "Cannot delete authorizer '"+authorizer.Name+"', is referenced in route: "+route.RouteKey, 409)
			}
			return nil, bad("The authorizer is in use by a route")
		}
	}
	if err := tx.DeleteAuthorizer(key); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, owner.Key); err != nil {
		return nil, err
	}
	return &api.DeleteAuthorizerOutput{}, nil
}

func (s *Service) getRoute(tx Transaction, in *api.GetRouteInput) (*api.GetRouteOutput, error) {
	owner, err := s.ownedAPI(tx, "GET", value(in.ApiId), "/routes/"+value(in.RouteId))
	if err != nil {
		return nil, err
	}
	v, err := tx.Route(ResourceKey{owner.Key, value(in.RouteId)})
	if err != nil {
		return nil, err
	}
	return new(api.GetRouteOutput(routeOutput(v))), nil
}
func (s *Service) getRoutes(tx Transaction, in *api.GetRoutesInput) (*api.GetRoutesOutput, error) {
	owner, err := s.ownedAPI(tx, "GET", value(in.ApiId), "/routes")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Routes(owner.Key)
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, value(in.MaxResults), value(in.NextToken), pageBinding(tx, "/apis/"+owner.Key.ID+"/routes"), func(v RouteRecord) string { return v.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.GetRoutesOutput{}
	for _, v := range rows {
		out.Items = append(out.Items, routeOutput(v))
	}
	if out.Items == nil {
		out.Items = []api.Route{}
	}
	if next != nil {
		text(&out.NextToken, *next)
	}
	return out, nil
}

func (s *Service) deleteRoute(tx Transaction, in *api.DeleteRouteInput) (*api.DeleteRouteOutput, error) {
	owner, err := s.ownedAPI(tx, "DELETE", value(in.ApiId), "/routes/"+value(in.RouteId))
	if err != nil {
		return nil, err
	}
	key := ResourceKey{owner.Key, value(in.RouteId)}
	if _, err := tx.Route(key); err != nil {
		return nil, err
	}

	if err := tx.DeleteRoute(key); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, owner.Key); err != nil {
		return nil, err
	}
	return &api.DeleteRouteOutput{}, nil
}

func (s *Service) getStage(tx Transaction, in *api.GetStageInput) (*api.GetStageOutput, error) {
	owner, err := s.ownedAPI(tx, "GET", value(in.ApiId), "/stages/"+value(in.StageName))
	if err != nil {
		return nil, err
	}
	v, err := tx.Stage(ResourceKey{owner.Key, value(in.StageName)})
	if err != nil {
		return nil, err
	}
	return new(api.GetStageOutput(stageOutput(v, owner.ProtocolType))), nil
}
func (s *Service) getStages(tx Transaction, in *api.GetStagesInput) (*api.GetStagesOutput, error) {
	owner, err := s.ownedAPI(tx, "GET", value(in.ApiId), "/stages")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Stages(owner.Key)
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, value(in.MaxResults), value(in.NextToken), pageBinding(tx, "/apis/"+owner.Key.ID+"/stages"), func(v StageRecord) string { return v.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.GetStagesOutput{}
	for _, v := range rows {
		out.Items = append(out.Items, stageOutput(v, owner.ProtocolType))
	}
	if out.Items == nil {
		out.Items = []api.Stage{}
	}
	if next != nil {
		text(&out.NextToken, *next)
	}
	return out, nil
}

func (s *Service) deleteStage(tx Transaction, in *api.DeleteStageInput) (*api.DeleteStageOutput, error) {
	owner, err := s.ownedAPI(tx, "DELETE", value(in.ApiId), "/stages/"+value(in.StageName))
	if err != nil {
		return nil, err
	}
	key := ResourceKey{owner.Key, value(in.StageName)}
	if _, err := tx.Stage(key); err != nil {
		return nil, err
	}

	if err := tx.DeleteStage(key); err != nil {
		return nil, err
	}
	return &api.DeleteStageOutput{}, nil
}

func (s *Service) getDeployment(tx Transaction, in *api.GetDeploymentInput) (*api.GetDeploymentOutput, error) {
	owner, err := s.ownedAPI(tx, "GET", value(in.ApiId), "/deployments/"+value(in.DeploymentId))
	if err != nil {
		return nil, err
	}
	v, err := tx.Deployment(ResourceKey{owner.Key, value(in.DeploymentId)})
	if err != nil {
		return nil, err
	}
	return new(api.GetDeploymentOutput(deploymentOutput(v))), nil
}
func (s *Service) getDeployments(tx Transaction, in *api.GetDeploymentsInput) (*api.GetDeploymentsOutput, error) {
	owner, err := s.ownedAPI(tx, "GET", value(in.ApiId), "/deployments")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Deployments(owner.Key)
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, value(in.MaxResults), value(in.NextToken), pageBinding(tx, "/apis/"+owner.Key.ID+"/deployments"), func(v DeploymentRecord) string { return v.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.GetDeploymentsOutput{}
	for _, v := range rows {
		out.Items = append(out.Items, deploymentOutput(v))
	}
	if out.Items == nil {
		out.Items = []api.Deployment{}
	}
	if next != nil {
		text(&out.NextToken, *next)
	}
	return out, nil
}
