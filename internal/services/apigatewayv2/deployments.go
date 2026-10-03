package apigatewayv2

import (
	"errors"
	api "stackd/internal/awsapi/apigatewayv2"
	"stackd/internal/awswire"
)

func deploymentOutput(v DeploymentRecord) api.Deployment {
	out := api.Deployment{CreatedDate: new(v.Created)}
	text(&out.DeploymentId, v.Key.ID)
	text(&out.DeploymentStatus, "DEPLOYED")
	flag(&out.AutoDeployed, v.AutoDeployed)
	if v.Description != "" {
		text(&out.Description, v.Description)
	}
	return out
}
func deploymentRoutes(r Reader, key APIKey) ([]DeployedRoute, error) {
	owner, err := r.API(key)
	if err != nil {
		return nil, err
	}
	routes, err := r.Routes(key)
	if err != nil {
		return nil, err
	}
	out := make([]DeployedRoute, 0, len(routes))
	for _, route := range routes {
		integration, err := r.Integration(ResourceKey{key, route.Target})
		if errors.Is(err, ErrNotFound) {
			return nil, bad("Unable to deploy: a route has no valid integration")
		}
		if err != nil {
			return nil, err
		}
		v := DeployedRoute{RouteID: route.Key.ID, RouteKey: route.RouteKey, FunctionARN: integration.URI, PayloadVersion: integration.PayloadVersion, AuthorizationType: route.AuthorizationType, Scopes: route.Scopes}
		v.TimeoutMillis = integration.TimeoutMillis
		v.CredentialsARN = integration.CredentialsARN
		if owner.ProtocolType == "WEBSOCKET" {
			v.FunctionARN, err = authorizerFunctionARN(integration.URI)
			if err != nil {
				return nil, bad("Unable to deploy: invalid WebSocket Lambda integration URI")
			}
			responses, err := r.RouteResponses(route.Key)
			if err != nil {
				return nil, err
			}
			for _, response := range responses {
				if response.ResponseKey == "$default" {
					v.WebSocketResponseEnabled = true
					break
				}
			}
		}
		if route.AuthorizationType == "JWT" || route.AuthorizationType == "CUSTOM" {
			auth, err := r.Authorizer(ResourceKey{key, route.AuthorizerID})
			if errors.Is(err, ErrNotFound) {
				return nil, bad("Unable to deploy: a route has no valid authorizer")
			}
			if err != nil {
				return nil, err
			}
			if (route.AuthorizationType == "CUSTOM") != (auth.LambdaAuthorizer != nil) {
				return nil, bad("Unable to deploy: authorizer type does not match route authorization")
			}
			v.LambdaAuthorizer = auth.LambdaAuthorizer
			v.Issuer = auth.Issuer
			v.Audiences = auth.Audiences
		}
		out = append(out, v)
	}
	return out, nil
}
func (s *Service) saveDeployment(tx Transaction, key APIKey, description string, auto bool, rows []DeployedRoute) (DeploymentRecord, error) {
	id, err := controlID()
	if err != nil {
		return DeploymentRecord{}, err
	}
	v := DeploymentRecord{Key: ResourceKey{key, id}, Description: description, Created: s.clock.Now(), AutoDeployed: auto}
	owner, err := tx.API(key)
	if err != nil {
		return v, err
	}
	v.RouteSelectionExpression = owner.RouteSelectionExpression
	if err := tx.PutDeployment(v); err != nil {
		return v, err
	}
	for _, row := range rows {
		row.Key = v.Key
		if err := tx.PutDeployedRoute(row); err != nil {
			return v, err
		}
	}
	return v, nil
}
func (s *Service) autoDeploy(tx Transaction, key APIKey) error {
	stages, err := tx.Stages(key)
	if err != nil {
		return err
	}
	active := false
	for _, stage := range stages {
		active = active || stage.AutoDeploy
	}
	if !active {
		return nil
	}
	rows, err := deploymentRoutes(tx, key)
	if err != nil {
		var rejected *awswire.Error
		if !errors.As(err, &rejected) || rejected.Code != "BadRequestException" {
			return err
		}
		// Failed automatic deployment retains the last successful immutable deployment,
		// while reporting the actual failure on every affected automatically managed stage.
		for _, stage := range stages {
			if stage.AutoDeploy {
				stage.LastDeploymentStatusMessage = rejected.Message
				stage.Updated = s.clock.Now()
				if err := tx.PutStage(stage); err != nil {
					return err
				}
			}
		}
		return nil
	}
	deployment, err := s.saveDeployment(tx, key, "", true, rows)
	if err != nil {
		return err
	}
	for _, stage := range stages {
		if stage.AutoDeploy {
			stage.DeploymentID = deployment.Key.ID
			stage.LastDeploymentStatusMessage = ""
			stage.Updated = s.clock.Now()
			if err := tx.PutStage(stage); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) createDeployment(tx Transaction, in *api.CreateDeploymentInput) (*api.CreateDeploymentOutput, error) {
	owner, err := s.ownedAPI(tx, "POST", value(in.ApiId), "/deployments")
	if err != nil {
		return nil, err
	}
	var stage *StageRecord
	if in.StageName != nil {
		v, err := tx.Stage(ResourceKey{owner.Key, value(in.StageName)})
		if err != nil {
			return nil, err
		}
		if v.AutoDeploy {
			return nil, bad("DeploymentId cannot be set on an automatically deployed stage")
		}
		stage = &v
	}
	rows, err := deploymentRoutes(tx, owner.Key)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, bad("Unable to deploy an API with no routes")
	}
	v, err := s.saveDeployment(tx, owner.Key, value(in.Description), false, rows)
	if err != nil {
		return nil, err
	}
	if stage != nil {
		stage.DeploymentID = v.Key.ID
		stage.Updated = s.clock.Now()
		stage.LastDeploymentStatusMessage = ""
		if err := tx.PutStage(*stage); err != nil {
			return nil, err
		}
	}
	return new(api.CreateDeploymentOutput(deploymentOutput(v))), nil
}
func (s *Service) updateDeployment(tx Transaction, in *api.UpdateDeploymentInput) (*api.UpdateDeploymentOutput, error) {
	owner, err := s.ownedAPI(tx, "PATCH", value(in.ApiId), "/deployments/"+value(in.DeploymentId))
	if err != nil {
		return nil, err
	}
	v, err := tx.Deployment(ResourceKey{owner.Key, value(in.DeploymentId)})
	if err != nil {
		return nil, err
	}
	if in.Description != nil {
		v.Description = value(in.Description)
	}
	if err := tx.PutDeployment(v); err != nil {
		return nil, err
	}
	return new(api.UpdateDeploymentOutput(deploymentOutput(v))), nil
}
func (s *Service) deleteDeployment(tx Transaction, in *api.DeleteDeploymentInput) (*api.DeleteDeploymentOutput, error) {
	owner, err := s.ownedAPI(tx, "DELETE", value(in.ApiId), "/deployments/"+value(in.DeploymentId))
	if err != nil {
		return nil, err
	}
	key := ResourceKey{owner.Key, value(in.DeploymentId)}
	if _, err := tx.Deployment(key); err != nil {
		return nil, err
	}
	stages, err := tx.Stages(owner.Key)
	if err != nil {
		return nil, err
	}
	for _, stage := range stages {
		if stage.DeploymentID == key.ID {
			return nil, bad("A deployment referenced by a stage cannot be deleted")
		}
	}
	if err := tx.DeleteDeployment(key); err != nil {
		return nil, err
	}
	return &api.DeleteDeploymentOutput{}, nil
}
