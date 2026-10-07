package apigateway

import (
	"errors"
	"regexp"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/services/apigatewayexec"
	"strings"
)

func deploymentOutput(v DeploymentRecord, embed bool) *api.Deployment {
	out := &api.Deployment{Id: ptr(v.Key.DeploymentID), Description: optional(v.Description), CreatedDate: new(v.Created)}
	if embed {
		out.ApiSummary = api.PathToMapOfMethodSnapshot{}
		for _, route := range v.Routes {
			path := api.String(route.Path)
			if out.ApiSummary[path] == nil {
				out.ApiSummary[path] = api.MapOfMethodSnapshot{}
			}
			out.ApiSummary[path][api.String(route.HTTPMethod)] = api.MethodSnapshot{AuthorizationType: ptr(route.AuthorizationType), ApiKeyRequired: new(api.Boolean(route.APIKeyRequired))}
		}
	}
	return out
}
func (s *Service) createDeployment(tx Transaction, in *api.CreateDeploymentRequest) (*api.Deployment, error) {
	owner, err := s.api(tx, value(in.RestApiId), "POST", "/deployments")
	if err != nil {
		return nil, err
	}
	// TODO: Comeback stage caches, canary traffic and X-Ray tracing;
	// none are accepted as inert configuration.
	if truth(in.CacheClusterEnabled) || in.CacheClusterSize != nil || in.CanarySettings != nil || truth(in.TracingEnabled) {
		return nil, unsupported("deployment caches, canaries or tracing")
	}
	if value(in.StageName) == "" && (value(in.StageDescription) != "" || len(in.Variables) > 0) {
		return nil, bad("Stage settings require a stage name")
	}
	var stage StageRecord
	stageMissing := false
	if value(in.StageName) != "" {
		if err := validStage(value(in.StageName), mapIn(in.Variables)); err != nil {
			return nil, err
		}
		stage, err = tx.Stage(StageKey{APIKey: owner.Key, Name: value(in.StageName)})
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		stageMissing = errors.Is(err, ErrNotFound)
	}
	methods, err := tx.Methods(owner.Key)
	if err != nil {
		return nil, err
	}
	if len(methods) == 0 {
		return nil, bad("The REST API doesn't contain any methods")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	row := DeploymentRecord{Key: DeploymentKey{APIKey: owner.Key, DeploymentID: id}, Description: value(in.Description), Created: s.clock.Now(), Routes: make([]DeploymentRoute, 0, len(methods))}
	row.APIKeySource = owner.APIKeySource
	resources, err := tx.Resources(owner.Key)
	if err != nil {
		return nil, err
	}
	row.Resources = make([]DeploymentResource, 0, len(resources))
	for _, resource := range resources {
		row.Resources = append(row.Resources, DeploymentResource{ResourceID: resource.Key.ResourceID, Path: resource.Path})
	}
	for _, m := range methods {
		integration, err := tx.Integration(m.Key)
		if errors.Is(err, ErrNotFound) {
			return nil, bad("No integration defined for method")
		}
		if err != nil {
			return nil, err
		}
		resource, err := tx.Resource(m.Key.ResourceKey)
		if err != nil {
			return nil, err
		}
		arn, err := functionARN(integration.URI, owner.Key.Scope)
		if err != nil {
			return nil, err
		}
		route := DeploymentRoute{ResourceID: resource.Key.ResourceID, Path: resource.Path, HTTPMethod: m.Key.HTTPMethod, AuthorizationType: m.AuthorizationType, Scopes: m.Scopes, FunctionARN: arn, TimeoutMillis: integration.TimeoutMillis}
		route.CredentialsARN = integration.CredentialsARN
		route.APIKeyRequired = m.APIKeyRequired
		if m.AuthorizationType == "COGNITO_USER_POOLS" || m.AuthorizationType == "CUSTOM" {
			a, err := tx.Authorizer(AuthorizerKey{APIKey: owner.Key, AuthorizerID: m.AuthorizerID})
			if err != nil {
				return nil, err
			}
			route.UserPoolARNs = a.ProviderARNs
			route.LambdaAuthorizer = cloneLambdaAuthorizer(a.LambdaAuthorizer)
		}
		row.Routes = append(row.Routes, route)
	}
	if err := tx.PutDeployment(row); err != nil {
		return nil, err
	}
	if name := value(in.StageName); name != "" {
		if stageMissing {
			incarnation, err := tx.NextStageIncarnation(owner.Key.Scope)
			if err != nil {
				return nil, err
			}
			stage = StageRecord{Key: StageKey{APIKey: owner.Key, Name: name}, Incarnation: incarnation, Created: row.Created, Variables: map[string]string{}, Tags: map[string]string{}}
		}
		stage.DeploymentID = id
		stage.Updated = row.Created
		if in.StageDescription != nil {
			stage.Description = value(in.StageDescription)
		}
		if in.Variables != nil {
			stage.Variables = mapIn(in.Variables)
		}
		if err := tx.PutStage(stage); err != nil {
			return nil, err
		}
		if err := activateEndpoint(tx, owner); err != nil {
			return nil, err
		}
	}
	return deploymentOutput(row, false), nil
}
func (s *Service) getDeployment(tx Transaction, in *api.GetDeploymentRequest) (*api.Deployment, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", "/deployments/"+value(in.DeploymentId))
	if err != nil {
		return nil, err
	}
	embed, err := validEmbed(in.Embed, "apisummary")
	if err != nil {
		return nil, err
	}
	row, err := tx.Deployment(DeploymentKey{APIKey: owner.Key, DeploymentID: value(in.DeploymentId)})
	if err != nil {
		return nil, err
	}
	return deploymentOutput(row, embed), nil
}
func (s *Service) getDeployments(tx Transaction, in *api.GetDeploymentsRequest) (*api.Deployments, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", "/deployments")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Deployments(owner.Key)
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, owner.Key.Scope, "deployments/"+owner.Key.ID, in.Limit, in.Position, func(v DeploymentRecord) string { return v.Key.DeploymentID })
	if err != nil {
		return nil, err
	}
	out := &api.Deployments{Items: api.ListOfDeployment{}, Position: next}
	for _, v := range rows {
		out.Items = append(out.Items, *deploymentOutput(v, false))
	}
	return out, nil
}
func (s *Service) updateDeployment(tx Transaction, in *api.UpdateDeploymentRequest) (*api.Deployment, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PATCH", "/deployments/"+value(in.DeploymentId))
	if err != nil {
		return nil, err
	}
	row, err := tx.Deployment(DeploymentKey{APIKey: owner.Key, DeploymentID: value(in.DeploymentId)})
	if err != nil {
		return nil, err
	}
	for _, p := range in.PatchOperations {
		if value(p.Path) != "/description" {
			return nil, bad("Only deployment description can be patched")
		}
		if err := replace(p, &row.Description); err != nil {
			return nil, err
		}
	}
	if err := tx.PutDeployment(row); err != nil {
		return nil, err
	}
	return deploymentOutput(row, false), nil
}
func (s *Service) deleteDeployment(tx Transaction, in *api.DeleteDeploymentRequest) (*api.Unit, error) {
	owner, err := s.api(tx, value(in.RestApiId), "DELETE", "/deployments/"+value(in.DeploymentId))
	if err != nil {
		return nil, err
	}
	key := DeploymentKey{APIKey: owner.Key, DeploymentID: value(in.DeploymentId)}
	if _, err := tx.Deployment(key); err != nil {
		return nil, err
	}
	stages, err := tx.Stages(owner.Key)
	if err != nil {
		return nil, err
	}
	for _, v := range stages {
		if v.DeploymentID == key.DeploymentID {
			return nil, bad("Active stages pointing to this deployment must be moved or deleted")
		}
	}
	return &api.Unit{}, tx.DeleteDeployment(key)
}

var stageName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
var variableName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
var variableValue = regexp.MustCompile(`^[a-zA-Z0-9\-._~:/?#&=,]+$`)

func validStage(name string, variables map[string]string) error {
	if !stageName.MatchString(name) {
		return bad("Invalid stage name")
	}
	for k, v := range variables {
		if !variableName.MatchString(k) || !variableValue.MatchString(v) {
			return bad("Invalid stage variable")
		}
	}
	return nil
}
func stageOutput(v StageRecord) *api.Stage {
	out := &api.Stage{StageName: ptr(v.Key.Name), DeploymentId: ptr(v.DeploymentID), Description: optional(v.Description), CreatedDate: new(v.Created), LastUpdatedDate: new(v.Updated), CacheClusterEnabled: new(api.Boolean(false)), CacheClusterStatus: new(api.CacheClusterStatus("NOT_AVAILABLE")), TracingEnabled: new(api.Boolean(false)), Variables: mapOut(v.Variables), Tags: mapOut(v.Tags), MethodSettings: methodSettingsOutput(v.MethodSettings)}
	if v.AccessLogs.DestinationARN != "" || v.AccessLogs.Format != "" {
		out.AccessLogSettings = &api.AccessLogSettings{DestinationArn: optional(v.AccessLogs.DestinationARN), Format: optional(v.AccessLogs.Format)}
	}
	return out
}
func (s *Service) createStage(tx Transaction, in *api.CreateStageRequest) (*api.Stage, error) {
	owner, err := s.api(tx, value(in.RestApiId), "POST", "/stages")
	if err != nil {
		return nil, err
	}
	if truth(in.CacheClusterEnabled) || in.CacheClusterSize != nil || in.CanarySettings != nil || truth(in.TracingEnabled) || value(in.DocumentationVersion) != "" {
		return nil, unsupported("stage cache, canary, tracing or documentation version")
	}
	if err := validStage(value(in.StageName), mapIn(in.Variables)); err != nil {
		return nil, err
	}
	tags := mapIn(in.Tags)
	if err := validateTags(tags); err != nil {
		return nil, err
	}
	key := StageKey{APIKey: owner.Key, Name: value(in.StageName)}
	if _, err := tx.Stage(key); err == nil {
		return nil, conflict("Stage already exists")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if _, err := tx.Deployment(DeploymentKey{APIKey: owner.Key, DeploymentID: value(in.DeploymentId)}); err != nil {
		return nil, err
	}
	if err := activateEndpoint(tx, owner); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	incarnation, err := tx.NextStageIncarnation(owner.Key.Scope)
	if err != nil {
		return nil, err
	}
	row := StageRecord{Key: key, Incarnation: incarnation, DeploymentID: value(in.DeploymentId), Description: value(in.Description), Created: now, Updated: now, Variables: mapIn(in.Variables), Tags: tags}
	if err := tx.PutStage(row); err != nil {
		return nil, err
	}
	return stageOutput(row), nil
}
func (s *Service) getStage(tx Transaction, in *api.GetStageRequest) (*api.Stage, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", "/stages/"+value(in.StageName))
	if err != nil {
		return nil, err
	}
	row, err := tx.Stage(StageKey{APIKey: owner.Key, Name: value(in.StageName)})
	if err != nil {
		return nil, err
	}
	return stageOutput(row), nil
}
func (s *Service) getStages(tx Transaction, in *api.GetStagesRequest) (*api.Stages, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", "/stages")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Stages(owner.Key)
	if err != nil {
		return nil, err
	}
	out := &api.Stages{Item: api.ListOfStage{}}
	for _, v := range rows {
		if value(in.DeploymentId) == "" || v.DeploymentID == value(in.DeploymentId) {
			out.Item = append(out.Item, *stageOutput(v))
		}
	}
	return out, nil
}
func (s *Service) updateStage(tx Transaction, in *api.UpdateStageRequest) (*api.Stage, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PATCH", "/stages/"+value(in.StageName))
	if err != nil {
		return nil, err
	}
	row, err := tx.Stage(StageKey{APIKey: owner.Key, Name: value(in.StageName)})
	if err != nil {
		return nil, err
	}
	if row.Variables == nil {
		row.Variables = map[string]string{}
	}
	accessChanged, executionChanged := false, false
	for _, p := range in.PatchOperations {
		path := value(p.Path)
		_, methodSetting := row.MethodSettings[strings.TrimPrefix(path, "/")]
		switch {
		case path == "/description":
			err = replace(p, &row.Description)
		case path == "/deploymentId":
			err = replace(p, &row.DeploymentID)
		case path == "/cacheClusterEnabled" || path == "/tracingEnabled":
			v := false
			err = patchBool(p, &v)
			if err == nil && v {
				err = unsupported("stage cache or tracing")
			}
		case path == "/variables" && value(p.Op) == "remove":
			row.Variables = map[string]string{}
		case strings.HasPrefix(path, "/variables/"):
			err = patchMap(p, "/variables", row.Variables)
		case path == "/accessLogSettings":
			var ignored string
			err = patchString(p, &ignored, "remove")
			if err == nil {
				row.AccessLogs = apigatewayexec.AccessLogSettings{}
			}
		case path == "/accessLogSettings/destinationArn":
			err = patchString(p, &row.AccessLogs.DestinationARN, "add", "replace", "remove")
			accessChanged = accessChanged || value(p.Op) != "remove"
		case path == "/accessLogSettings/format":
			err = patchString(p, &row.AccessLogs.Format, "add", "replace", "remove")
			accessChanged = accessChanged || value(p.Op) != "remove"
		case strings.HasSuffix(path, "/metrics/enabled"):
			err = patchMethodSetting(p, "/metrics/enabled", &row)
		case strings.HasSuffix(path, "/logging/loglevel"):
			err = patchMethodSetting(p, "/logging/loglevel", &row)
			executionChanged = true
		case strings.HasSuffix(path, "/logging/dataTrace"):
			err = patchMethodSetting(p, "/logging/dataTrace", &row)
			executionChanged = true
		case value(p.Op) == "remove" && methodSetting:
			err = removeMethodSetting(p, &row)
		default:
			err = unsupported("stage patch path " + path)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := activateEndpoint(tx, owner); err != nil {
		return nil, err
	}
	if err := validStage(row.Key.Name, row.Variables); err != nil {
		return nil, err
	}
	if _, err := tx.Deployment(DeploymentKey{APIKey: owner.Key, DeploymentID: row.DeploymentID}); err != nil {
		return nil, err
	}
	if accessChanged && (row.AccessLogs.DestinationARN != "" || row.AccessLogs.Format != "") {
		if s.logs == nil {
			return nil, unsupported("CloudWatch access logging")
		}
		if err := s.logs.ConfigureAccessLogs(tx.Context(), "REST", row.AccessLogs); err != nil {
			return nil, err
		}
	}
	if executionChanged {
		for _, settings := range row.MethodSettings {
			if settings.LoggingLevel != "INFO" && settings.LoggingLevel != "ERROR" {
				continue
			}
			if s.logs == nil {
				return nil, unsupported("CloudWatch execution logging")
			}
			if err := s.logs.RequireLoggingRole(tx.Context()); err != nil {
				return nil, err
			}
			break
		}
	}
	row.Updated = s.clock.Now()
	if err := tx.PutStage(row); err != nil {
		return nil, err
	}
	return stageOutput(row), nil
}
func (s *Service) deleteStage(tx Transaction, in *api.DeleteStageRequest) (*api.Unit, error) {
	owner, err := s.api(tx, value(in.RestApiId), "DELETE", "/stages/"+value(in.StageName))
	if err != nil {
		return nil, err
	}
	key := StageKey{APIKey: owner.Key, Name: value(in.StageName)}
	if _, err := tx.Stage(key); err != nil {
		return nil, err
	}
	return &api.Unit{}, tx.DeleteStage(key)
}

// AWS applies endpoint enablement to all stages only when a stage is updated.
func activateEndpoint(tx Transaction, owner APIRecord) error {
	if owner.EffectiveDisabled == owner.Disabled {
		return nil
	}
	owner.EffectiveDisabled = owner.Disabled
	return tx.PutAPI(owner)
}
