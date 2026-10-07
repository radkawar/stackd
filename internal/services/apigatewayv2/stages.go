package apigatewayv2

import (
	"context"
	"errors"
	"regexp"
	api "stackd/internal/awsapi/apigatewayv2"
	"stackd/internal/services/apigatewayexec"
)

var stageNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var stageVariableName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
var stageVariableValue = regexp.MustCompile(`^[A-Za-z0-9\-._~:/?#&=,]+$`)

type declarativeStageKey struct{}

// WithDeclarativeStage makes UpdateStage replace stage variables and route
// settings with the request values, as a complete CloudFormation model does.
func WithDeclarativeStage(ctx context.Context) context.Context {
	return context.WithValue(ctx, declarativeStageKey{}, true)
}
func declarativeStage(ctx context.Context) bool {
	v, _ := ctx.Value(declarativeStageKey{}).(bool)
	return v
}

func stageOutput(v StageRecord, protocol string) api.Stage {
	out := api.Stage{CreatedDate: new(v.Created), LastUpdatedDate: new(v.Updated), DefaultRouteSettings: &api.RouteSettings{}, RouteSettings: api.RouteSettingsMap{}}
	flag(&out.DefaultRouteSettings.DetailedMetricsEnabled, boolean(v.DefaultRouteSettings.DetailedMetricsEnabled))
	routeSettingsMapOutput(out.RouteSettings, v.RouteSettings, protocol)
	if protocol == "WEBSOCKET" {
		flag(&out.DefaultRouteSettings.DataTraceEnabled, boolean(v.DefaultRouteSettings.DataTraceEnabled))
		text(&out.DefaultRouteSettings.LoggingLevel, loggingLevel(v.DefaultRouteSettings.LoggingLevel))
	}
	if v.AccessLogSettings.DestinationARN != "" {
		out.AccessLogSettings = &api.AccessLogSettings{}
		text(&out.AccessLogSettings.DestinationArn, v.AccessLogSettings.DestinationARN)
		text(&out.AccessLogSettings.Format, v.AccessLogSettings.Format)
	}
	text(&out.StageName, v.Key.ID)
	flag(&out.AutoDeploy, v.AutoDeploy)
	if v.DeploymentID != "" {
		text(&out.DeploymentId, v.DeploymentID)
	}
	if v.Description != "" {
		text(&out.Description, v.Description)
	}
	if v.LastDeploymentStatusMessage != "" {
		text(&out.LastDeploymentStatusMessage, v.LastDeploymentStatusMessage)
	}
	stringMap(&out.StageVariables, v.Variables)
	stringMap(&out.Tags, v.Tags)
	return out
}
func validateSettings(v *api.RouteSettings, protocol string) error {
	if v == nil {
		return nil
	}
	if protocol == "HTTP" && (v.LoggingLevel != nil || boolean(v.DataTraceEnabled)) {
		return bad("Execution logs are not supported on protocolType HTTP")
	}
	if v.ThrottlingBurstLimit != nil || v.ThrottlingRateLimit != nil {
		// TODO: Comeback implement route throttling.
		return unsupported("Route throttling is not implemented")
	}
	return nil
}
func validateStage(in *api.CreateStageInput, protocol string) error {
	if value(in.StageName) != "$default" && !stageNamePattern.MatchString(value(in.StageName)) {
		return bad("Invalid stage name")
	}
	if in.ClientCertificateId != nil {
		return unsupported("Client certificates are not implemented")
	}
	if err := validateSettings(in.DefaultRouteSettings, protocol); err != nil {
		return err
	}
	for _, settings := range in.RouteSettings {
		if err := validateSettings(&settings, protocol); err != nil {
			return err
		}
	}
	for k, v := range in.StageVariables {
		if !stageVariableName.MatchString(string(k)) || !stageVariableValue.MatchString(string(v)) {
			return bad("Invalid stage variable")
		}
	}
	return validTags(mapOf(in.Tags))
}
func (s *Service) createStage(tx Transaction, in *api.CreateStageInput) (*api.CreateStageOutput, error) {
	owner, err := tx.API(APIKey{scopeFor(tx.Context()), value(in.ApiId)})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if e := s.authorize(tx, "POST", "/apis/"+value(in.ApiId)+"/stages", nil, mapOf(in.Tags), nil); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	if err := validateStage(in, owner.ProtocolType); err != nil {
		return nil, err
	}
	if v, found, err := recoverOwnedResource(tx, owner.Key, tx.Stages); err != nil {
		return nil, err
	} else if found {
		return new(api.CreateStageOutput(stageOutput(v, owner.ProtocolType))), nil
	}
	key := ResourceKey{owner.Key, value(in.StageName)}
	if _, err := tx.Stage(key); err == nil {
		return nil, failure("ConflictException", "Stage already exists", 409)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if in.DeploymentId != nil {
		if boolean(in.AutoDeploy) {
			return nil, bad("DeploymentId cannot be set on an automatically deployed stage")
		}
		if _, err := tx.Deployment(ResourceKey{owner.Key, value(in.DeploymentId)}); err != nil {
			return nil, err
		}
	}
	now := s.clock.Now()
	v := StageRecord{Key: key, Description: value(in.Description), DeploymentID: value(in.DeploymentId), AutoDeploy: boolean(in.AutoDeploy), Created: now, Updated: now, Variables: mapOf(in.StageVariables), Tags: mapOf(in.Tags)}
	applyStageSettings(&v, in.DefaultRouteSettings, in.RouteSettings, owner.ProtocolType)
	if err := s.configureStageLogging(tx.Context(), &v, owner.ProtocolType, in.AccessLogSettings, in.DefaultRouteSettings != nil || len(in.RouteSettings) != 0); err != nil {
		return nil, err
	}
	if err := tx.PutStage(v); err != nil {
		return nil, err
	}
	if v.AutoDeploy {
		if err := s.autoDeploy(tx, owner.Key); err != nil {
			return nil, err
		}
		v, err = tx.Stage(key)
		if err != nil {
			return nil, err
		}
	}
	return new(api.CreateStageOutput(stageOutput(v, owner.ProtocolType))), nil
}
func (s *Service) updateStage(tx Transaction, in *api.UpdateStageInput) (*api.UpdateStageOutput, error) {
	owner, err := s.ownedAPI(tx, "PATCH", value(in.ApiId), "/stages/"+value(in.StageName))
	if err != nil {
		return nil, err
	}
	v, err := tx.Stage(ResourceKey{owner.Key, value(in.StageName)})
	if err != nil {
		return nil, err
	}
	check := api.CreateStageInput{StageName: new(api.StringWithLengthBetween1And128(v.Key.ID)), AccessLogSettings: in.AccessLogSettings, ClientCertificateId: in.ClientCertificateId, DefaultRouteSettings: in.DefaultRouteSettings, RouteSettings: in.RouteSettings, StageVariables: in.StageVariables}
	if err := validateStage(&check, owner.ProtocolType); err != nil {
		return nil, err
	}
	if declarativeStage(tx.Context()) {
		// CloudFormation declares the complete stage model. Stage variables and
		// route settings omitted from it must be removed, not merged.
		v.Variables = nil
		v.DefaultRouteSettings = RouteSettings{}
		v.RouteSettings = nil
	}
	wasAuto := v.AutoDeploy
	if in.AutoDeploy != nil {
		v.AutoDeploy = boolean(in.AutoDeploy)
	}
	if in.DeploymentId != nil {
		if wasAuto || v.AutoDeploy {
			return nil, bad("DeploymentId cannot be set on an automatically deployed stage")
		}
		if _, err := tx.Deployment(ResourceKey{owner.Key, value(in.DeploymentId)}); err != nil {
			return nil, err
		}
		v.DeploymentID = value(in.DeploymentId)
		v.LastDeploymentStatusMessage = ""
	}
	if in.Description != nil {
		v.Description = value(in.Description)
	}
	if len(in.StageVariables) != 0 && v.Variables == nil {
		v.Variables = make(map[string]string, len(in.StageVariables))
	}
	for name, variable := range in.StageVariables {
		v.Variables[string(name)] = string(variable)
	}
	applyStageSettings(&v, in.DefaultRouteSettings, in.RouteSettings, owner.ProtocolType)
	if err := s.configureStageLogging(tx.Context(), &v, owner.ProtocolType, in.AccessLogSettings, in.DefaultRouteSettings != nil || len(in.RouteSettings) != 0); err != nil {
		return nil, err
	}
	v.Updated = s.clock.Now()
	if err := tx.PutStage(v); err != nil {
		return nil, err
	}
	if v.AutoDeploy && !wasAuto {
		if err := s.autoDeploy(tx, owner.Key); err != nil {
			return nil, err
		}
		v, err = tx.Stage(v.Key)
		if err != nil {
			return nil, err
		}
	}
	return new(api.UpdateStageOutput(stageOutput(v, owner.ProtocolType))), nil
}

func applyRouteSettings(settings *RouteSettings, in *api.RouteSettings, protocol string) {
	if in == nil {
		return
	}
	if in.DetailedMetricsEnabled != nil {
		settings.DetailedMetricsEnabled = new(boolean(in.DetailedMetricsEnabled))
	}
	if protocol == "WEBSOCKET" {
		if in.LoggingLevel != nil {
			settings.LoggingLevel = loggingLevel(value(in.LoggingLevel))
		}
		if in.DataTraceEnabled != nil {
			settings.DataTraceEnabled = new(boolean(in.DataTraceEnabled))
		}
	}
}

func applyStageSettings(stage *StageRecord, defaults *api.RouteSettings, routes api.RouteSettingsMap, protocol string) {
	applyRouteSettings(&stage.DefaultRouteSettings, defaults, protocol)
	if len(routes) != 0 && stage.RouteSettings == nil {
		stage.RouteSettings = make(map[string]RouteSettings, len(routes))
	}
	for key, input := range routes {
		settings := stage.RouteSettings[string(key)]
		applyRouteSettings(&settings, &input, protocol)
		stage.RouteSettings[string(key)] = settings
	}
}

func loggingLevel(level string) string {
	switch level {
	case "INFO", "ERROR":
		return level
	default:
		return "OFF"
	}
}

func (s *Service) configureStageLogging(ctx context.Context, stage *StageRecord, protocol string, access *api.AccessLogSettings, executionChanged bool) error {
	if access != nil {
		settings := stage.AccessLogSettings
		if access.DestinationArn != nil {
			settings.DestinationARN = value(access.DestinationArn)
		}
		if access.Format != nil {
			settings.Format = value(access.Format)
		}
		if settings.DestinationARN == "" || settings.Format == "" {
			return bad("Access Log value missing. Expected destinationArn and format.")
		}
		if s.logs == nil {
			return unsupported("Access log delivery is not configured")
		}
		if err := s.logs.ConfigureAccessLogs(ctx, protocol, settings); err != nil {
			return err
		}
		stage.AccessLogSettings = settings
	}
	if protocol == "WEBSOCKET" && executionChanged {
		enabled := loggingLevel(stage.DefaultRouteSettings.LoggingLevel) != "OFF"
		for _, settings := range stage.RouteSettings {
			enabled = enabled || settings.LoggingLevel != "" && loggingLevel(settings.LoggingLevel) != "OFF"
		}
		if enabled {
			if s.logs == nil {
				return unsupported("Execution log delivery is not configured")
			}
			return s.logs.RequireLoggingRole(ctx)
		}
	}
	return nil
}

func (s StageRecord) detailedMetrics(route string) bool {
	// Native v2 stage defaults enable detail even when a retained route value
	// is false; this differs from REST's method override precedence.
	return boolean(s.DefaultRouteSettings.DetailedMetricsEnabled) || boolean(s.RouteSettings[route].DetailedMetricsEnabled)
}

func routeSettingsMapOutput[K ~string](out map[K]api.RouteSettings, settings map[string]RouteSettings, protocol string) {
	for key, setting := range settings {
		out[K(key)] = routeSettingsOutput(setting, protocol)
	}
}

func routeSettingsOutput(settings RouteSettings, protocol string) api.RouteSettings {
	out := api.RouteSettings{}
	if settings.DetailedMetricsEnabled != nil {
		flag(&out.DetailedMetricsEnabled, *settings.DetailedMetricsEnabled)
	}
	if protocol == "WEBSOCKET" {
		if settings.DataTraceEnabled != nil {
			flag(&out.DataTraceEnabled, *settings.DataTraceEnabled)
		}
		if settings.LoggingLevel != "" {
			text(&out.LoggingLevel, settings.LoggingLevel)
		}
	}
	return out
}

func (s StageRecord) logging(route string) apigatewayexec.LoggingSettings {
	out := apigatewayexec.LoggingSettings{Access: s.AccessLogSettings, Level: loggingLevel(s.DefaultRouteSettings.LoggingLevel), DataTrace: boolean(s.DefaultRouteSettings.DataTraceEnabled)}
	settings := s.RouteSettings[route]
	if settings.LoggingLevel != "" {
		out.Level = settings.LoggingLevel
	}
	if settings.DataTraceEnabled != nil {
		out.DataTrace = *settings.DataTraceEnabled
	}
	return out
}

func (s *Service) deleteAccessLogSettings(tx Transaction, in *api.DeleteAccessLogSettingsInput) (*api.DeleteAccessLogSettingsOutput, error) {
	owner, err := s.ownedAPI(tx, "DELETE", value(in.ApiId), "/stages/"+value(in.StageName)+"/accesslogsettings")
	if err != nil {
		return nil, err
	}
	stage, err := tx.Stage(ResourceKey{owner.Key, value(in.StageName)})
	if err != nil {
		return nil, err
	}
	stage.AccessLogSettings = apigatewayexec.AccessLogSettings{}
	stage.Updated = s.clock.Now()
	if err := tx.PutStage(stage); err != nil {
		return nil, err
	}
	return &api.DeleteAccessLogSettingsOutput{}, nil
}

func (s *Service) deleteRouteSettings(tx Transaction, in *api.DeleteRouteSettingsInput) (*api.DeleteRouteSettingsOutput, error) {
	owner, err := s.ownedAPI(tx, "DELETE", value(in.ApiId), "/stages/"+value(in.StageName)+"/routesettings/"+value(in.RouteKey))
	if err != nil {
		return nil, err
	}
	stage, err := tx.Stage(ResourceKey{owner.Key, value(in.StageName)})
	if err != nil {
		return nil, err
	}
	delete(stage.RouteSettings, value(in.RouteKey))
	stage.Updated = s.clock.Now()
	if err := tx.PutStage(stage); err != nil {
		return nil, err
	}
	return &api.DeleteRouteSettingsOutput{}, nil
}
