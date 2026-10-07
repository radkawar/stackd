package apigatewayv2

import (
	"database/sql"
	"stackd/internal/services/apigatewayexec"
	domain "stackd/internal/services/apigatewayv2"
	"stackd/storage/sqlite/apigatewayv2/internal/sqlcgen"
)

func rowAPI(row sqlcgen.Apigatewayv2Api) (domain.APIRecord, error) {
	out := domain.APIRecord{Key: domain.APIKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ID}, Name: row.Name, Description: row.Description, Version: row.Version, Disabled: row.Disabled != 0, Created: row.CreatedAt.UTC(), ProtocolType: row.ProtocolType, RouteSelectionExpression: row.RouteSelectionExpression}
	out.Owner = domain.ResourceOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}
	if err := decode(row.Tags, &out.Tags); err != nil {
		return out, err
	}
	return out, nil
}
func (r reader) API(k domain.APIKey) (domain.APIRecord, error) {
	row, err := r.q.GetAPI(r.ctx, sqlcgen.GetAPIParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID})
	if err != nil {
		return domain.APIRecord{}, missing(err)
	}
	return rowAPI(row)
}
func (r reader) APIs(k domain.Scope) ([]domain.APIRecord, error) {
	rows, err := r.q.ListAPIs(r.ctx, sqlcgen.ListAPIsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.APIRecord, len(rows))
	for i, row := range rows {
		out[i], err = rowAPI(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (w writer) PutAPI(v domain.APIRecord) error {
	k := v.Key
	tags, err := encode(v.Tags)
	if err != nil {
		return err
	}
	return w.q.PutAPI(w.ctx, sqlcgen.PutAPIParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID, Name: v.Name, Description: v.Description, Version: v.Version, Disabled: integer(v.Disabled), CreatedAt: v.Created.UTC(), Tags: tags, ProtocolType: v.ProtocolType, RouteSelectionExpression: v.RouteSelectionExpression, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token})
}
func (w writer) DeleteAPI(k domain.APIKey) error {
	return w.q.DeleteAPI(w.ctx, sqlcgen.DeleteAPIParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID})
}

func rowIntegration(row sqlcgen.Apigatewayv2Integration) (domain.IntegrationRecord, error) {
	out := domain.IntegrationRecord{Key: domain.ResourceKey{APIKey: domain.APIKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.GatewayID}, ID: row.ID}, Description: row.Description, URI: row.Uri, PayloadVersion: row.PayloadVersion, TimeoutMillis: int32(row.TimeoutMillis), PassthroughBehavior: row.PassthroughBehavior}
	out.Owner = domain.ResourceOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}
	out.CredentialsARN = row.CredentialsArn
	return out, nil
}
func (r reader) Integration(k domain.ResourceKey) (domain.IntegrationRecord, error) {
	row, err := r.q.GetIntegration(r.ctx, sqlcgen.GetIntegrationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
	if err != nil {
		return domain.IntegrationRecord{}, missing(err)
	}
	return rowIntegration(row)
}
func (r reader) Integrations(k domain.APIKey) ([]domain.IntegrationRecord, error) {
	rows, err := r.q.ListIntegrations(r.ctx, sqlcgen.ListIntegrationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.IntegrationRecord, len(rows))
	for i, row := range rows {
		out[i], err = rowIntegration(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (w writer) PutIntegration(v domain.IntegrationRecord) error {
	k := v.Key
	return w.q.PutIntegration(w.ctx, sqlcgen.PutIntegrationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID, Description: v.Description, Uri: v.URI, PayloadVersion: v.PayloadVersion, TimeoutMillis: int64(v.TimeoutMillis), PassthroughBehavior: v.PassthroughBehavior, CredentialsArn: v.CredentialsARN, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token})
}
func (w writer) DeleteIntegration(k domain.ResourceKey) error {
	return w.q.DeleteIntegration(w.ctx, sqlcgen.DeleteIntegrationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
}

func rowAuthorizer(row sqlcgen.Apigatewayv2Authorizer) (domain.AuthorizerRecord, error) {
	out := domain.AuthorizerRecord{Key: domain.ResourceKey{APIKey: domain.APIKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.GatewayID}, ID: row.ID}, Name: row.Name, Issuer: row.Issuer}
	out.Owner = domain.ResourceOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}
	if err := decode(row.Audiences, &out.Audiences); err != nil {
		return out, err
	}
	if row.AuthorizerType == "REQUEST" {
		out.URI = row.Uri
		out.LambdaAuthorizer = &apigatewayexec.LambdaAuthorizer{ID: row.ID, Type: row.AuthorizerType, FunctionARN: row.FunctionArn, CredentialsARN: row.CredentialsArn, PayloadVersion: row.PayloadVersion, TTLSeconds: int32(row.TtlSeconds), SimpleResponses: row.SimpleResponses != 0, ValidationExpression: row.ValidationExpression}
		if err := decode(row.IdentitySources, &out.LambdaAuthorizer.IdentitySources); err != nil {
			return out, err
		}
	}
	return out, nil
}
func (r reader) Authorizer(k domain.ResourceKey) (domain.AuthorizerRecord, error) {
	row, err := r.q.GetAuthorizer(r.ctx, sqlcgen.GetAuthorizerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
	if err != nil {
		return domain.AuthorizerRecord{}, missing(err)
	}
	return rowAuthorizer(row)
}
func (r reader) Authorizers(k domain.APIKey) ([]domain.AuthorizerRecord, error) {
	rows, err := r.q.ListAuthorizers(r.ctx, sqlcgen.ListAuthorizersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.AuthorizerRecord, len(rows))
	for i, row := range rows {
		out[i], err = rowAuthorizer(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (w writer) PutAuthorizer(v domain.AuthorizerRecord) error {
	k := v.Key
	audiences, err := encode(v.Audiences)
	if err != nil {
		return err
	}
	params := sqlcgen.PutAuthorizerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID, Name: v.Name, Issuer: v.Issuer, Audiences: audiences, AuthorizerType: "JWT", IdentitySources: []byte("[]")}
	params.OwnerStackID, params.OwnerLogicalID, params.OwnerToken = v.Owner.StackID, v.Owner.LogicalID, v.Owner.Token
	if auth := v.LambdaAuthorizer; auth != nil {
		params.AuthorizerType, params.Uri, params.FunctionArn, params.PayloadVersion = auth.Type, v.URI, auth.FunctionARN, auth.PayloadVersion
		params.CredentialsArn = auth.CredentialsARN
		params.ValidationExpression = auth.ValidationExpression
		params.TtlSeconds, params.SimpleResponses = int64(auth.TTLSeconds), integer(auth.SimpleResponses)
		params.IdentitySources, err = encode(auth.IdentitySources)
		if err != nil {
			return err
		}
	}
	return w.q.PutAuthorizer(w.ctx, params)
}
func (w writer) DeleteAuthorizer(k domain.ResourceKey) error {
	return w.q.DeleteAuthorizer(w.ctx, sqlcgen.DeleteAuthorizerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
}

func rowRoute(row sqlcgen.Apigatewayv2Route) (domain.RouteRecord, error) {
	out := domain.RouteRecord{Key: domain.ResourceKey{APIKey: domain.APIKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.GatewayID}, ID: row.ID}, RouteKey: row.RouteKey, Target: row.Target, AuthorizationType: row.AuthorizationType, AuthorizerID: row.AuthorizerID, OperationName: row.OperationName, RouteResponseSelectionExpression: row.RouteResponseSelectionExpression}
	out.Owner = domain.ResourceOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}
	if err := decode(row.Scopes, &out.Scopes); err != nil {
		return out, err
	}
	return out, nil
}
func (r reader) Route(k domain.ResourceKey) (domain.RouteRecord, error) {
	row, err := r.q.GetRoute(r.ctx, sqlcgen.GetRouteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
	if err != nil {
		return domain.RouteRecord{}, missing(err)
	}
	return rowRoute(row)
}
func (r reader) Routes(k domain.APIKey) ([]domain.RouteRecord, error) {
	rows, err := r.q.ListRoutes(r.ctx, sqlcgen.ListRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.RouteRecord, len(rows))
	for i, row := range rows {
		out[i], err = rowRoute(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (w writer) PutRoute(v domain.RouteRecord) error {
	k := v.Key
	scopes, err := encode(v.Scopes)
	if err != nil {
		return err
	}
	return w.q.PutRoute(w.ctx, sqlcgen.PutRouteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID, RouteKey: v.RouteKey, Target: v.Target, AuthorizationType: v.AuthorizationType, AuthorizerID: v.AuthorizerID, OperationName: v.OperationName, Scopes: scopes, RouteResponseSelectionExpression: v.RouteResponseSelectionExpression, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token})
}
func (w writer) DeleteRoute(k domain.ResourceKey) error {
	return w.q.DeleteRoute(w.ctx, sqlcgen.DeleteRouteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
}

func (r reader) stage(row sqlcgen.Apigatewayv2Stage) (domain.StageRecord, error) {
	out := domain.StageRecord{Key: domain.ResourceKey{APIKey: domain.APIKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.GatewayID}, ID: row.ID}, Description: row.Description, DeploymentID: row.DeploymentID, LastDeploymentStatusMessage: row.LastDeploymentStatusMessage, AutoDeploy: row.AutoDeploy != 0, Created: row.CreatedAt.UTC(), Updated: row.UpdatedAt.UTC(), DefaultRouteSettings: domain.RouteSettings{DetailedMetricsEnabled: new(row.DetailedMetrics), LoggingLevel: row.LoggingLevel, DataTraceEnabled: new(row.DataTrace)}, AccessLogSettings: apigatewayexec.AccessLogSettings{DestinationARN: row.AccessLogDestinationArn, Format: row.AccessLogFormat}}
	out.Owner = domain.ResourceOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}
	if err := decode(row.Variables, &out.Variables); err != nil {
		return out, err
	}
	if err := decode(row.Tags, &out.Tags); err != nil {
		return out, err
	}
	settings, err := r.q.ListRouteSettings(r.ctx, sqlcgen.ListRouteSettingsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, GatewayID: row.GatewayID, Stage: row.ID})
	if err != nil {
		return out, err
	}
	out.RouteSettings = make(map[string]domain.RouteSettings, len(settings))
	for _, setting := range settings {
		retained := domain.RouteSettings{LoggingLevel: setting.LoggingLevel}
		if setting.DetailedMetrics.Valid {
			retained.DetailedMetricsEnabled = new(setting.DetailedMetrics.Bool)
		}
		if setting.DataTrace.Valid {
			retained.DataTraceEnabled = new(setting.DataTrace.Bool)
		}
		out.RouteSettings[setting.RouteKey] = retained
	}
	return out, nil
}
func (r reader) Stage(k domain.ResourceKey) (domain.StageRecord, error) {
	row, err := r.q.GetStage(r.ctx, sqlcgen.GetStageParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
	if err != nil {
		return domain.StageRecord{}, missing(err)
	}
	return r.stage(row)
}
func (r reader) Stages(k domain.APIKey) ([]domain.StageRecord, error) {
	rows, err := r.q.ListStages(r.ctx, sqlcgen.ListStagesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.StageRecord, len(rows))
	for i, row := range rows {
		out[i], err = r.stage(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (w writer) PutStage(v domain.StageRecord) error {
	k := v.Key
	variables, err := encode(v.Variables)
	if err != nil {
		return err
	}
	tags, err := encode(v.Tags)
	if err != nil {
		return err
	}
	params := sqlcgen.PutStageParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID, Description: v.Description, DeploymentID: v.DeploymentID, LastDeploymentStatusMessage: v.LastDeploymentStatusMessage, AutoDeploy: integer(v.AutoDeploy), CreatedAt: v.Created.UTC(), UpdatedAt: v.Updated.UTC(), Variables: variables, Tags: tags, DetailedMetrics: v.DefaultRouteSettings.DetailedMetricsEnabled != nil && *v.DefaultRouteSettings.DetailedMetricsEnabled, LoggingLevel: v.DefaultRouteSettings.LoggingLevel, DataTrace: v.DefaultRouteSettings.DataTraceEnabled != nil && *v.DefaultRouteSettings.DataTraceEnabled, AccessLogDestinationArn: v.AccessLogSettings.DestinationARN, AccessLogFormat: v.AccessLogSettings.Format}
	params.OwnerStackID, params.OwnerLogicalID, params.OwnerToken = v.Owner.StackID, v.Owner.LogicalID, v.Owner.Token
	if err := w.q.PutStage(w.ctx, params); err != nil {
		return err
	}
	if err := w.q.DeleteRouteSettings(w.ctx, sqlcgen.DeleteRouteSettingsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, Stage: k.ID}); err != nil {
		return err
	}
	for route, settings := range v.RouteSettings {
		metrics, trace := sql.NullBool{}, sql.NullBool{}
		if settings.DetailedMetricsEnabled != nil {
			metrics = sql.NullBool{Bool: *settings.DetailedMetricsEnabled, Valid: true}
		}
		if settings.DataTraceEnabled != nil {
			trace = sql.NullBool{Bool: *settings.DataTraceEnabled, Valid: true}
		}
		if err := w.q.PutRouteSettings(w.ctx, sqlcgen.PutRouteSettingsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, Stage: k.ID, RouteKey: route, DetailedMetrics: metrics, LoggingLevel: settings.LoggingLevel, DataTrace: trace}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteStage(k domain.ResourceKey) error {
	return w.q.DeleteStage(w.ctx, sqlcgen.DeleteStageParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
}

func rowDeployment(row sqlcgen.Apigatewayv2Deployment) (domain.DeploymentRecord, error) {
	out := domain.DeploymentRecord{Key: domain.ResourceKey{APIKey: domain.APIKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.GatewayID}, ID: row.ID}, Description: row.Description, AutoDeployed: row.AutoDeployed != 0, Created: row.CreatedAt.UTC(), RouteSelectionExpression: row.RouteSelectionExpression}
	out.Owner = domain.ResourceOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}
	return out, nil
}
func (r reader) Deployment(k domain.ResourceKey) (domain.DeploymentRecord, error) {
	row, err := r.q.GetDeployment(r.ctx, sqlcgen.GetDeploymentParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
	if err != nil {
		return domain.DeploymentRecord{}, missing(err)
	}
	return rowDeployment(row)
}
func (r reader) Deployments(k domain.APIKey) ([]domain.DeploymentRecord, error) {
	rows, err := r.q.ListDeployments(r.ctx, sqlcgen.ListDeploymentsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DeploymentRecord, len(rows))
	for i, row := range rows {
		out[i], err = rowDeployment(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (w writer) PutDeployment(v domain.DeploymentRecord) error {
	k := v.Key
	return w.q.PutDeployment(w.ctx, sqlcgen.PutDeploymentParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID, Description: v.Description, AutoDeployed: integer(v.AutoDeployed), CreatedAt: v.Created.UTC(), RouteSelectionExpression: v.RouteSelectionExpression, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token})
}
func (w writer) DeleteDeployment(k domain.ResourceKey) error {
	return w.q.DeleteDeployment(w.ctx, sqlcgen.DeleteDeploymentParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
}

func rowDeployedRoute(row sqlcgen.Apigatewayv2DeployedRoute) (domain.DeployedRoute, error) {
	out := domain.DeployedRoute{Key: domain.ResourceKey{APIKey: domain.APIKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.GatewayID}, ID: row.DeploymentID}, RouteID: row.RouteID, RouteKey: row.RouteKey, FunctionARN: row.FunctionArn, PayloadVersion: row.PayloadVersion, AuthorizationType: row.AuthorizationType, Issuer: row.Issuer, WebSocketResponseEnabled: row.WebsocketResponseEnabled != 0, TimeoutMillis: int32(row.TimeoutMillis)}
	out.CredentialsARN = row.CredentialsArn
	if err := decode(row.Audiences, &out.Audiences); err != nil {
		return out, err
	}
	if err := decode(row.Scopes, &out.Scopes); err != nil {
		return out, err
	}
	if row.AuthorizerType != "" {
		out.LambdaAuthorizer = &apigatewayexec.LambdaAuthorizer{ID: row.AuthorizerID, Type: row.AuthorizerType, FunctionARN: row.AuthorizerFunctionArn, CredentialsARN: row.AuthorizerCredentialsArn, PayloadVersion: row.AuthorizerPayloadVersion, TTLSeconds: int32(row.AuthorizerTtlSeconds), SimpleResponses: row.AuthorizerSimpleResponses != 0}
		if err := decode(row.AuthorizerIdentitySources, &out.LambdaAuthorizer.IdentitySources); err != nil {
			return out, err
		}
	}
	return out, nil
}
func (r reader) DeployedRoutes(k domain.ResourceKey) ([]domain.DeployedRoute, error) {
	rows, err := r.q.ListDeployedRoutes(r.ctx, sqlcgen.ListDeployedRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, DeploymentID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DeployedRoute, len(rows))
	for i, row := range rows {
		out[i], err = rowDeployedRoute(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (w writer) PutDeployedRoute(v domain.DeployedRoute) error {
	k := v.Key
	audiences, err := encode(v.Audiences)
	if err != nil {
		return err
	}
	scopes, err := encode(v.Scopes)
	if err != nil {
		return err
	}
	params := sqlcgen.PutDeployedRouteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, DeploymentID: k.ID, RouteID: v.RouteID, RouteKey: v.RouteKey, FunctionArn: v.FunctionARN, PayloadVersion: v.PayloadVersion, AuthorizationType: v.AuthorizationType, Issuer: v.Issuer, Audiences: audiences, Scopes: scopes, AuthorizerIdentitySources: []byte("[]"), WebsocketResponseEnabled: integer(v.WebSocketResponseEnabled), TimeoutMillis: int64(v.TimeoutMillis)}
	params.CredentialsArn = v.CredentialsARN
	if auth := v.LambdaAuthorizer; auth != nil {
		params.AuthorizerID, params.AuthorizerType, params.AuthorizerFunctionArn, params.AuthorizerPayloadVersion = auth.ID, auth.Type, auth.FunctionARN, auth.PayloadVersion
		params.AuthorizerCredentialsArn = auth.CredentialsARN
		params.AuthorizerTtlSeconds, params.AuthorizerSimpleResponses = int64(auth.TTLSeconds), integer(auth.SimpleResponses)
		params.AuthorizerIdentitySources, err = encode(auth.IdentitySources)
		if err != nil {
			return err
		}
	}
	return w.q.PutDeployedRoute(w.ctx, params)
}
func (r reader) APIByID(id string) (domain.APIRecord, error) {
	row, err := r.q.GetAPIByID(r.ctx, id)
	if err != nil {
		return domain.APIRecord{}, missing(err)
	}
	return rowAPI(row)
}
