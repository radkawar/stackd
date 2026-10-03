package apigatewayv2

import (
	"regexp"
	api "stackd/internal/awsapi/apigatewayv2"
)

var lambdaURI = regexp.MustCompile(`^arn:[a-z0-9-]+:lambda:[a-z0-9-]+:[0-9]{12}:function:[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)?$`)

func integrationOutput(v IntegrationRecord) api.Integration {
	out := api.Integration{}
	text(&out.IntegrationId, v.Key.ID)
	text(&out.IntegrationType, "AWS_PROXY")
	text(&out.ConnectionType, "INTERNET")
	text(&out.IntegrationMethod, "POST")
	text(&out.IntegrationUri, v.URI)
	text(&out.PayloadFormatVersion, v.PayloadVersion)
	if v.CredentialsARN != "" {
		text(&out.CredentialsArn, v.CredentialsARN)
	}
	out.TimeoutInMillis = new(api.IntegerWithLengthBetween50And30000(v.TimeoutMillis))
	if v.PassthroughBehavior != "" {
		text(&out.PassthroughBehavior, v.PassthroughBehavior)
	}
	if v.Description != "" {
		text(&out.Description, v.Description)
	}
	return out
}
func validateIntegration(in *api.CreateIntegrationInput, protocol string) error {
	// TODO: Comeback implement non-Lambda integrations, mappings,
	// templates, TLS and configurable HTTP integration timeouts.
	if value(in.IntegrationType) != "AWS_PROXY" {
		return unsupported("Only Lambda AWS_PROXY integrations are implemented")
	}
	if protocol == "WEBSOCKET" {
		if _, err := authorizerFunctionARN(value(in.IntegrationUri)); err != nil {
			return bad("WebSocket Lambda integrations require an API Gateway Lambda invocation URI")
		}
		if in.PayloadFormatVersion != nil && value(in.PayloadFormatVersion) != "1.0" {
			return bad("WebSocket integrations require PayloadFormatVersion 1.0")
		}
		if in.PassthroughBehavior != nil && value(in.PassthroughBehavior) != "WHEN_NO_MATCH" {
			return unsupported("Only WHEN_NO_MATCH passthrough behavior is implemented")
		}
		if in.TimeoutInMillis != nil && (*in.TimeoutInMillis < 50 || *in.TimeoutInMillis > 29000) {
			return bad("WebSocket integration timeout must be between 50 and 29000 milliseconds")
		}
	} else {
		if !lambdaURI.MatchString(value(in.IntegrationUri)) {
			return unsupported("Only Lambda ARN AWS_PROXY integrations are implemented")
		}
		if value(in.PayloadFormatVersion) != "1.0" && value(in.PayloadFormatVersion) != "2.0" {
			return bad("PayloadFormatVersion must be 1.0 or 2.0")
		}
		if in.PassthroughBehavior != nil {
			return unsupported("HTTP integration passthrough behavior is not implemented")
		}
		if in.TimeoutInMillis != nil && int32(*in.TimeoutInMillis) != 30000 {
			return unsupported("Custom HTTP integration timeouts are not implemented")
		}
	}
	if arn := value(in.CredentialsArn); arn != "" && !authorizerRoleARN.MatchString(arn) {
		return bad("Invalid role ARN")
	}
	if in.ConnectionId != nil || in.ConnectionType != nil && value(in.ConnectionType) != "INTERNET" || in.ContentHandlingStrategy != nil || in.IntegrationSubtype != nil || in.IntegrationMethod != nil && value(in.IntegrationMethod) != "POST" || len(in.RequestParameters) > 0 || len(in.RequestTemplates) > 0 || len(in.ResponseParameters) > 0 || in.TemplateSelectionExpression != nil || in.TlsConfig != nil {
		return unsupported("Integration mappings, templates and TLS are not implemented")
	}
	return nil
}
func (s *Service) createIntegration(tx Transaction, in *api.CreateIntegrationInput) (*api.CreateIntegrationOutput, error) {
	owner, err := s.ownedAPI(tx, "POST", value(in.ApiId), "/integrations")
	if err != nil {
		return nil, err
	}
	if err := validateIntegration(in, owner.ProtocolType); err != nil {
		return nil, err
	}
	if err := s.passInvocationRole(tx, value(in.CredentialsArn)); err != nil {
		return nil, err
	}
	id, err := controlID()
	if err != nil {
		return nil, err
	}
	v := IntegrationRecord{Key: ResourceKey{owner.Key, id}, Description: value(in.Description), URI: value(in.IntegrationUri), PayloadVersion: value(in.PayloadFormatVersion), CredentialsARN: value(in.CredentialsArn)}
	v.TimeoutMillis = 30000
	if owner.ProtocolType == "WEBSOCKET" {
		v.TimeoutMillis = 29000
		v.PassthroughBehavior = "WHEN_NO_MATCH"
		if v.PayloadVersion == "" {
			v.PayloadVersion = "1.0"
		}
	}
	if in.TimeoutInMillis != nil {
		v.TimeoutMillis = int32(*in.TimeoutInMillis)
	}
	if err := tx.PutIntegration(v); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, owner.Key); err != nil {
		return nil, err
	}
	return new(api.CreateIntegrationOutput(integrationOutput(v))), nil
}
func (s *Service) updateIntegration(tx Transaction, in *api.UpdateIntegrationInput) (*api.UpdateIntegrationOutput, error) {
	owner, err := s.ownedAPI(tx, "PATCH", value(in.ApiId), "/integrations/"+value(in.IntegrationId))
	if err != nil {
		return nil, err
	}
	v, err := tx.Integration(ResourceKey{owner.Key, value(in.IntegrationId)})
	if err != nil {
		return nil, err
	}
	check := api.CreateIntegrationInput{IntegrationType: new(api.IntegrationType("AWS_PROXY")), IntegrationUri: new(api.UriWithLengthBetween1And2048(v.URI)), PayloadFormatVersion: new(api.StringWithLengthBetween1And64(v.PayloadVersion)), ConnectionId: in.ConnectionId, ConnectionType: in.ConnectionType, CredentialsArn: in.CredentialsArn, ContentHandlingStrategy: in.ContentHandlingStrategy, IntegrationSubtype: in.IntegrationSubtype, IntegrationMethod: in.IntegrationMethod, PassthroughBehavior: in.PassthroughBehavior, RequestParameters: in.RequestParameters, RequestTemplates: in.RequestTemplates, ResponseParameters: in.ResponseParameters, TemplateSelectionExpression: in.TemplateSelectionExpression, TlsConfig: in.TlsConfig, TimeoutInMillis: in.TimeoutInMillis}
	if in.IntegrationType != nil {
		check.IntegrationType = in.IntegrationType
	}
	if in.IntegrationUri != nil {
		check.IntegrationUri = in.IntegrationUri
	}
	if in.PayloadFormatVersion != nil {
		check.PayloadFormatVersion = in.PayloadFormatVersion
	}
	if err := validateIntegration(&check, owner.ProtocolType); err != nil {
		return nil, err
	}
	if err := s.passInvocationRole(tx, value(in.CredentialsArn)); err != nil {
		return nil, err
	}
	if in.CredentialsArn != nil {
		v.CredentialsARN = value(in.CredentialsArn)
	}
	v.URI = value(check.IntegrationUri)
	v.PayloadVersion = value(check.PayloadFormatVersion)
	if in.Description != nil {
		v.Description = value(in.Description)
	}
	if in.TimeoutInMillis != nil {
		v.TimeoutMillis = int32(*in.TimeoutInMillis)
	}
	if err := tx.PutIntegration(v); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, owner.Key); err != nil {
		return nil, err
	}
	return new(api.UpdateIntegrationOutput(integrationOutput(v))), nil
}
