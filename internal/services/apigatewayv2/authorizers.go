package apigatewayv2

import (
	"net/url"
	"regexp"
	api "stackd/internal/awsapi/apigatewayv2"
	"stackd/internal/services/apigatewayexec"
	"strings"
)

func authorizerOutput(v AuthorizerRecord, protocol string) api.Authorizer {
	out := api.Authorizer{}
	text(&out.AuthorizerId, v.Key.ID)
	text(&out.Name, v.Name)
	if auth := v.LambdaAuthorizer; auth != nil {
		text(&out.AuthorizerType, auth.Type)
		text(&out.AuthorizerUri, v.URI)
		if auth.CredentialsARN != "" {
			text(&out.AuthorizerCredentialsArn, auth.CredentialsARN)
		}
		if protocol != "WEBSOCKET" {
			text(&out.AuthorizerPayloadFormatVersion, auth.PayloadVersion)
			out.AuthorizerResultTtlInSeconds = new(api.IntegerWithLengthBetween0And3600(auth.TTLSeconds))
			flag(&out.EnableSimpleResponses, auth.SimpleResponses)
		}
		if auth.ValidationExpression != "" {
			text(&out.IdentityValidationExpression, auth.ValidationExpression)
		}
		if len(auth.IdentitySources) > 0 {
			stringList(&out.IdentitySource, auth.IdentitySources)
		}
		return out
	}
	out.JwtConfiguration = &api.JWTConfiguration{}
	text(&out.AuthorizerType, "JWT")
	stringList(&out.IdentitySource, []string{"$request.header.Authorization"})
	text(&out.JwtConfiguration.Issuer, v.Issuer)
	stringList(&out.JwtConfiguration.Audience, v.Audiences)
	return out
}
func (s *Service) validateAuthorizer(in *api.CreateAuthorizerInput, protocol string) error {
	if value(in.Name) == "" {
		return bad("Name is required")
	}
	if protocol == "WEBSOCKET" {
		return validateWebSocketAuthorizer(in)
	}
	if value(in.AuthorizerType) == "REQUEST" {
		return validateLambdaAuthorizer(in)
	}
	if value(in.AuthorizerType) != "JWT" {
		return bad("Invalid authorizer type. Only JWT authorizer type is supported on HTTP protocol Apis.")
	}
	if in.AuthorizerCredentialsArn != nil || in.AuthorizerUri != nil || in.AuthorizerPayloadFormatVersion != nil || in.AuthorizerResultTtlInSeconds != nil || in.EnableSimpleResponses != nil || in.IdentityValidationExpression != nil {
		return unsupported("JWT authorizers do not support Lambda authorizer settings")
	}
	if len(in.IdentitySource) != 1 || !strings.EqualFold(string(in.IdentitySource[0]), "$request.header.Authorization") {
		return unsupported("JWT authorizers currently require the Authorization request header")
	}
	if in.JwtConfiguration == nil || len(in.JwtConfiguration.Audience) == 0 || len(in.JwtConfiguration.Audience) > 50 {
		return bad("JWT authorizers require an issuer and between 1 and 50 audiences")
	}
	issuer := value(in.JwtConfiguration.Issuer)
	u, err := url.Parse(issuer)
	local := false
	if err == nil && s.endpoint != "" {
		base, baseErr := url.Parse(s.endpoint)
		poolID := strings.TrimPrefix(u.Path, "/")
		local = baseErr == nil && u.Scheme == base.Scheme && u.Host == base.Host &&
			!strings.Contains(poolID, "/") && strings.Contains(poolID, "_")
	}
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" && !(local && u.Scheme == "http") {
		return bad("JWT issuer must be an HTTPS URL or the configured local OIDC issuer")
	}
	for _, a := range in.JwtConfiguration.Audience {
		if a == "" {
			return bad("JWT audience must not be empty")
		}
	}
	return nil
}

func authorizerFunctionARN(uri string) (string, error) {
	prefix, suffix, ok := strings.Cut(uri, ":lambda:path/2015-03-31/functions/")
	arn, invocation := strings.CutSuffix(suffix, "/invocations")
	parts := strings.Split(prefix, ":")
	if !ok || !invocation || len(parts) != 4 || parts[0] != "arn" || parts[1] == "" || parts[2] != "apigateway" || parts[3] == "" || !lambdaURI.MatchString(arn) {
		return "", bad("Invalid authorizer URI")
	}
	return arn, nil
}

func authorizerTTL(in *api.CreateAuthorizerInput) int32 {
	if in.AuthorizerResultTtlInSeconds == nil {
		return 300
	}
	return int32(*in.AuthorizerResultTtlInSeconds)
}

var authorizerRoleARN = regexp.MustCompile(`^arn:[a-z0-9-]+:iam::[0-9]{12}:role/([!-~]+/)?[A-Za-z0-9_+=,.@-]+$`)

func validateLambdaAuthorizer(in *api.CreateAuthorizerInput) error {
	if in.AuthorizerCredentialsArn != nil && !authorizerRoleARN.MatchString(value(in.AuthorizerCredentialsArn)) {
		return bad("Invalid role ARN")
	}
	version := value(in.AuthorizerPayloadFormatVersion)
	if version == "" {
		return bad("AuthorizerPayloadFormatVersion is a required parameter for REQUEST authorizer")
	}
	if version != "1.0" && version != "2.0" {
		return bad("AuthorizerPayloadFormatVersion " + version + " is not supported")
	}
	if version != "2.0" && boolean(in.EnableSimpleResponses) {
		return bad("EnableSimpleResponses can only be set for AuthorizerPayloadFormatVersion \"2.0\".")
	}
	ttl := authorizerTTL(in)
	if ttl < 0 || ttl > 3600 {
		return bad("Authorizer result TTL outside allowable range. TTL must be between 0 and 3600 seconds.")
	}
	if ttl > 0 && len(in.IdentitySource) == 0 {
		return bad("Identity source must be set if authorizer caching is enabled (TTL is greater than 0)")
	}
	for _, expression := range in.IdentitySource {
		source := string(expression)
		valid := false
		for _, prefix := range []string{"$request.header.", "$request.querystring.", "$stageVariables.", "$context."} {
			if name, ok := strings.CutPrefix(source, prefix); ok && name != "" && !strings.ContainsAny(name, " \t\r\n") {
				valid = true
				break
			}
		}
		if !valid {
			return bad("Invalid identity source expression: " + source + ". The source must be a request header, request querystring, stage variable or context parameter")
		}
	}
	if _, err := authorizerFunctionARN(value(in.AuthorizerUri)); err != nil {
		return err
	}
	if in.JwtConfiguration != nil || in.IdentityValidationExpression != nil {
		return bad("JWT configuration and identity validation expressions are not supported for HTTP REQUEST authorizers")
	}
	return nil
}

func authorizerRecord(key ResourceKey, in *api.CreateAuthorizerInput, protocol string) AuthorizerRecord {
	out := AuthorizerRecord{Key: key, Name: value(in.Name)}
	if value(in.AuthorizerType) == "REQUEST" {
		out.URI = value(in.AuthorizerUri)
		arn, _ := authorizerFunctionARN(out.URI) // The validated URI is retained for control-plane output.
		out.LambdaAuthorizer = &apigatewayexec.LambdaAuthorizer{ID: key.ID, Type: "REQUEST", FunctionARN: arn, CredentialsARN: value(in.AuthorizerCredentialsArn), PayloadVersion: value(in.AuthorizerPayloadFormatVersion), IdentitySources: stringsOf(in.IdentitySource), TTLSeconds: authorizerTTL(in), SimpleResponses: boolean(in.EnableSimpleResponses)}
		if protocol == "WEBSOCKET" {
			out.LambdaAuthorizer.TTLSeconds = 0
			out.LambdaAuthorizer.ValidationExpression = value(in.IdentityValidationExpression)
			if len(out.LambdaAuthorizer.IdentitySources) == 1 && out.LambdaAuthorizer.IdentitySources[0] == "" {
				out.LambdaAuthorizer.IdentitySources = nil
			}
		}
	} else {
		out.Issuer = value(in.JwtConfiguration.Issuer)
		out.Audiences = stringsOf(in.JwtConfiguration.Audience)
	}
	return out
}
func (s *Service) createAuthorizer(tx Transaction, in *api.CreateAuthorizerInput) (*api.CreateAuthorizerOutput, error) {
	owner, err := s.ownedAPI(tx, "POST", value(in.ApiId), "/authorizers")
	if err != nil {
		return nil, err
	}
	if err := s.validateAuthorizer(in, owner.ProtocolType); err != nil {
		return nil, err
	}
	if err := s.passInvocationRole(tx, value(in.AuthorizerCredentialsArn)); err != nil {
		return nil, err
	}
	authorizers, err := tx.Authorizers(owner.Key)
	if err != nil {
		return nil, err
	}
	if len(authorizers) >= 10 {
		return nil, failure("ConflictException", "Maximum number of Authorizers for this API has been reached. Please contact AWS if you need additional Authorizers.", 429)
	}
	id, err := controlID()
	if err != nil {
		return nil, err
	}
	v := authorizerRecord(ResourceKey{owner.Key, id}, in, owner.ProtocolType)
	if err := tx.PutAuthorizer(v); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, owner.Key); err != nil {
		return nil, err
	}
	return new(api.CreateAuthorizerOutput(authorizerOutput(v, owner.ProtocolType))), nil
}
func (s *Service) updateAuthorizer(tx Transaction, in *api.UpdateAuthorizerInput) (*api.UpdateAuthorizerOutput, error) {
	owner, err := s.ownedAPI(tx, "PATCH", value(in.ApiId), "/authorizers/"+value(in.AuthorizerId))
	if err != nil {
		return nil, err
	}
	v, err := tx.Authorizer(ResourceKey{owner.Key, value(in.AuthorizerId)})
	if err != nil {
		return nil, err
	}
	old := authorizerOutput(v, owner.ProtocolType)
	check := api.CreateAuthorizerInput{Name: old.Name, AuthorizerType: old.AuthorizerType, IdentitySource: old.IdentitySource, JwtConfiguration: old.JwtConfiguration, AuthorizerCredentialsArn: old.AuthorizerCredentialsArn, AuthorizerUri: old.AuthorizerUri, AuthorizerPayloadFormatVersion: old.AuthorizerPayloadFormatVersion, AuthorizerResultTtlInSeconds: old.AuthorizerResultTtlInSeconds, EnableSimpleResponses: old.EnableSimpleResponses, IdentityValidationExpression: old.IdentityValidationExpression}
	if in.AuthorizerCredentialsArn != nil {
		check.AuthorizerCredentialsArn = in.AuthorizerCredentialsArn
		if value(in.AuthorizerCredentialsArn) == "" {
			check.AuthorizerCredentialsArn = nil
		}
	}
	if in.Name != nil {
		check.Name = in.Name
	}
	if in.AuthorizerType != nil {
		check.AuthorizerType = in.AuthorizerType
	}
	if in.AuthorizerUri != nil {
		check.AuthorizerUri = in.AuthorizerUri
	}
	if in.AuthorizerPayloadFormatVersion != nil && (owner.ProtocolType != "WEBSOCKET" || value(in.AuthorizerPayloadFormatVersion) != "") {
		check.AuthorizerPayloadFormatVersion = in.AuthorizerPayloadFormatVersion
	}
	if in.AuthorizerResultTtlInSeconds != nil {
		check.AuthorizerResultTtlInSeconds = in.AuthorizerResultTtlInSeconds
	}
	if in.EnableSimpleResponses != nil {
		check.EnableSimpleResponses = in.EnableSimpleResponses
	}
	if in.IdentitySource != nil {
		check.IdentitySource = in.IdentitySource
	}
	if in.IdentityValidationExpression != nil {
		check.IdentityValidationExpression = in.IdentityValidationExpression
		if owner.ProtocolType == "WEBSOCKET" && value(in.IdentityValidationExpression) == "" {
			check.IdentityValidationExpression = nil
		}
	}
	if in.JwtConfiguration != nil {
		if check.JwtConfiguration == nil {
			check.JwtConfiguration = &api.JWTConfiguration{}
		}
		if in.JwtConfiguration.Issuer != nil {
			check.JwtConfiguration.Issuer = in.JwtConfiguration.Issuer
		}
		if in.JwtConfiguration.Audience != nil {
			check.JwtConfiguration.Audience = in.JwtConfiguration.Audience
		}
	}
	if err := s.validateAuthorizer(&check, owner.ProtocolType); err != nil {
		return nil, err
	}
	if err := s.passInvocationRole(tx, value(in.AuthorizerCredentialsArn)); err != nil {
		return nil, err
	}
	v = authorizerRecord(v.Key, &check, owner.ProtocolType)
	if err := tx.PutAuthorizer(v); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, owner.Key); err != nil {
		return nil, err
	}
	return new(api.UpdateAuthorizerOutput(authorizerOutput(v, owner.ProtocolType))), nil
}
