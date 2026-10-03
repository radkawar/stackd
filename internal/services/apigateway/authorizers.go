package apigateway

import (
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/services/apigatewayexec"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/dlclark/regexp2"
)

func authorizerOutput(v AuthorizerRecord) *api.Authorizer {
	out := &api.Authorizer{Id: ptr(v.Key.AuthorizerID), Name: ptr(v.Name), AuthType: ptr(v.AuthType)}
	if a := v.LambdaAuthorizer; a != nil {
		out.Type = new(api.AuthorizerType(a.Type))
		out.AuthorizerUri = ptr(v.URI)
		out.AuthorizerCredentials = optional(a.CredentialsARN)
		out.IdentitySource = optional(strings.Join(a.IdentitySources, ","))
		out.IdentityValidationExpression = optional(a.ValidationExpression)
		out.AuthorizerResultTtlInSeconds = new(api.NullableInteger(a.TTLSeconds))
		return out
	}
	out.Type = new(api.AuthorizerTypeCOGNITO_USER_POOLS)
	out.IdentitySource = ptr("method.request.header.Authorization")
	out.ProviderARNs = make(api.ListOfARNs, len(v.ProviderARNs))
	for i, p := range v.ProviderARNs {
		out.ProviderARNs[i] = api.ProviderARN(p)
	}
	return out
}

func identitySources(value string) []string {
	if value == "" {
		return nil
	}
	sources := strings.Split(value, ",")
	for i := range sources {
		sources[i] = strings.TrimSpace(sources[i])
	}
	return sources
}

func validIdentitySource(source, prefix string) bool {
	return strings.HasPrefix(source, prefix) && len(source) > len(prefix) && !strings.ContainsAny(source[len(prefix):], " \t\r\n,")
}

func validateAuthorizer(row *AuthorizerRecord) error {
	if strings.TrimSpace(row.Name) == "" || len(row.Name) > 128 {
		return bad("Invalid authorizer name")
	}
	if a := row.LambdaAuthorizer; a != nil {
		if a.Type != "TOKEN" && a.Type != "REQUEST" {
			return bad("Invalid authorizer type")
		}
		if len(row.ProviderARNs) != 0 {
			return bad("Provider ARNs are only supported for Cognito authorizers")
		}
		arn, err := functionARN(row.URI, row.Key.Scope)
		if err != nil {
			return err
		}
		a.ID, a.FunctionARN, a.PayloadVersion = row.Key.AuthorizerID, arn, "1.0"
		if a.TTLSeconds < 0 || a.TTLSeconds > 3600 {
			return bad("Authorizer result TTL must be between 0 and 3600 seconds")
		}
		if a.Type == "TOKEN" {
			if len(a.IdentitySources) != 1 || !validIdentitySource(a.IdentitySources[0], "method.request.header.") {
				return bad("TOKEN authorizers require one method request header identity source")
			}
			if _, err := regexp2.Compile(a.ValidationExpression, regexp2.None); err != nil {
				return bad("Invalid identity validation expression")
			}
		} else {
			if a.ValidationExpression != "" {
				return unsupported("REQUEST authorizer identity validation expression")
			}
			if a.TTLSeconds > 0 && len(a.IdentitySources) == 0 {
				return bad("Cached REQUEST authorizers require an identity source")
			}
			for _, source := range a.IdentitySources {
				if !validIdentitySource(source, "method.request.header.") && !validIdentitySource(source, "method.request.querystring.") && !validIdentitySource(source, "stageVariables.") && !validIdentitySource(source, "context.") {
					return bad("Invalid REQUEST authorizer identity source")
				}
			}
		}
		return nil
	}
	if row.URI != "" {
		return unsupported("Lambda URI on a Cognito authorizer")
	}
	if len(row.ProviderARNs) == 0 || len(row.ProviderARNs) > 1000 {
		return bad("At least one Cognito user pool is required")
	}
	for _, arn := range row.ProviderARNs {
		parts := strings.SplitN(arn, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] != row.Key.Partition || parts[2] != "cognito-idp" || parts[3] == "" || len(parts[4]) != 12 || !strings.HasPrefix(parts[5], "userpool/"+parts[3]+"_") {
			return bad("Invalid Cognito user pool ARN")
		}
		for _, c := range parts[4] {
			if c < '0' || c > '9' {
				return bad("Invalid Cognito user pool account")
			}
		}
	}
	return nil
}

func (s *Service) passCredentials(tx Transaction, credentials string) error {
	if credentials == "" {
		return nil
	}
	parsed, err := arn.Parse(credentials)
	if err != nil || parsed.Partition == "" || parsed.Service == "" || parsed.Resource == "" {
		return bad("Invalid ARN specified in the request")
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(tx.Context(), authorization.Request{
		Action: "iam:PassRole", ResourceARN: credentials, ResourceAccountID: parsed.AccountID,
		Context: map[string][]string{"iam:PassedToService": {"apigateway.amazonaws.com"}}, EvaluationTime: &now,
	}); rejected != nil {
		return rejected
	}
	return nil
}

func (s *Service) createAuthorizer(tx Transaction, in *api.CreateAuthorizerRequest) (*api.Authorizer, error) {
	owner, err := s.api(tx, value(in.RestApiId), "POST", "/authorizers")
	if err != nil {
		return nil, err
	}
	kind := value(in.Type)
	if kind != "COGNITO_USER_POOLS" && kind != "TOKEN" && kind != "REQUEST" {
		return nil, bad("Invalid authorizer type")
	}
	if kind == "COGNITO_USER_POOLS" && value(in.AuthorizerCredentials) != "" {
		return nil, unsupported("Lambda invocation credentials on a Cognito authorizer")
	}
	if kind == "COGNITO_USER_POOLS" && (value(in.IdentitySource) != "method.request.header.Authorization" || value(in.IdentityValidationExpression) != "" || value(in.AuthorizerUri) != "" || in.AuthorizerResultTtlInSeconds != nil) {
		return nil, unsupported("Cognito custom identity source, validation or caching")
	}
	rows, err := tx.Authorizers(owner.Key)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		if v.Name == value(in.Name) {
			return nil, conflict("Authorizer name already exists")
		}
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	authType := value(in.AuthType)
	if authType == "" {
		authType = "cognito_user_pools"
		if kind != "COGNITO_USER_POOLS" {
			authType = "custom"
		}
	}
	row := AuthorizerRecord{Key: AuthorizerKey{APIKey: owner.Key, AuthorizerID: id}, Name: value(in.Name), AuthType: authType, URI: value(in.AuthorizerUri), ProviderARNs: stringsIn(in.ProviderARNs)}
	if kind != "COGNITO_USER_POOLS" {
		ttl := int32(300)
		if in.AuthorizerResultTtlInSeconds != nil {
			ttl = int32(*in.AuthorizerResultTtlInSeconds)
		}
		row.LambdaAuthorizer = &apigatewayexec.LambdaAuthorizer{Type: kind, CredentialsARN: value(in.AuthorizerCredentials), IdentitySources: identitySources(value(in.IdentitySource)), ValidationExpression: value(in.IdentityValidationExpression), TTLSeconds: ttl}
	}
	if err := validateAuthorizer(&row); err != nil {
		return nil, err
	}
	if err := s.passCredentials(tx, value(in.AuthorizerCredentials)); err != nil {
		return nil, err
	}
	if err := tx.PutAuthorizer(row); err != nil {
		return nil, err
	}
	return authorizerOutput(row), nil
}
func (s *Service) getAuthorizer(tx Transaction, in *api.GetAuthorizerRequest) (*api.Authorizer, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", "/authorizers/"+value(in.AuthorizerId))
	if err != nil {
		return nil, err
	}
	row, err := tx.Authorizer(AuthorizerKey{APIKey: owner.Key, AuthorizerID: value(in.AuthorizerId)})
	if err != nil {
		return nil, err
	}
	return authorizerOutput(row), nil
}
func (s *Service) getAuthorizers(tx Transaction, in *api.GetAuthorizersRequest) (*api.Authorizers, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", "/authorizers")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Authorizers(owner.Key)
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, owner.Key.Scope, "authorizers/"+owner.Key.ID, in.Limit, in.Position, func(v AuthorizerRecord) string { return v.Key.AuthorizerID })
	if err != nil {
		return nil, err
	}
	out := &api.Authorizers{Items: api.ListOfAuthorizer{}, Position: next}
	for _, v := range rows {
		out.Items = append(out.Items, *authorizerOutput(v))
	}
	return out, nil
}
func (s *Service) updateAuthorizer(tx Transaction, in *api.UpdateAuthorizerRequest) (*api.Authorizer, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PATCH", "/authorizers/"+value(in.AuthorizerId))
	if err != nil {
		return nil, err
	}
	row, err := tx.Authorizer(AuthorizerKey{APIKey: owner.Key, AuthorizerID: value(in.AuthorizerId)})
	if err != nil {
		return nil, err
	}
	for _, p := range in.PatchOperations {
		path := value(p.Path)
		switch {
		case path == "/name":
			err = replace(p, &row.Name)
		case path == "/authType":
			err = replace(p, &row.AuthType)
		case path == "/identitySource":
			if row.LambdaAuthorizer == nil {
				v := "method.request.header.Authorization"
				err = patchString(p, &v, "add", "replace", "remove")
				if err == nil && v != "method.request.header.Authorization" {
					err = unsupported("Cognito custom identity source")
				}
			} else {
				v := strings.Join(row.LambdaAuthorizer.IdentitySources, ",")
				err = patchString(p, &v, "add", "replace", "remove")
				row.LambdaAuthorizer.IdentitySources = identitySources(v)
			}
		case path == "/type":
			v := "COGNITO_USER_POOLS"
			if row.LambdaAuthorizer != nil {
				v = row.LambdaAuthorizer.Type
			}
			previous := v
			err = replace(p, &v)
			if err == nil && v != previous {
				if row.LambdaAuthorizer != nil && (v == "TOKEN" || v == "REQUEST") {
					row.LambdaAuthorizer.Type = v
				} else {
					err = unsupported("conversion between Cognito and Lambda authorizers")
				}
			}
		case path == "/authorizerUri":
			err = patchString(p, &row.URI, "add", "replace", "remove")
		case path == "/identityValidationExpression" && row.LambdaAuthorizer != nil:
			err = patchString(p, &row.LambdaAuthorizer.ValidationExpression, "add", "replace", "remove")
		case path == "/authorizerResultTtlInSeconds" && row.LambdaAuthorizer != nil:
			v := ""
			err = replace(p, &v)
			if err == nil {
				var ttl int64
				ttl, err = strconv.ParseInt(v, 10, 32)
				if err != nil {
					err = bad("Invalid authorizer result TTL")
				} else {
					row.LambdaAuthorizer.TTLSeconds = int32(ttl)
				}
			}
		case path == "/authorizerCredentials":
			credentials := ""
			err = patchString(p, &credentials, "add", "replace")
			if err == nil {
				if row.LambdaAuthorizer == nil {
					if credentials != "" {
						err = unsupported("Lambda invocation credentials on a Cognito authorizer")
					}
				} else if err = s.passCredentials(tx, credentials); err == nil {
					row.LambdaAuthorizer.CredentialsARN = credentials
				}
			}
		case path == "/providerARNs" || strings.HasPrefix(path, "/providerARNs/"):
			err = patchList(p, "/providerARNs", &row.ProviderARNs)
		default:
			err = unsupported("authorizer patch path " + path)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := validateAuthorizer(&row); err != nil {
		return nil, err
	}
	rows, err := tx.Authorizers(owner.Key)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		if v.Key != row.Key && v.Name == row.Name {
			return nil, conflict("Authorizer name already exists")
		}
	}
	if err := tx.PutAuthorizer(row); err != nil {
		return nil, err
	}
	return authorizerOutput(row), nil
}
func (s *Service) deleteAuthorizer(tx Transaction, in *api.DeleteAuthorizerRequest) (*api.Unit, error) {
	owner, err := s.api(tx, value(in.RestApiId), "DELETE", "/authorizers/"+value(in.AuthorizerId))
	if err != nil {
		return nil, err
	}
	key := AuthorizerKey{APIKey: owner.Key, AuthorizerID: value(in.AuthorizerId)}
	if _, err := tx.Authorizer(key); err != nil {
		return nil, err
	}
	methods, err := tx.Methods(owner.Key)
	if err != nil {
		return nil, err
	}
	for _, m := range methods {
		if m.AuthorizerID == key.AuthorizerID {
			return nil, conflict("Authorizer is referenced by a method")
		}
	}
	return &api.Unit{}, tx.DeleteAuthorizer(key)
}
