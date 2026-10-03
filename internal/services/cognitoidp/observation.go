package cognitoidp

import (
	"context"
	"encoding/json"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

type cognitoAuditKey struct{}
type cognitoAudit struct {
	pool         PoolKey
	sub          string
	refreshRetry bool
}

// Resource ownership completes audit scope, never public caller authority.
func notePool(ctx context.Context, key PoolKey) {
	if audit, ok := ctx.Value(cognitoAuditKey{}).(*cognitoAudit); ok {
		audit.pool = key
	}
}
func noteUser(ctx context.Context, user UserRecord) {
	if audit, ok := ctx.Value(cognitoAuditKey{}).(*cognitoAudit); ok {
		audit.pool = user.Key.PoolKey
		audit.sub = userAttribute(user, "sub")
	}
}

func noteRefreshRetry(ctx context.Context) {
	if audit, ok := ctx.Value(cognitoAuditKey{}).(*cognitoAudit); ok {
		audit.refreshRetry = true
	}
}

var cognitoRequestProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"ClientId":           {Mode: awsapi.IncludeField},
	"Username":           {Mode: awsapi.RedactValueField},
	"Password":           {Mode: awsapi.RedactValueField},
	"TemporaryPassword":  {Mode: awsapi.RedactValueField},
	"PreviousPassword":   {Mode: awsapi.RedactValueField},
	"ProposedPassword":   {Mode: awsapi.RedactValueField},
	"ConfirmationCode":   {Mode: awsapi.RedactValueField},
	"Code":               {Mode: awsapi.RedactValueField},
	"AccessToken":        {Mode: awsapi.RedactValueField},
	"RefreshToken":       {Mode: awsapi.RedactValueField},
	"Token":              {Mode: awsapi.RedactValueField},
	"ClientSecret":       {Mode: awsapi.RedactValueField},
	"SecretHash":         {Mode: awsapi.RedactValueField},
	"Session":            {Mode: awsapi.RedactValueField},
	"AuthParameters":     {Mode: awsapi.RedactValueField},
	"ChallengeResponses": {Mode: awsapi.RedactValueField},
	"UserAttributes":     {Mode: awsapi.RedactValueField},
	"ValidationData":     {Mode: awsapi.RedactValueField},
}}

var cognitoResponseProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Session":                           {Mode: awsapi.RedactValueField},
	"ChallengeParameters":               {Mode: awsapi.RedactValueField},
	"AuthenticationResult.AccessToken":  {Mode: awsapi.RedactValueField},
	"AuthenticationResult.IdToken":      {Mode: awsapi.RedactValueField},
	"AuthenticationResult.RefreshToken": {Mode: awsapi.RedactValueField},
	"User.Username":                     {Mode: awsapi.RedactValueField},
	"User.Attributes":                   {Mode: awsapi.RedactValueField},
	"User.UserCreateDate":               {TimeLayout: "Jan 2, 2006, 3:04:05 PM"},
	"User.UserLastModifiedDate":         {TimeLayout: "Jan 2, 2006, 3:04:05 PM"},
	"UserPool.CreationDate":             {TimeLayout: time.RFC3339},
	"UserPool.LastModifiedDate":         {TimeLayout: time.RFC3339},
	"UserPoolClient.ClientId":           {Mode: awsapi.IncludeField},
	"UserPoolClient.ClientSecret":       {Mode: awsapi.RedactValueField},
	"UserPoolClient.CreationDate":       {TimeLayout: "Jan 2, 2006, 3:04:05 PM"},
	"UserPoolClient.LastModifiedDate":   {TimeLayout: "Jan 2, 2006, 3:04:05 PM"},
	"Group.CreationDate":                {TimeLayout: time.RFC3339},
	"Group.LastModifiedDate":            {TimeLayout: time.RFC3339},
}}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	scope := scopeFor(ctx)
	audit, _ := ctx.Value(cognitoAuditKey{}).(*cognitoAudit)
	if audit != nil && audit.pool.AccountID != "" {
		scope = audit.pool.Scope
	}
	// An unknown public client/token has no recipient account to record against.
	if scope.AccountID == "" {
		return nil
	}
	model, _ := awscatalog.LookupService("cognitoidp")
	operation, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, Request: cognitoRequestProjection}
	switch action {
	case "DescribeUserPool", "DescribeUserPoolClient", "ListUserPools", "ListUserPoolClients", "ListUsers", "ListTagsForResource", "AdminGetUser", "GetUser", "GetGroup", "ListGroups", "AdminListGroupsForUser", "ListUsersInGroup":
		projection.ReadOnly = true
	case "CreateUserPool", "CreateUserPoolClient", "UpdateUserPoolClient", "AdminCreateUser", "InitiateAuth", "AdminInitiateAuth", "RespondToAuthChallenge", "AdminRespondToAuthChallenge", "GetTokensFromRefreshToken", "SignUp", "CreateGroup", "UpdateGroup":
		projection.Response = &cognitoResponseProjection
	}
	if rejected != nil {
		switch rejected.Code {
		case "AccessDeniedException", "FeatureUnavailableInTierException", "TierChangeNotAllowedException":
			in = nil
		}
	}
	auditInput, err := cognitoAuditInput(ctx, in)
	if err != nil {
		return err
	}
	call, err := projection.Call(model, operation, auditInput, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	if call.ErrorCode == "AccessDeniedException" {
		call.ErrorCode = "AccessDenied"
	}
	if metadata := awsctx.FromContext(ctx); metadata.PrincipalARN == "" && metadata.ServicePrincipal.Name == "" {
		call.Identity = journal.APIIdentity{Type: "Unknown", PrincipalID: "Anonymous"}
	}
	if audit != nil && audit.sub != "" {
		data := struct {
			Sub                       string `json:"sub"`
			RefreshTokenReuseDetected string `json:"refreshTokenReuseDetected,omitempty"`
			RefreshTokenRotationRetry string `json:"refreshTokenRotationRetry,omitempty"`
		}{Sub: audit.sub}
		if rejected != nil && rejected.Code == "RefreshTokenReuseException" {
			data.RefreshTokenReuseDetected = "true"
		}
		if rejected == nil && audit.refreshRetry {
			data.RefreshTokenRotationRetry = "true"
		}
		call.AdditionalEventData, err = json.Marshal(data)
		if err != nil {
			return err
		}
	}
	if action == "RevokeToken" && rejected != nil && (rejected.Code == "UnauthorizedException" || rejected.Code == "UnsupportedOperationException") {
		call.ErrorCode = "UnknownError"
		call.ErrorMessage = "An unknown error occurred"
	}
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}

// Native audit distinguishes omitted optional integers from Smithy defaults,
// but includes the Java primitive boolean defaults.
func cognitoAuditInput(ctx context.Context, input any) (any, error) {
	var fields map[string]json.RawMessage
	switch input.(type) {
	case *api.CreateUserPoolClientRequest, *api.UpdateUserPoolClientRequest:
		if request, ok := awsapi.FromContext(ctx); ok && len(request.Body) != 0 {
			if err := json.Unmarshal(request.Body, &fields); err != nil {
				return nil, err
			}
		}
	}
	switch in := input.(type) {
	case *api.AdminCreateUserRequest:
		copy := *in
		if copy.ForceAliasCreation == nil {
			copy.ForceAliasCreation = new(api.ForceAliasCreation(false))
		}
		return &copy, nil
	case *api.CreateUserPoolClientRequest:
		copy := *in
		if fields != nil && fields["RefreshTokenValidity"] == nil {
			copy.RefreshTokenValidity = nil
		}
		if copy.GenerateSecret == nil {
			copy.GenerateSecret = new(api.GenerateSecret(false))
		}
		if copy.AllowedOAuthFlowsUserPoolClient == nil {
			copy.AllowedOAuthFlowsUserPoolClient = new(api.BooleanType(false))
		}
		return &copy, nil
	case *api.UpdateUserPoolClientRequest:
		copy := *in
		if fields != nil && fields["RefreshTokenValidity"] == nil {
			copy.RefreshTokenValidity = nil
		}
		if copy.AllowedOAuthFlowsUserPoolClient == nil {
			copy.AllowedOAuthFlowsUserPoolClient = new(api.BooleanType(false))
		}
		return &copy, nil
	case *api.UpdateUserPoolRequest:
		copy := *in
		if copy.AdminCreateUserConfig != nil {
			config := *copy.AdminCreateUserConfig
			if config.UnusedAccountValidityDays == nil {
				config.UnusedAccountValidityDays = new(api.AdminCreateUserUnusedAccountValidityDaysType(0))
			}
			copy.AdminCreateUserConfig = &config
		}
		return &copy, nil
	}
	return input, nil
}

func (s *Service) RequestErrorInput(operation awscatalog.Operation, request awsapi.Request) any {
	if s.recorder == nil {
		return nil
	}
	input, err := api.NewInput(string(operation.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("cognitoidp")
	if err := awsapi.BindHTTP(model, operation, request, input); err != nil {
		return nil
	}
	return input
}
