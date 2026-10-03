package integrations

import (
	"context"
	"errors"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awscatalog"
	"stackd/internal/services/cognitoidp"
)

// SSOCognitoLogin is an explicitly configured local Identity Center identity
// source. Cognito owns passwords, user status and actual login tokens; Identity
// Store owns the separately provisioned directory username and memberships.
type SSOCognitoLogin struct {
	Cognito  *cognitoidp.Service
	ClientID string
}

func (a SSOCognitoLogin) Authenticate(ctx context.Context, username, password string) (string, error) {
	if a.Cognito == nil || a.ClientID == "" {
		return "", errors.New("Identity Center Cognito identity source is not configured")
	}
	model, _ := awscatalog.LookupService("cognitoidp")
	op, _ := model.Operation("InitiateAuth")
	out, rejected := a.Cognito.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: &api.InitiateAuthInput{AuthFlow: new(api.AuthFlowType("USER_PASSWORD_AUTH")), ClientId: new(api.ClientIdType(a.ClientID)), AuthParameters: api.AuthParametersType{"USERNAME": api.StringType(username), "PASSWORD": api.StringType(password)}}})
	if rejected != nil {
		return "", rejected
	}
	auth, ok := out.(*api.InitiateAuthOutput)
	if !ok || auth.AuthenticationResult == nil || auth.AuthenticationResult.AccessToken == nil {
		return "", errors.New("Identity Center requires completed Cognito password authentication")
	}
	op, _ = model.Operation("GetUser")
	out, rejected = a.Cognito.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: &api.GetUserInput{AccessToken: auth.AuthenticationResult.AccessToken}})
	if rejected != nil {
		return "", rejected
	}
	user, ok := out.(*api.GetUserOutput)
	if !ok || user.Username == nil {
		return "", errors.New("cognito did not return a canonical username")
	}
	return string(*user.Username), nil
}
