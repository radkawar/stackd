package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	idptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	"stackd"
	"stackd/clock"
)

// Guard's local account and Region. These are local regressions for the
// reported regionless-endpoint login failure, not native AWS captures.
const (
	cognitoGuardAccount  = "000000000000"
	cognitoGuardRegion   = "us-east-2"
	cognitoGuardPassword = "Guard-local-password-16!"
)

func cognitoGuardPublic(t *testing.T, idp *cognitoidentityprovider.Client) *cognitoidentityprovider.Client {
	t.Helper()
	options := idp.Options()
	// The SDK sends InitiateAuth unsigned. A custom endpoint names no Region,
	// so the SDK Region deliberately differs from the client's.
	options.Region = "eu-west-1"
	options.Credentials = aws.AnonymousCredentials{}
	return cognitoidentityprovider.New(options)
}

func cognitoGuardSigned(clients cloudClients, idp *cognitoidentityprovider.Client) *cognitoidentityprovider.Client {
	options := idp.Options()
	// InitiateAuth is IAM-free and normally unsigned in the SDK. Reuse the
	// native replay transport to exercise CLI-style SigV4 with SDK inputs.
	options.HTTPClient = &cognitoReplayTransport{
		client: clients.server.Client(), mode: "signed", region: options.Region,
		identity: aws.Credentials{AccessKeyID: cognitoGuardAccount, SecretAccessKey: "test"},
	}
	return cognitoidentityprovider.New(options)
}

// cognitoGuardPool creates the Guard pool/client shape and a confirmed user.
func cognitoGuardPool(t *testing.T, idp *cognitoidentityprovider.Client, email, password string) (string, string) {
	t.Helper()
	pool, err := idp.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{
		PoolName: aws.String("guard-users"), UsernameAttributes: []idptypes.UsernameAttributeType{idptypes.UsernameAttributeTypeEmail},
		AutoVerifiedAttributes: []idptypes.VerifiedAttributeType{idptypes.VerifiedAttributeTypeEmail},
		Policies:               &idptypes.UserPoolPolicyType{PasswordPolicy: &idptypes.PasswordPolicyType{MinimumLength: aws.Int32(16), RequireLowercase: true, RequireUppercase: true, RequireNumbers: true, RequireSymbols: true}},
		Schema:                 []idptypes.SchemaAttributeType{{Name: aws.String("guard_role"), AttributeDataType: idptypes.AttributeDataTypeString, Mutable: aws.Bool(true)}},
		AdminCreateUserConfig:  &idptypes.AdminCreateUserConfigType{AllowAdminCreateUserOnly: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := idp.CreateUserPoolClient(t.Context(), &cognitoidentityprovider.CreateUserPoolClientInput{
		UserPoolId: pool.UserPool.Id, ClientName: aws.String("guard-ui"), GenerateSecret: false,
		ExplicitAuthFlows:   []idptypes.ExplicitAuthFlowsType{idptypes.ExplicitAuthFlowsTypeAllowUserSrpAuth, idptypes.ExplicitAuthFlowsTypeAllowUserPasswordAuth, idptypes.ExplicitAuthFlowsTypeAllowRefreshTokenAuth, idptypes.ExplicitAuthFlowsTypeAllowAdminUserPasswordAuth},
		AccessTokenValidity: aws.Int32(1), IdTokenValidity: aws.Int32(1), RefreshTokenValidity: 30,
		TokenValidityUnits:         &idptypes.TokenValidityUnitsType{AccessToken: idptypes.TimeUnitsTypeHours, IdToken: idptypes.TimeUnitsTypeHours, RefreshToken: idptypes.TimeUnitsTypeDays},
		PreventUserExistenceErrors: idptypes.PreventUserExistenceErrorTypesEnabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	poolID := aws.ToString(pool.UserPool.Id)
	cognitoGuardUser(t, idp, poolID, email, password)
	return poolID, aws.ToString(client.UserPoolClient.ClientId)
}

func cognitoGuardUser(t *testing.T, idp *cognitoidentityprovider.Client, poolID, email, password string) {
	t.Helper()
	if _, err := idp.AdminCreateUser(t.Context(), &cognitoidentityprovider.AdminCreateUserInput{
		UserPoolId: aws.String(poolID), Username: aws.String(email), MessageAction: idptypes.MessageActionTypeSuppress,
		UserAttributes: []idptypes.AttributeType{{Name: aws.String("email"), Value: aws.String(email)}, {Name: aws.String("email_verified"), Value: aws.String("true")}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := idp.AdminSetUserPassword(t.Context(), &cognitoidentityprovider.AdminSetUserPasswordInput{UserPoolId: aws.String(poolID), Username: aws.String(email), Password: aws.String(password), Permanent: true}); err != nil {
		t.Fatal(err)
	}
}

func cognitoGuardLogin(t *testing.T, clients cloudClients, public *cognitoidentityprovider.Client, poolID, clientID, email, password string) *idptypes.AuthenticationResultType {
	t.Helper()
	login, err := public.InitiateAuth(t.Context(), &cognitoidentityprovider.InitiateAuthInput{ClientId: aws.String(clientID), AuthFlow: idptypes.AuthFlowTypeUserPasswordAuth, AuthParameters: map[string]string{"USERNAME": email, "PASSWORD": password}})
	if err != nil || login.AuthenticationResult == nil || aws.ToString(login.AuthenticationResult.RefreshToken) == "" {
		t.Fatalf("password login through client %s: %+v, %v", clientID, login, err)
	}
	claims, idKid := cognitoVerifiedJWT(t, clients, aws.ToString(login.AuthenticationResult.IdToken))
	if claims["aud"] != clientID || claims["email"] != email || claims["token_use"] != "id" || !strings.HasSuffix(claims["iss"].(string), "/"+poolID) {
		t.Fatalf("ID token does not name its client, user and pool: %+v", claims)
	}
	access, accessKid := cognitoVerifiedJWT(t, clients, aws.ToString(login.AuthenticationResult.AccessToken))
	if access["client_id"] != clientID || access["token_use"] != "access" || access["iss"] != claims["iss"] || access["sub"] != claims["sub"] || accessKid == idKid {
		t.Fatalf("access token does not name its client, user and distinct signing key: %+v", access)
	}
	user, err := public.GetUser(t.Context(), &cognitoidentityprovider.GetUserInput{AccessToken: login.AuthenticationResult.AccessToken})
	if err != nil {
		t.Fatalf("access token from a regionless endpoint was not resolved: %v", err)
	}
	for _, attribute := range user.UserAttributes {
		if aws.ToString(attribute.Name) == "email" && aws.ToString(attribute.Value) != email {
			t.Fatalf("access token resolved another user: %+v", user.UserAttributes)
		}
	}
	return login.AuthenticationResult
}

// cognitoSignedInitiateAuth sends a SigV4-signed InitiateAuth, as the AWS CLI
// does with credentials, scoped to region.
func cognitoSignedInitiateAuth(t *testing.T, clients cloudClients, region, clientID, email, password string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"ClientId": clientID, "AuthFlow": "USER_PASSWORD_AUTH", "AuthParameters": map[string]string{"USERNAME": email, "PASSWORD": password}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, clients.server.URL+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("X-Amz-Target", "AWSCognitoIdentityProviderService.InitiateAuth")
	sum := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: cognitoGuardAccount, SecretAccessKey: "test"}, request, hex.EncodeToString(sum[:]), "cognito-idp", region, time.Now()); err != nil {
		t.Fatal(err)
	}
	response, err := clients.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	out := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, out
}

func TestCognitoRegionlessEndpointPasswordLogin(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: cognitoGuardAccount}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			idp := cognitoWorkflowClient(clients, cognitoGuardRegion, cognitoGuardAccount, "test")
			const email = "analyst@guard.example"
			poolID, clientID := cognitoGuardPool(t, idp, email, cognitoGuardPassword)
			cognitoGuardLogin(t, clients, cognitoGuardPublic(t, idp), poolID, clientID, email, cognitoGuardPassword)

			// The same email in another account's pool is a different user.
			other := cognitoWorkflowClient(clients, cognitoGuardRegion, "222222222222", "test")
			const otherPassword = "Other-account-password-16!"
			otherPool, otherClient := cognitoGuardPool(t, other, email, otherPassword)
			cognitoGuardLogin(t, clients, cognitoGuardPublic(t, other), otherPool, otherClient, email, otherPassword)
			for _, attempt := range []struct{ client, password string }{{clientID, otherPassword}, {otherClient, cognitoGuardPassword}} {
				_, err := cognitoGuardPublic(t, idp).InitiateAuth(t.Context(), &cognitoidentityprovider.InitiateAuthInput{ClientId: aws.String(attempt.client), AuthFlow: idptypes.AuthFlowTypeUserPasswordAuth, AuthParameters: map[string]string{"USERNAME": email, "PASSWORD": attempt.password}})
				assertAPIError(t, err, "NotAuthorizedException")
			}

			// A signed request's credential scope is its endpoint Region.
			signed := cognitoGuardSigned(clients, idp)
			retained := cognitoGuardLogin(t, clients, signed, poolID, clientID, email, cognitoGuardPassword)
			for _, attempt := range []struct{ client, password string }{
				{clientID, "Incorrect-password-16!"},
				{clientID, otherPassword},
				{otherClient, cognitoGuardPassword},
				{"missingguardclient", cognitoGuardPassword},
			} {
				_, err := signed.InitiateAuth(t.Context(), &cognitoidentityprovider.InitiateAuthInput{
					ClientId: aws.String(attempt.client), AuthFlow: idptypes.AuthFlowTypeUserPasswordAuth,
					AuthParameters: map[string]string{"USERNAME": email, "PASSWORD": attempt.password},
				})
				code := "NotAuthorizedException"
				if attempt.client == "missingguardclient" {
					code = "ResourceNotFoundException"
				}
				assertAPIError(t, err, code)
			}
			_, err := signed.InitiateAuth(t.Context(), &cognitoidentityprovider.InitiateAuthInput{
				ClientId: aws.String(otherClient), AuthFlow: idptypes.AuthFlowTypeRefreshTokenAuth,
				AuthParameters: map[string]string{"REFRESH_TOKEN": aws.ToString(retained.RefreshToken)},
			})
			assertAPIError(t, err, "NotAuthorizedException")
			if status, out := cognitoSignedInitiateAuth(t, clients, "us-west-2", clientID, email, cognitoGuardPassword); status != http.StatusBadRequest || !strings.Contains(out["__type"].(string), "ResourceNotFoundException") {
				t.Fatalf("signed us-west-2 request reached a us-east-2 client: HTTP %d %+v", status, out)
			}

			clients = reopen()
			idp = cognitoWorkflowClient(clients, cognitoGuardRegion, cognitoGuardAccount, "test")
			cognitoGuardLogin(t, clients, cognitoGuardPublic(t, idp), poolID, clientID, email, cognitoGuardPassword)
			// The reopened owner serves the original keys and still accepts the
			// original session; merely issuing new tokens would not prove retention.
			cognitoVerifiedJWT(t, clients, aws.ToString(retained.AccessToken))
			cognitoVerifiedJWT(t, clients, aws.ToString(retained.IdToken))
			public := cognitoGuardPublic(t, idp)
			if _, err := public.GetUser(t.Context(), &cognitoidentityprovider.GetUserInput{AccessToken: retained.AccessToken}); err != nil {
				t.Fatalf("retained access session: %v", err)
			}
			refresh, err := public.InitiateAuth(t.Context(), &cognitoidentityprovider.InitiateAuthInput{
				ClientId: aws.String(clientID), AuthFlow: idptypes.AuthFlowTypeRefreshTokenAuth,
				AuthParameters: map[string]string{"REFRESH_TOKEN": aws.ToString(retained.RefreshToken)},
			})
			if err != nil || refresh.AuthenticationResult == nil {
				t.Fatalf("retained refresh session: %+v, %v", refresh, err)
			}
			cognitoVerifiedJWT(t, clients, aws.ToString(refresh.AuthenticationResult.AccessToken))
			cognitoVerifiedJWT(t, clients, aws.ToString(refresh.AuthenticationResult.IdToken))
			cognitoGuardLogin(t, clients, cognitoGuardSigned(clients, idp), poolID, clientID, email, cognitoGuardPassword)
		})
	}
}

func cognitoGuardTemplate(t *testing.T, domain string, clientFlows []string, attributes []map[string]any) string {
	t.Helper()
	schema := []map[string]any{{"Name": "query", "AttributeDataType": "String", "Mutable": true}, {"Name": "guard_role", "AttributeDataType": "String", "Mutable": true}}
	schema = append(schema, attributes...)
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{
			"Pool": map[string]any{"Type": "AWS::Cognito::UserPool", "Properties": map[string]any{
				"UserPoolName": "guard-cfn", "UsernameAttributes": []string{"email"}, "AutoVerifiedAttributes": []string{"email"},
				"Policies":              map[string]any{"PasswordPolicy": map[string]any{"MinimumLength": 16, "RequireLowercase": true, "RequireUppercase": true, "RequireNumbers": true, "RequireSymbols": true}},
				"AdminCreateUserConfig": map[string]any{"AllowAdminCreateUserOnly": "true"},
				"Schema":                schema, "UserPoolTags": map[string]string{"team": "guard"},
				"VerificationMessageTemplate": map[string]any{"DefaultEmailOption": "CONFIRM_WITH_CODE", "EmailSubject": "Guard code", "EmailMessage": "Your Guard code is {####}"},
			}},
			"Client": map[string]any{"Type": "AWS::Cognito::UserPoolClient", "Properties": map[string]any{
				"UserPoolId": map[string]any{"Ref": "Pool"}, "GenerateSecret": false, "ExplicitAuthFlows": clientFlows,
				"AccessTokenValidity": 60, "IdTokenValidity": 60, "RefreshTokenValidity": 30,
				"TokenValidityUnits": map[string]any{"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"}, "PreventUserExistenceErrors": "ENABLED",
			}},
			"Domain": map[string]any{"Type": "AWS::Cognito::UserPoolDomain", "Properties": map[string]any{"UserPoolId": map[string]any{"Ref": "Pool"}, "Domain": domain}},
			"User": map[string]any{"Type": "AWS::Cognito::UserPoolUser", "Properties": map[string]any{
				"UserPoolId": map[string]any{"Ref": "Pool"}, "Username": "internal@guard.example", "MessageAction": "SUPPRESS",
				"UserAttributes": []map[string]string{{"Name": "email", "Value": "internal@guard.example"}, {"Name": "email_verified", "Value": "true"}},
			}},
			"Admins": map[string]any{"Type": "AWS::Cognito::UserPoolGroup", "Properties": map[string]any{"UserPoolId": map[string]any{"Ref": "Pool"}, "GroupName": "admins", "Precedence": 1}},
			"Membership": map[string]any{"Type": "AWS::Cognito::UserPoolUserToGroupAttachment", "Properties": map[string]any{
				"UserPoolId": map[string]any{"Ref": "Pool"}, "GroupName": map[string]any{"Ref": "Admins"}, "Username": map[string]any{"Ref": "User"},
			}},
			"Google": map[string]any{"Type": "AWS::Cognito::UserPoolIdentityProvider", "Properties": map[string]any{
				"UserPoolId": map[string]any{"Ref": "Pool"}, "ProviderName": "Google", "ProviderType": "Google",
				"ProviderDetails":  map[string]string{"client_id": "guard.apps.googleusercontent.com", "client_secret": "local-secret", "authorize_scopes": "openid email"},
				"AttributeMapping": map[string]string{"email": "email"},
			}},
			"Identities": map[string]any{"Type": "AWS::Cognito::IdentityPool", "Properties": map[string]any{
				"AllowUnauthenticatedIdentities": false,
				"CognitoIdentityProviders":       []map[string]any{{"ProviderName": map[string]any{"Fn::GetAtt": []string{"Pool", "ProviderName"}}, "ClientId": map[string]any{"Ref": "Client"}}},
			}},
			"Tags": map[string]any{"Type": "AWS::Cognito::IdentityPoolPrincipalTag", "Properties": map[string]any{
				"IdentityPoolId": map[string]any{"Ref": "Identities"}, "IdentityProviderName": map[string]any{"Fn::GetAtt": []string{"Pool", "ProviderName"}}, "UseDefaults": true,
			}},
		},
		"Outputs": map[string]any{
			"PoolId":      map[string]any{"Value": map[string]any{"Ref": "Pool"}},
			"ClientId":    map[string]any{"Value": map[string]any{"Ref": "Client"}},
			"Domain":      map[string]any{"Value": map[string]any{"Ref": "Domain"}},
			"ProviderURL": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Pool", "ProviderURL"}}},
			"Identities":  map[string]any{"Value": map[string]any{"Ref": "Identities"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

type cognitoGuardStack struct {
	clients cloudClients
	source  *clock.Manual
	stackID string
}

func (f *cognitoGuardStack) cfn() *cloudformation.Client {
	return cloudFormationClient(f.clients, cognitoGuardRegion, cognitoGuardAccount, "test")
}

func (f *cognitoGuardStack) wait(t *testing.T, stackID string, wanted cfntypes.StackStatus) cfntypes.Stack {
	t.Helper()
	for range 100 {
		if _, err := f.clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1000); err != nil {
			t.Fatal(err)
		}
		out, err := f.cfn().DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: aws.String(stackID)})
		if err != nil {
			t.Fatal(err)
		}
		stack := out.Stacks[0]
		if stack.StackStatus == wanted {
			return stack
		}
		if !cloudFormationTransient(map[string]any{"Stacks": []any{map[string]any{"StackStatus": string(stack.StackStatus)}}}) {
			events, _ := f.cfn().DescribeStackEvents(t.Context(), &cloudformation.DescribeStackEventsInput{StackName: aws.String(stackID)})
			var reasons []string
			for _, event := range events.StackEvents {
				if reason := aws.ToString(event.ResourceStatusReason); reason != "" {
					reasons = append(reasons, aws.ToString(event.LogicalResourceId)+": "+reason)
				}
			}
			t.Fatalf("wanted %s, got %s: %s %v", wanted, stack.StackStatus, aws.ToString(stack.StackStatusReason), reasons)
		}
		advanceClock(t, f.source, time.Second)
	}
	t.Fatalf("stack did not reach %s", wanted)
	return cfntypes.Stack{}
}

func cognitoStackOutputs(stack cfntypes.Stack) map[string]string {
	out := map[string]string{}
	for _, output := range stack.Outputs {
		out[aws.ToString(output.OutputKey)] = aws.ToString(output.OutputValue)
	}
	return out
}

func TestCloudFormationCognitoGuardLifecycle(t *testing.T) {
	flows := []string{"ALLOW_USER_SRP_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH"}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := &cognitoGuardStack{source: clock.NewManual(time.Now().UTC())}
			var reopen func() cloudClients
			f.clients, reopen = retainedCloud(t, backend, stackd.Config{AccountID: cognitoGuardAccount, Clock: f.source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			created, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("guard-auth"), TemplateBody: aws.String(cognitoGuardTemplate(t, "praetorian-guard-auth", flows, nil))})
			if err != nil {
				t.Fatal(err)
			}
			f.stackID = aws.ToString(created.StackId)
			outputs := cognitoStackOutputs(f.wait(t, f.stackID, cfntypes.StackStatusCreateComplete))
			poolID, clientID := outputs["PoolId"], outputs["ClientId"]
			if outputs["Domain"] != "praetorian-guard-auth" || outputs["ProviderURL"] != "https://cognito-idp.us-east-2.amazonaws.com/"+poolID || !strings.HasPrefix(outputs["Identities"], cognitoGuardRegion+":") {
				t.Fatalf("stack outputs do not name the owner resources: %+v", outputs)
			}
			idp := cognitoWorkflowClient(f.clients, cognitoGuardRegion, cognitoGuardAccount, "test")
			pool, err := idp.DescribeUserPool(t.Context(), &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: aws.String(poolID)})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(pool.UserPool.Domain) != "praetorian-guard-auth" || aws.ToInt32(pool.UserPool.Policies.PasswordPolicy.MinimumLength) != 16 || !pool.UserPool.AdminCreateUserConfig.AllowAdminCreateUserOnly || pool.UserPool.UserPoolTags["team"] != "guard" {
				t.Fatalf("pool lost template configuration: %+v", pool.UserPool)
			}
			if aws.ToString(pool.UserPool.VerificationMessageTemplate.EmailMessage) != "Your Guard code is {####}" {
				t.Fatalf("pool lost its verification template: %+v", pool.UserPool.VerificationMessageTemplate)
			}
			// The CloudFormation user signs in after an administrator sets its password.
			const internal = "internal@guard.example"
			if _, err := idp.AdminSetUserPassword(t.Context(), &cognitoidentityprovider.AdminSetUserPasswordInput{UserPoolId: aws.String(poolID), Username: aws.String(internal), Password: aws.String(cognitoGuardPassword), Permanent: true}); err != nil {
				t.Fatal(err)
			}
			cognitoGuardLogin(t, f.clients, cognitoGuardPublic(t, idp), poolID, clientID, internal, cognitoGuardPassword)
			groups, err := idp.AdminListGroupsForUser(t.Context(), &cognitoidentityprovider.AdminListGroupsForUserInput{UserPoolId: aws.String(poolID), Username: aws.String(internal)})
			if err != nil || len(groups.Groups) != 1 || aws.ToString(groups.Groups[0].GroupName) != "admins" {
				t.Fatalf("attachment did not add the user to its group: %+v, %v", groups, err)
			}
			provider, err := idp.DescribeIdentityProvider(t.Context(), &cognitoidentityprovider.DescribeIdentityProviderInput{UserPoolId: aws.String(poolID), ProviderName: aws.String("Google")})
			if err != nil || provider.IdentityProvider.ProviderDetails["client_id"] != "guard.apps.googleusercontent.com" {
				t.Fatalf("identity provider not retained by its owner: %+v, %v", provider, err)
			}

			// A second stack cannot claim a prefix domain another pool owns; its
			// rollback removes only its own resources.
			conflict, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("guard-conflict"), TemplateBody: aws.String(cognitoGuardTemplate(t, "praetorian-guard-auth", flows, nil))})
			if err != nil {
				t.Fatal(err)
			}
			f.wait(t, aws.ToString(conflict.StackId), cfntypes.StackStatusRollbackComplete)
			domain, err := idp.DescribeUserPoolDomain(t.Context(), &cognitoidentityprovider.DescribeUserPoolDomainInput{Domain: aws.String("praetorian-guard-auth")})
			if err != nil || aws.ToString(domain.DomainDescription.UserPoolId) != poolID {
				t.Fatalf("conflicting stack disturbed the owned domain: %+v, %v", domain, err)
			}

			f.clients = reopen()
			idp = cognitoWorkflowClient(f.clients, cognitoGuardRegion, cognitoGuardAccount, "test")
			// Update: narrow the client's flows and add a custom attribute.
			extra := []map[string]any{{"Name": "frozen", "AttributeDataType": "String", "Mutable": true}}
			if _, err := f.cfn().UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: aws.String(f.stackID), TemplateBody: aws.String(cognitoGuardTemplate(t, "praetorian-guard-auth", []string{"ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"}, extra))}); err != nil {
				t.Fatal(err)
			}
			outputs = cognitoStackOutputs(f.wait(t, f.stackID, cfntypes.StackStatusUpdateComplete))
			if outputs["PoolId"] != poolID || outputs["ClientId"] != clientID {
				t.Fatalf("in-place update replaced the pool or client: %+v", outputs)
			}
			described, err := idp.DescribeUserPoolClient(t.Context(), &cognitoidentityprovider.DescribeUserPoolClientInput{UserPoolId: aws.String(poolID), ClientId: aws.String(clientID)})
			if err != nil || len(described.UserPoolClient.ExplicitAuthFlows) != 2 {
				t.Fatalf("client update not applied by its owner: %+v, %v", described, err)
			}
			pool, err = idp.DescribeUserPool(t.Context(), &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: aws.String(poolID)})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, attribute := range pool.UserPool.SchemaAttributes {
				found = found || aws.ToString(attribute.Name) == "custom:frozen"
			}
			if !found {
				t.Fatalf("schema addition not applied: %+v", pool.UserPool.SchemaAttributes)
			}
			cognitoGuardLogin(t, f.clients, cognitoGuardPublic(t, idp), poolID, clientID, internal, cognitoGuardPassword)

			if _, err := f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(f.stackID)}); err != nil {
				t.Fatal(err)
			}
			f.wait(t, f.stackID, cfntypes.StackStatusDeleteComplete)
			_, err = idp.DescribeUserPool(t.Context(), &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: aws.String(poolID)})
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = identityPoolClient(f.clients, cognitoGuardRegion, cognitoGuardAccount).DescribeIdentityPool(t.Context(), &cognitoidentity.DescribeIdentityPoolInput{IdentityPoolId: aws.String(outputs["Identities"])})
			assertAPIError(t, err, "ResourceNotFoundException")
			domain, err = idp.DescribeUserPoolDomain(t.Context(), &cognitoidentityprovider.DescribeUserPoolDomainInput{Domain: aws.String("praetorian-guard-auth")})
			if err != nil || domain.DomainDescription == nil || domain.DomainDescription.UserPoolId != nil {
				t.Fatalf("deleted stack left its domain: %+v, %v", domain, err)
			}
		})
	}
}
