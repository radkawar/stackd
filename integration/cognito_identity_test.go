package stackd_test

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	citypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentity/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	idptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
)

func identityPoolClient(c cloudClients, region, key string) *cognitoidentity.Client {
	return cognitoidentity.New(cognitoidentity.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func TestCognitoIdentityEnhancedAuthorityAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			source := clock.NewManual(time.Now().UTC())
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			ci := identityPoolClient(c, "us-east-1", eventDeliveryAccount)
			idp := cognitoWorkflowClient(c, "us-east-1", eventDeliveryAccount, "test")
			root := c.iam(eventDeliveryAccount, "test", "")
			up, e := idp.CreateUserPool(ctx, &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("identity-login"), UserPoolTier: idptypes.UserPoolTierTypeLite})
			if e != nil {
				t.Fatal(e)
			}
			app, e := idp.CreateUserPoolClient(ctx, &cognitoidentityprovider.CreateUserPoolClientInput{UserPoolId: up.UserPool.Id, ClientName: aws.String("identity-app"), ExplicitAuthFlows: []idptypes.ExplicitAuthFlowsType{idptypes.ExplicitAuthFlowsTypeAllowUserPasswordAuth, idptypes.ExplicitAuthFlowsTypeAllowRefreshTokenAuth}})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = idp.AdminCreateUser(ctx, &cognitoidentityprovider.AdminCreateUserInput{UserPoolId: up.UserPool.Id, Username: aws.String("alice"), MessageAction: idptypes.MessageActionTypeSuppress}); e != nil {
				t.Fatal(e)
			}
			if _, e = idp.AdminSetUserPassword(ctx, &cognitoidentityprovider.AdminSetUserPasswordInput{UserPoolId: up.UserPool.Id, Username: aws.String("alice"), Password: aws.String("A-local-password-123!"), Permanent: true}); e != nil {
				t.Fatal(e)
			}
			login := func() *cognitoidentityprovider.InitiateAuthOutput {
				t.Helper()
				result, e := idp.InitiateAuth(ctx, &cognitoidentityprovider.InitiateAuthInput{ClientId: app.UserPoolClient.ClientId, AuthFlow: idptypes.AuthFlowTypeUserPasswordAuth, AuthParameters: map[string]string{"USERNAME": "alice", "PASSWORD": "A-local-password-123!"}})
				if e != nil {
					t.Fatal(e)
				}
				return result
			}
			auth := login()
			provider := "cognito-idp.us-east-1.amazonaws.com/" + aws.ToString(up.UserPool.Id)
			pool, e := ci.CreateIdentityPool(ctx, &cognitoidentity.CreateIdentityPoolInput{IdentityPoolName: aws.String("identity-pool"), AllowUnauthenticatedIdentities: true, CognitoIdentityProviders: []citypes.CognitoIdentityProvider{{ProviderName: aws.String(provider), ClientId: app.UserPoolClient.ClientId, ServerSideTokenCheck: new(true)}}})
			if e != nil {
				t.Fatal(e)
			}
			trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":%q},"ForAnyValue:StringLike":{"cognito-identity.amazonaws.com:amr":["authenticated","unauthenticated"]}}}}`, aws.ToString(pool.IdentityPoolId))
			role, e := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("identity-exchange"), AssumeRolePolicyDocument: aws.String(trust)})
			if e != nil {
				t.Fatal(e)
			}
			putRolePolicy(t, root, "identity-exchange", allow(`"sqs:SendMessage"`, "*"))
			roles := map[string]string{"authenticated": aws.ToString(role.Role.Arn), "unauthenticated": aws.ToString(role.Role.Arn)}
			if _, e = ci.SetIdentityPoolRoles(ctx, &cognitoidentity.SetIdentityPoolRolesInput{IdentityPoolId: pool.IdentityPoolId, Roles: roles}); e != nil {
				t.Fatal(e)
			}
			queue, e := c.sqs(eventDeliveryAccount, "test", "").CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("identity-proof")})
			if e != nil {
				t.Fatal(e)
			}
			guest, e := ci.GetId(ctx, &cognitoidentity.GetIdInput{IdentityPoolId: pool.IdentityPoolId})
			if e != nil {
				t.Fatal(e)
			}
			logins := map[string]string{provider: aws.ToString(auth.AuthenticationResult.IdToken)}
			type acquisition struct {
				identity *cognitoidentity.GetIdOutput
				err      error
			}
			acquired := make(chan acquisition, 8)
			for range 8 {
				go func() {
					out, err := ci.GetId(ctx, &cognitoidentity.GetIdInput{IdentityPoolId: pool.IdentityPoolId, Logins: logins})
					acquired <- acquisition{out, err}
				}()
			}
			var signed *cognitoidentity.GetIdOutput
			for range 8 {
				result := <-acquired
				if result.err != nil {
					t.Fatal(result.err)
				}
				if signed != nil && aws.ToString(result.identity.IdentityId) != aws.ToString(signed.IdentityId) {
					t.Fatal("concurrent login created different identity bindings")
				}
				signed = result.identity
			}
			again, e := ci.GetId(ctx, &cognitoidentity.GetIdInput{IdentityPoolId: pool.IdentityPoolId, Logins: logins})
			if e != nil || aws.ToString(again.IdentityId) != aws.ToString(signed.IdentityId) {
				t.Fatalf("login identity changed: %v", e)
			}
			exchange := func(id *string, logins map[string]string) *citypes.Credentials {
				t.Helper()
				out, e := ci.GetCredentialsForIdentity(ctx, &cognitoidentity.GetCredentialsForIdentityInput{IdentityId: id, Logins: logins})
				if e != nil {
					t.Fatal(e)
				}
				return out.Credentials
			}
			guestCredentials := exchange(guest.IdentityId, nil)
			signedCredentials := exchange(signed.IdentityId, logins)
			send := func(v *citypes.Credentials, body string) error {
				_, e := c.sqs(aws.ToString(v.AccessKeyId), aws.ToString(v.SecretKey), aws.ToString(v.SessionToken)).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String(body)})
				return e
			}
			if e := send(guestCredentials, "guest"); e != nil {
				t.Fatal(e)
			}
			if e := send(signedCredentials, "authenticated"); e != nil {
				t.Fatal(e)
			}
			received, e := c.sqs(eventDeliveryAccount, "test", "").ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
			if e != nil {
				t.Fatal(e)
			}
			bodies := map[string]bool{}
			for _, m := range received.Messages {
				bodies[aws.ToString(m.Body)] = true
			}
			if !bodies["guest"] || !bodies["authenticated"] {
				t.Fatalf("signed messages missing: %v", bodies)
			}
			_, e = ci.GetCredentialsForIdentity(ctx, &cognitoidentity.GetCredentialsForIdentityInput{IdentityId: signed.IdentityId})
			assertAPIError(t, e, "NotAuthorizedException")
			_, e = ci.GetId(ctx, &cognitoidentity.GetIdInput{IdentityPoolId: pool.IdentityPoolId, Logins: map[string]string{provider: aws.ToString(auth.AuthenticationResult.AccessToken)}})
			assertAPIError(t, e, "NotAuthorizedException")
			_, e = identityPoolClient(c, "us-west-2", eventDeliveryAccount).DescribeIdentityPool(ctx, &cognitoidentity.DescribeIdentityPoolInput{IdentityPoolId: pool.IdentityPoolId})
			assertAPIError(t, e, "ResourceNotFoundException")
			_, e = identityPoolClient(c, "us-east-1", "999999999999").DescribeIdentityPool(ctx, &cognitoidentity.DescribeIdentityPoolInput{IdentityPoolId: pool.IdentityPoolId})
			assertAPIError(t, e, "ResourceNotFoundException")
			c = reopen()
			ci = identityPoolClient(c, "us-east-1", eventDeliveryAccount)
			idp = cognitoWorkflowClient(c, "us-east-1", eventDeliveryAccount, "test")
			root = c.iam(eventDeliveryAccount, "test", "")
			again, e = ci.GetId(ctx, &cognitoidentity.GetIdInput{IdentityPoolId: pool.IdentityPoolId, Logins: logins})
			if e != nil || aws.ToString(again.IdentityId) != aws.ToString(signed.IdentityId) {
				t.Fatalf("restart lost identity: %v", e)
			}
			if e := send(guestCredentials, "retained-session"); e != nil {
				t.Fatal(e)
			}
			putRolePolicy(t, root, "identity-exchange", `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`)
			assertAPIError(t, send(guestCredentials, "denied"), "AccessDenied")
			if _, e = root.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: role.Role.RoleName, PolicyDocument: aws.String(strings.Replace(trust, `"Allow"`, `"Deny"`, 1))}); e != nil {
				t.Fatal(e)
			}
			_, e = ci.GetCredentialsForIdentity(ctx, &cognitoidentity.GetCredentialsForIdentityInput{IdentityId: guest.IdentityId})
			assertAPIError(t, e, "InvalidIdentityPoolConfigurationException")
			if _, e = root.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: role.Role.RoleName, PolicyDocument: aws.String(trust)}); e != nil {
				t.Fatal(e)
			}
			if _, e = idp.AdminUserGlobalSignOut(ctx, &cognitoidentityprovider.AdminUserGlobalSignOutInput{UserPoolId: up.UserPool.Id, Username: aws.String("alice")}); e != nil {
				t.Fatal(e)
			}
			_, e = ci.GetCredentialsForIdentity(ctx, &cognitoidentity.GetCredentialsForIdentityInput{IdentityId: signed.IdentityId, Logins: logins})
			assertAPIError(t, e, "NotAuthorizedException")
			tokenRole, e := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("identity-token-role"), AssumeRolePolicyDocument: aws.String(trust)})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = idp.CreateGroup(ctx, &cognitoidentityprovider.CreateGroupInput{UserPoolId: up.UserPool.Id, GroupName: aws.String("identity-readers"), RoleArn: tokenRole.Role.Arn, Precedence: new(int32(1))}); e != nil {
				t.Fatal(e)
			}
			if _, e = idp.AdminAddUserToGroup(ctx, &cognitoidentityprovider.AdminAddUserToGroupInput{UserPoolId: up.UserPool.Id, GroupName: aws.String("identity-readers"), Username: aws.String("alice")}); e != nil {
				t.Fatal(e)
			}
			tokenMapping := citypes.RoleMapping{Type: citypes.RoleMappingTypeToken, AmbiguousRoleResolution: citypes.AmbiguousRoleResolutionTypeDeny}
			if _, e = ci.SetIdentityPoolRoles(ctx, &cognitoidentity.SetIdentityPoolRolesInput{IdentityPoolId: pool.IdentityPoolId, Roles: roles, RoleMappings: map[string]citypes.RoleMapping{provider + ":" + aws.ToString(app.UserPoolClient.ClientId): tokenMapping}}); e != nil {
				t.Fatal(e)
			}
			withGroup := login()
			logins[provider] = aws.ToString(withGroup.AuthenticationResult.IdToken)
			fromToken := exchange(signed.IdentityId, logins)
			tokenIdentity, e := c.sts(aws.ToString(fromToken.AccessKeyId), aws.ToString(fromToken.SecretKey), aws.ToString(fromToken.SessionToken)).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if e != nil || !strings.Contains(aws.ToString(tokenIdentity.Arn), ":assumed-role/identity-token-role/") {
				t.Fatalf("token preferred role: %v", e)
			}
			_, e = ci.GetCredentialsForIdentity(ctx, &cognitoidentity.GetCredentialsForIdentityInput{IdentityId: signed.IdentityId, Logins: logins, CustomRoleArn: role.Role.Arn})
			assertAPIError(t, e, "NotAuthorizedException")
			fresh := login()
			logins[provider] = aws.ToString(fresh.AuthenticationResult.IdToken)
			mapping := citypes.RoleMapping{Type: citypes.RoleMappingTypeRules, AmbiguousRoleResolution: citypes.AmbiguousRoleResolutionTypeDeny, RulesConfiguration: &citypes.RulesConfigurationType{Rules: []citypes.MappingRule{{Claim: aws.String("cognito:groups"), MatchType: citypes.MappingRuleMatchTypeContains, Value: aws.String("identity-readers"), RoleARN: role.Role.Arn}}}}
			if _, e = ci.SetIdentityPoolRoles(ctx, &cognitoidentity.SetIdentityPoolRolesInput{IdentityPoolId: pool.IdentityPoolId, Roles: roles, RoleMappings: map[string]citypes.RoleMapping{provider + ":" + aws.ToString(app.UserPoolClient.ClientId): mapping}}); e != nil {
				t.Fatal(e)
			}
			mapped := exchange(signed.IdentityId, logins)
			who, e := c.sts(aws.ToString(mapped.AccessKeyId), aws.ToString(mapped.SecretKey), aws.ToString(mapped.SessionToken)).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if e != nil || !strings.Contains(aws.ToString(who.Arn), ":assumed-role/identity-exchange/") {
				t.Fatalf("mapped role: %v", e)
			}
			_, e = ci.GetCredentialsForIdentity(ctx, &cognitoidentity.GetCredentialsForIdentityInput{IdentityId: signed.IdentityId, Logins: logins, CustomRoleArn: tokenRole.Role.Arn})
			assertAPIError(t, e, "InvalidParameterException")
			if _, e = ci.UnlinkIdentity(ctx, &cognitoidentity.UnlinkIdentityInput{IdentityId: signed.IdentityId, Logins: logins, LoginsToRemove: []string{provider}}); e != nil {
				t.Fatal(e)
			}
			unlinked, e := ci.DescribeIdentity(ctx, &cognitoidentity.DescribeIdentityInput{IdentityId: signed.IdentityId})
			if e != nil || len(unlinked.Logins) != 0 {
				t.Fatalf("identity retained unlinked provider: %v", e)
			}
			rebound, e := ci.GetId(ctx, &cognitoidentity.GetIdInput{IdentityPoolId: pool.IdentityPoolId, Logins: logins})
			if e != nil || aws.ToString(rebound.IdentityId) == aws.ToString(signed.IdentityId) {
				t.Fatalf("unlinked login retained old identity binding: %v", e)
			}
			if e := source.Advance(time.Hour); e != nil {
				t.Fatal(e)
			}
			_, e = ci.GetCredentialsForIdentity(ctx, &cognitoidentity.GetCredentialsForIdentityInput{IdentityId: signed.IdentityId, Logins: logins})
			assertAPIError(t, e, "NotAuthorizedException")
			if _, e = ci.DeleteIdentityPool(ctx, &cognitoidentity.DeleteIdentityPoolInput{IdentityPoolId: pool.IdentityPoolId}); e != nil {
				t.Fatal(e)
			}
			_, e = ci.DescribeIdentity(ctx, &cognitoidentity.DescribeIdentityInput{IdentityId: signed.IdentityId})
			assertAPIError(t, e, "ResourceNotFoundException")
		})
	}
}
