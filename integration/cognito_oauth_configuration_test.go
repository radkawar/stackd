package stackd_test

import (
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	idptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	"stackd"
)

func TestCognitoOAuthConfigurationLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: cognitoGuardAccount})
			idp := cognitoWorkflowClient(clients, cognitoGuardRegion, cognitoGuardAccount, "test")
			pool, err := idp.CreateUserPool(t.Context(), &cognitoidentityprovider.CreateUserPoolInput{PoolName: aws.String("oauth-config")})
			if err != nil {
				t.Fatal(err)
			}
			input := func() *cognitoidentityprovider.CreateUserPoolClientInput {
				return &cognitoidentityprovider.CreateUserPoolClientInput{
					UserPoolId: pool.UserPool.Id, ClientName: aws.String("oauth-app"),
					AllowedOAuthFlowsUserPoolClient: true,
					AllowedOAuthFlows:               []idptypes.OAuthFlowType{idptypes.OAuthFlowTypeCode},
					AllowedOAuthScopes:              []string{"openid", "email", "profile"},
					CallbackURLs:                    []string{"https://guard.example/callback", "http://127.0.0.1:8080/callback", "myapp://callback"},
					LogoutURLs:                      []string{"https://guard.example/logout"},
					DefaultRedirectURI:              aws.String("https://guard.example/callback"),
					SupportedIdentityProviders:      []string{"COGNITO", "Google"},
				}
			}
			_, err = idp.CreateUserPoolClient(t.Context(), input())
			assertAPIError(t, err, "InvalidParameterException")
			_, err = idp.CreateIdentityProvider(t.Context(), &cognitoidentityprovider.CreateIdentityProviderInput{
				UserPoolId: pool.UserPool.Id, ProviderName: aws.String("Google"), ProviderType: idptypes.IdentityProviderTypeTypeGoogle,
				ProviderDetails: map[string]string{"client_id": "guard-google", "client_secret": "guard-secret", "authorize_scopes": "openid email profile"},
			})
			if err != nil {
				t.Fatal(err)
			}
			created, err := idp.CreateUserPoolClient(t.Context(), input())
			if err != nil {
				t.Fatal(err)
			}
			clientID := created.UserPoolClient.ClientId
			check := func() {
				t.Helper()
				out, err := idp.DescribeUserPoolClient(t.Context(), &cognitoidentityprovider.DescribeUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientId: clientID})
				if err != nil {
					t.Fatal(err)
				}
				d := out.UserPoolClient
				want := input()
				if !aws.ToBool(d.AllowedOAuthFlowsUserPoolClient) || !slices.Equal(d.AllowedOAuthFlows, want.AllowedOAuthFlows) || !slices.Equal(d.AllowedOAuthScopes, want.AllowedOAuthScopes) || !slices.Equal(d.CallbackURLs, want.CallbackURLs) || !slices.Equal(d.LogoutURLs, want.LogoutURLs) || aws.ToString(d.DefaultRedirectURI) != aws.ToString(want.DefaultRedirectURI) || !slices.Equal(d.SupportedIdentityProviders, want.SupportedIdentityProviders) {
					t.Fatalf("OAuth configuration not retained: %+v", d)
				}
			}
			check()
			clients = reopen()
			idp = cognitoWorkflowClient(clients, cognitoGuardRegion, cognitoGuardAccount, "test")
			check()
			for _, mutate := range []func(*cognitoidentityprovider.CreateUserPoolClientInput){
				func(in *cognitoidentityprovider.CreateUserPoolClientInput) {
					in.AllowedOAuthFlowsUserPoolClient = false
				},
				func(in *cognitoidentityprovider.CreateUserPoolClientInput) {
					in.CallbackURLs = []string{"https://guard.example/callback#fragment"}
				},
				func(in *cognitoidentityprovider.CreateUserPoolClientInput) {
					in.CallbackURLs = []string{"http://guard.example/callback"}
				},
				func(in *cognitoidentityprovider.CreateUserPoolClientInput) {
					in.DefaultRedirectURI = aws.String("https://guard.example/missing")
				},
				func(in *cognitoidentityprovider.CreateUserPoolClientInput) {
					in.AllowedOAuthFlows = []idptypes.OAuthFlowType{idptypes.OAuthFlowTypeCode, idptypes.OAuthFlowTypeClientCredentials}
				},
				func(in *cognitoidentityprovider.CreateUserPoolClientInput) { in.AllowedOAuthScopes = []string{"email"} },
			} {
				in := input()
				mutate(in)
				_, err := idp.CreateUserPoolClient(t.Context(), in)
				assertAPIError(t, err, "InvalidParameterException")
			}
			_, err = idp.UpdateUserPoolClient(t.Context(), &cognitoidentityprovider.UpdateUserPoolClientInput{
				UserPoolId: pool.UserPool.Id, ClientId: clientID, AllowedOAuthFlowsUserPoolClient: true,
				AllowedOAuthFlows: []idptypes.OAuthFlowType{idptypes.OAuthFlowTypeImplicit}, AllowedOAuthScopes: []string{"openid"},
				CallbackURLs: []string{"https://guard.example/updated"}, SupportedIdentityProviders: []string{"Google"},
			})
			if err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			idp = cognitoWorkflowClient(clients, cognitoGuardRegion, cognitoGuardAccount, "test")
			updated, err := idp.DescribeUserPoolClient(t.Context(), &cognitoidentityprovider.DescribeUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientId: clientID})
			if err != nil {
				t.Fatal(err)
			}
			d := updated.UserPoolClient
			if !aws.ToBool(d.AllowedOAuthFlowsUserPoolClient) || !slices.Equal(d.AllowedOAuthFlows, []idptypes.OAuthFlowType{idptypes.OAuthFlowTypeImplicit}) || !slices.Equal(d.CallbackURLs, []string{"https://guard.example/updated"}) || len(d.LogoutURLs) != 0 || d.DefaultRedirectURI != nil || !slices.Equal(d.SupportedIdentityProviders, []string{"Google"}) {
				t.Fatalf("OAuth update not retained: %+v", d)
			}
			cleared, err := idp.UpdateUserPoolClient(t.Context(), &cognitoidentityprovider.UpdateUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientId: clientID})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToBool(cleared.UserPoolClient.AllowedOAuthFlowsUserPoolClient) || len(cleared.UserPoolClient.AllowedOAuthFlows) != 0 || len(cleared.UserPoolClient.CallbackURLs) != 0 {
				t.Fatalf("omission failed to reset OAuth: %+v", cleared.UserPoolClient)
			}
			machineInput := &cognitoidentityprovider.CreateUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientName: aws.String("machine"), GenerateSecret: true, AllowedOAuthFlowsUserPoolClient: true, AllowedOAuthFlows: []idptypes.OAuthFlowType{idptypes.OAuthFlowTypeClientCredentials}}
			machine, err := idp.CreateUserPoolClient(t.Context(), machineInput)
			if err != nil {
				t.Fatal(err)
			}
			secret := aws.ToString(machine.UserPoolClient.ClientSecret)
			if secret == "" {
				t.Fatal("client credentials configuration did not generate a secret")
			}
			reconfigured, err := idp.UpdateUserPoolClient(t.Context(), &cognitoidentityprovider.UpdateUserPoolClientInput{UserPoolId: pool.UserPool.Id, ClientId: machine.UserPoolClient.ClientId, AllowedOAuthFlowsUserPoolClient: true, AllowedOAuthFlows: machineInput.AllowedOAuthFlows})
			if err != nil || aws.ToString(reconfigured.UserPoolClient.ClientSecret) != secret {
				t.Fatalf("immutable secret lost on OAuth update: %+v, %v", reconfigured, err)
			}
			machineInput.GenerateSecret = false
			_, err = idp.CreateUserPoolClient(t.Context(), machineInput)
			assertAPIError(t, err, "InvalidParameterException")
			machineInput.GenerateSecret = true
			machineInput.AllowedOAuthScopes = []string{"missing/read"}
			_, err = idp.CreateUserPoolClient(t.Context(), machineInput)
			assertAPIError(t, err, "ScopeDoesNotExistException")
		})
	}
}
