package stackd_test

import (
	"maps"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	citypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentity/types"
	"stackd"
)

func TestCognitoIdentityPrincipalTagMapLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount})
			ci := identityPoolClient(c, "us-east-1", eventDeliveryAccount)
			provider := "cognito-idp.us-east-1.amazonaws.com/us-east-1_tags"
			providers := []citypes.CognitoIdentityProvider{{ProviderName: new(provider), ClientId: new("tagclient")}}
			pool, err := ci.CreateIdentityPool(ctx, &cognitoidentity.CreateIdentityPoolInput{IdentityPoolName: new("tagged"), AllowUnauthenticatedIdentities: true, CognitoIdentityProviders: providers})
			if err != nil {
				t.Fatal(err)
			}
			get := &cognitoidentity.GetPrincipalTagAttributeMapInput{IdentityPoolId: pool.IdentityPoolId, IdentityProviderName: new(provider)}
			_, err = ci.GetPrincipalTagAttributeMap(ctx, get)
			assertAPIError(t, err, "ResourceNotFoundException")
			defaults, err := ci.SetPrincipalTagAttributeMap(ctx, &cognitoidentity.SetPrincipalTagAttributeMapInput{IdentityPoolId: pool.IdentityPoolId, IdentityProviderName: new(provider), UseDefaults: new(true), PrincipalTags: map[string]string{"ignored": "email"}})
			if err != nil || defaults.UseDefaults == nil || !*defaults.UseDefaults || !maps.Equal(defaults.PrincipalTags, map[string]string{"client": "aud", "username": "sub"}) {
				t.Fatalf("defaults: %v %v", defaults, err)
			}
			want := map[string]string{"tenant": "custom:tenant"}
			_, err = ci.SetPrincipalTagAttributeMap(ctx, &cognitoidentity.SetPrincipalTagAttributeMapInput{IdentityPoolId: pool.IdentityPoolId, IdentityProviderName: new(provider), PrincipalTags: want})
			if err != nil {
				t.Fatal(err)
			}
			_, err = identityPoolClient(c, "us-east-1", "999999999999").GetPrincipalTagAttributeMap(ctx, get)
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = identityPoolClient(c, "us-west-2", eventDeliveryAccount).GetPrincipalTagAttributeMap(ctx, get)
			assertAPIError(t, err, "ResourceNotFoundException")
			_, key, secret := c.user(t, eventDeliveryAccount, "tag-map-reader")
			actor := cognitoidentity.New(cognitoidentity.Options{Region: "us-east-1", BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			_, err = actor.GetPrincipalTagAttributeMap(ctx, get)
			assertAPIError(t, err, "NotAuthorizedException")
			_, err = actor.SetPrincipalTagAttributeMap(ctx, &cognitoidentity.SetPrincipalTagAttributeMapInput{IdentityPoolId: pool.IdentityPoolId, IdentityProviderName: new(provider), UseDefaults: new(true)})
			assertAPIError(t, err, "NotAuthorizedException")
			other, err := ci.CreateIdentityPool(ctx, &cognitoidentity.CreateIdentityPoolInput{IdentityPoolName: new("other"), AllowUnauthenticatedIdentities: true, CognitoIdentityProviders: providers})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ci.GetPrincipalTagAttributeMap(ctx, &cognitoidentity.GetPrincipalTagAttributeMapInput{IdentityPoolId: other.IdentityPoolId, IdentityProviderName: new(provider)})
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = ci.GetPrincipalTagAttributeMap(ctx, &cognitoidentity.GetPrincipalTagAttributeMapInput{IdentityPoolId: pool.IdentityPoolId, IdentityProviderName: new("cognito-idp.us-east-1.amazonaws.com/us-east-1_other")})
			assertAPIError(t, err, "ResourceNotFoundException")
			c = reopen()
			ci = identityPoolClient(c, "us-east-1", eventDeliveryAccount)
			stored, err := ci.GetPrincipalTagAttributeMap(ctx, get)
			if err != nil || stored.UseDefaults == nil || *stored.UseDefaults || !maps.Equal(stored.PrincipalTags, want) {
				t.Fatalf("restart: %v %v", stored, err)
			}
			_, err = ci.SetPrincipalTagAttributeMap(ctx, &cognitoidentity.SetPrincipalTagAttributeMapInput{IdentityPoolId: pool.IdentityPoolId, IdentityProviderName: new(provider), PrincipalTags: map[string]string{}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ci.GetPrincipalTagAttributeMap(ctx, get)
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = ci.SetPrincipalTagAttributeMap(ctx, &cognitoidentity.SetPrincipalTagAttributeMapInput{IdentityPoolId: pool.IdentityPoolId, IdentityProviderName: new(provider), UseDefaults: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			for _, list := range [][]citypes.CognitoIdentityProvider{nil, providers} {
				_, err = ci.UpdateIdentityPool(ctx, &cognitoidentity.UpdateIdentityPoolInput{IdentityPoolId: pool.IdentityPoolId, IdentityPoolName: new("tagged"), AllowUnauthenticatedIdentities: true, CognitoIdentityProviders: list})
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err = ci.GetPrincipalTagAttributeMap(ctx, get)
			assertAPIError(t, err, "ResourceNotFoundException")
			_, err = ci.SetPrincipalTagAttributeMap(ctx, &cognitoidentity.SetPrincipalTagAttributeMapInput{IdentityPoolId: pool.IdentityPoolId, IdentityProviderName: new(provider), UseDefaults: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ci.DeleteIdentityPool(ctx, &cognitoidentity.DeleteIdentityPoolInput{IdentityPoolId: pool.IdentityPoolId})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ci.GetPrincipalTagAttributeMap(ctx, get)
			assertAPIError(t, err, "ResourceNotFoundException")
		})
	}
}
