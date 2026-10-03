package stackd_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"

	"stackd"
)

func TestCognitoIdentityPoolControls(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount})
			ci := identityPoolClient(c, "us-east-1", eventDeliveryAccount)
			pool, e := ci.CreateIdentityPool(ctx, &cognitoidentity.CreateIdentityPoolInput{IdentityPoolName: new("before"), AllowUnauthenticatedIdentities: true, IdentityPoolTags: map[string]string{"purpose": "initial"}})
			if e != nil {
				t.Fatal(e)
			}
			id, e := ci.GetId(ctx, &cognitoidentity.GetIdInput{IdentityPoolId: pool.IdentityPoolId})
			if e != nil {
				t.Fatal(e)
			}
			changed, e := ci.UpdateIdentityPool(ctx, &cognitoidentity.UpdateIdentityPoolInput{IdentityPoolId: pool.IdentityPoolId, IdentityPoolName: new("after"), AllowUnauthenticatedIdentities: false, IdentityPoolTags: map[string]string{"purpose": "initial"}})
			if e != nil || changed.AllowUnauthenticatedIdentities || aws.ToString(changed.IdentityPoolName) != "after" {
				t.Fatalf("update did not change pool: %v", e)
			}
			_, e = ci.GetId(ctx, &cognitoidentity.GetIdInput{IdentityPoolId: pool.IdentityPoolId})
			assertAPIError(t, e, "NotAuthorizedException")
			second, e := ci.CreateIdentityPool(ctx, &cognitoidentity.CreateIdentityPoolInput{IdentityPoolName: new("other"), AllowUnauthenticatedIdentities: true})
			if e != nil {
				t.Fatal(e)
			}
			firstPage, e := ci.ListIdentityPools(ctx, &cognitoidentity.ListIdentityPoolsInput{MaxResults: new(int32(1))})
			if e != nil {
				t.Fatal(e)
			}
			if len(firstPage.IdentityPools) != 1 || firstPage.NextToken == nil {
				t.Fatal("first pool page has no continuation")
			}
			secondPage, e := ci.ListIdentityPools(ctx, &cognitoidentity.ListIdentityPoolsInput{MaxResults: new(int32(1)), NextToken: firstPage.NextToken})
			if e != nil {
				t.Fatal(e)
			}
			if len(secondPage.IdentityPools) != 1 || secondPage.NextToken != nil || aws.ToString(firstPage.IdentityPools[0].IdentityPoolId) == aws.ToString(secondPage.IdentityPools[0].IdentityPoolId) {
				t.Fatal("pool cursor duplicated or omitted a pool")
			}
			_, e = identityPoolClient(c, "us-west-2", eventDeliveryAccount).ListIdentityPools(ctx, &cognitoidentity.ListIdentityPoolsInput{MaxResults: new(int32(1)), NextToken: firstPage.NextToken})
			assertAPIError(t, e, "InvalidParameterException")
			_, key, secret := c.user(t, eventDeliveryAccount, "identity-tag-manager")
			resource := "arn:aws:cognito-identity:us-east-1:" + eventDeliveryAccount + ":identitypool/" + aws.ToString(pool.IdentityPoolId)
			putUserPolicy(t, c.iam(eventDeliveryAccount, "test", ""), "identity-tag-manager", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"cognito-identity:TagResource","Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/purpose":"approved"}}}}`)
			actor := cognitoidentity.New(cognitoidentity.Options{Region: "us-east-1", BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			_, e = actor.TagResource(ctx, &cognitoidentity.TagResourceInput{ResourceArn: new(resource), Tags: map[string]string{"purpose": "denied"}})
			assertAPIError(t, e, "NotAuthorizedException")
			if _, e = actor.TagResource(ctx, &cognitoidentity.TagResourceInput{ResourceArn: new(resource), Tags: map[string]string{"purpose": "approved"}}); e != nil {
				t.Fatal(e)
			}
			c = reopen()
			ci = identityPoolClient(c, "us-east-1", eventDeliveryAccount)
			described, e := ci.DescribeIdentityPool(ctx, &cognitoidentity.DescribeIdentityPoolInput{IdentityPoolId: pool.IdentityPoolId})
			if e != nil || aws.ToString(described.IdentityPoolName) != "after" || described.AllowUnauthenticatedIdentities {
				t.Fatalf("restart lost pool update: %v", e)
			}
			tags, e := ci.ListTagsForResource(ctx, &cognitoidentity.ListTagsForResourceInput{ResourceArn: new(resource)})
			if e != nil || tags.Tags["purpose"] != "approved" {
				t.Fatalf("tags did not survive restart: %v", e)
			}
			listed, e := ci.ListIdentities(ctx, &cognitoidentity.ListIdentitiesInput{IdentityPoolId: pool.IdentityPoolId, MaxResults: new(int32(60))})
			if e != nil || len(listed.Identities) != 1 || aws.ToString(listed.Identities[0].IdentityId) != aws.ToString(id.IdentityId) {
				t.Fatalf("retained identity list differs: %v", e)
			}
			if _, e = ci.DeleteIdentities(ctx, &cognitoidentity.DeleteIdentitiesInput{IdentityIdsToDelete: []string{aws.ToString(id.IdentityId)}}); e != nil {
				t.Fatal(e)
			}
			_, e = ci.DescribeIdentity(ctx, &cognitoidentity.DescribeIdentityInput{IdentityId: id.IdentityId})
			assertAPIError(t, e, "ResourceNotFoundException")
			if _, e = ci.UntagResource(ctx, &cognitoidentity.UntagResourceInput{ResourceArn: new(resource), TagKeys: []string{"purpose"}}); e != nil {
				t.Fatal(e)
			}
			tags, e = ci.ListTagsForResource(ctx, &cognitoidentity.ListTagsForResourceInput{ResourceArn: new(resource)})
			if e != nil || len(tags.Tags) != 0 {
				t.Fatalf("untag failed: %v", e)
			}
			for _, poolID := range []*string{pool.IdentityPoolId, second.IdentityPoolId} {
				if _, e = ci.DeleteIdentityPool(ctx, &cognitoidentity.DeleteIdentityPoolInput{IdentityPoolId: poolID}); e != nil {
					t.Fatal(e)
				}
			}
			final, e := ci.ListIdentityPools(ctx, &cognitoidentity.ListIdentityPoolsInput{MaxResults: new(int32(60))})
			if e != nil || len(final.IdentityPools) != 0 {
				t.Fatalf("deleted pools remain: %v", e)
			}
		})
	}
}
