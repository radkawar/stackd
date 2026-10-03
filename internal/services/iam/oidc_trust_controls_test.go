package iam_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"stackd/internal/services/iam"
)

func TestIAMOIDCTrustControlsSDKWritesAndRollback(t *testing.T) {
	s := iam.New()
	c := clientFor(t, s, "123456789012", "us-east-1")
	for _, tc := range []struct{ issuer, claim string }{
		{"token.actions.githubusercontent.com", "sub"},
		{"cognito-identity.amazonaws.com", "aud"},
		{"accounts.google.com", "aud"},
		{"api.pulumi.com/oidc", "aud"},
	} {
		t.Run(tc.issuer, func(t *testing.T) {
			ctx := t.Context()
			principal := tc.issuer
			if tc.issuer != "accounts.google.com" && tc.issuer != "cognito-identity.amazonaws.com" {
				created, err := c.CreateOpenIDConnectProvider(ctx, &sdkiam.CreateOpenIDConnectProviderInput{Url: aws.String("https://" + tc.issuer), ClientIDList: []string{"audience"}, ThumbprintList: []string{strings.Repeat("a", 40)}})
				if err != nil {
					t.Fatal(err)
				}
				principal = aws.ToString(created.OpenIDConnectProviderArn)
			}
			name := strings.NewReplacer(".", "-", "/", "-").Replace(tc.issuer)
			statement := map[string]any{"Effect": "Allow", "Principal": map[string]string{"Federated": principal}, "Action": "sts:AssumeRoleWithWebIdentity"}
			document := func() *string {
				t.Helper()
				data, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statement})
				if err != nil {
					t.Fatal(err)
				}
				return aws.String(string(data))
			}
			_, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: document()})
			requireCode(t, err, "MalformedPolicyDocument")
			_, err = c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: aws.String(name)})
			requireCode(t, err, "NoSuchEntity")
			statement["Condition"] = map[string]any{"StringEquals": map[string]string{tc.issuer + ":" + tc.claim: "owned-value"}}
			created, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: document()})
			if err != nil {
				t.Fatal(err)
			}
			before, err := c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: aws.String(name)})
			if err != nil {
				t.Fatal(err)
			}
			statement["Condition"] = map[string]any{"StringEqualsIfExists": map[string]string{tc.issuer + ":" + tc.claim: "owned-value"}}
			_, err = c.UpdateAssumeRolePolicy(ctx, &sdkiam.UpdateAssumeRolePolicyInput{RoleName: aws.String(name), PolicyDocument: document()})
			requireCode(t, err, "MalformedPolicyDocument")
			after, err := c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: aws.String(name)})
			if err != nil || aws.ToString(after.Role.RoleId) != aws.ToString(created.Role.RoleId) || aws.ToString(after.Role.AssumeRolePolicyDocument) != aws.ToString(before.Role.AssumeRolePolicyDocument) {
				t.Fatal("failed trust update mutated the role", err)
			}
			claim := tc.claim
			if tc.issuer == "token.actions.githubusercontent.com" {
				claim = "job_workflow_ref"
			}
			statement["Condition"] = map[string]any{"ForAnyValue:StringEquals": map[string]string{tc.issuer + ":" + claim: "new-owned-value"}}
			if _, err := c.UpdateAssumeRolePolicy(ctx, &sdkiam.UpdateAssumeRolePolicyInput{RoleName: aws.String(name), PolicyDocument: document()}); err != nil {
				t.Fatal("scoped trust update failed", err)
			}
		})
	}
}

func TestIAMOIDCTrustControlsPreserveLegacyStoredRole(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	provider := iam.OIDCProviderRecord{ARN: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com", ID: "AOIDlegacy", URL: "token.actions.githubusercontent.com"}
	legacy := `{"Statement":{"Effect":"Allow","Principal":{"Federated":"` + provider.ARN + `"},"Action":"sts:AssumeRoleWithWebIdentity"}}`
	if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := tx.PutOIDCProvider(scope, provider); err != nil {
			return err
		}
		return tx.PutRole(scope, iam.Role{RoleName: "legacy", RoleId: "AROAlegacy", Arn: "arn:aws:iam::123456789012:role/legacy", Path: "/", CreateDate: time.Now().UTC(), AssumeRolePolicyDocument: legacy, MaxSessionDuration: 3600})
	}); err != nil {
		t.Fatal(err)
	}
	c := clientFor(t, iam.NewWithRepository(nil, repository), scope.AccountID, "us-east-1")
	before, err := c.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: aws.String("legacy")})
	if err != nil {
		t.Fatal("stored legacy trust could not be rendered", err)
	}
	if _, err := c.UpdateRoleDescription(t.Context(), &sdkiam.UpdateRoleDescriptionInput{RoleName: aws.String("legacy"), Description: aws.String("unrelated metadata")}); err != nil {
		t.Fatal("unrelated metadata applied new trust controls", err)
	}
	_, err = c.UpdateAssumeRolePolicy(t.Context(), &sdkiam.UpdateAssumeRolePolicyInput{RoleName: aws.String("legacy"), PolicyDocument: aws.String(legacy)})
	requireCode(t, err, "MalformedPolicyDocument")
	after, err := c.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: aws.String("legacy")})
	if err != nil || aws.ToString(after.Role.AssumeRolePolicyDocument) != aws.ToString(before.Role.AssumeRolePolicyDocument) {
		t.Fatal("rejected legacy trust replacement changed stored policy", err)
	}
}

func TestIAMOIDCTrustControlsDoNotBypassAuthorization(t *testing.T) {
	s := iam.New()
	c := clientFor(t, s, "123456789012", "us-east-1")
	user, err := c.CreateUser(context.Background(), &sdkiam.CreateUserInput{UserName: aws.String("unprivileged")})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, s, user.User)
	_, err = caller.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("denied"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity"}}`)})
	requireCode(t, err, "AccessDenied")
}
