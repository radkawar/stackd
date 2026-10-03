package sts

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

func samlProbeMetadata(f samlTestFixture) string {
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(f.certificate) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/login"/></IDPSSODescriptor></EntityDescriptor>`
}

// This separate opt-in probe uses static, independently created trust policies
// so policy-update propagation cannot masquerade as a condition-key result.
func TestSAMLProbeTrustAWS(t *testing.T) {
	if os.Getenv("STACKD_SAML_AWS_TRUST_PROBE_WRITE") != "1" {
		t.Skip("owned AWS trust probe requires explicit opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	iam := sdkiam.NewFromConfig(cfg)
	sts := sdksts.NewFromConfig(cfg)
	who, err := sts.GetCallerIdentity(ctx, &sdksts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatal(err)
	}
	account := aws.ToString(who.Account)
	name := fmt.Sprintf("stackd-saml-trust-%d", time.Now().UnixNano())
	f := newSAMLTestFixture(t)
	f.provider.ARN = "arn:aws:iam::" + account + ":saml-provider/" + name
	_, err = iam.CreateSAMLProvider(ctx, &sdkiam.CreateSAMLProviderInput{Name: aws.String(name), SAMLMetadataDocument: aws.String(samlProbeMetadata(f))})
	if err != nil {
		t.Fatal(err)
	}
	fixture := struct {
		ObservedAt      string               `json:"observed_at"`
		CleanupVerified bool                 `json:"cleanup_verified"`
		Observations    []samlAWSObservation `json:"observations"`
	}{ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	var roleNames []string
	useridOnly := os.Getenv("STACKD_SAML_AWS_TRUST_USERID_PROBE") == "1"
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 60*time.Second)
		defer stop()
		clean := true
		for _, roleName := range roleNames {
			if _, err := iam.DeleteRole(cleanup, &sdkiam.DeleteRoleInput{RoleName: aws.String(roleName)}); err != nil {
				t.Errorf("delete owned role %s: %v", roleName, err)
				clean = false
			}
		}
		if _, err := iam.DeleteSAMLProvider(cleanup, &sdkiam.DeleteSAMLProviderInput{SAMLProviderArn: aws.String(f.provider.ARN)}); err != nil {
			t.Errorf("delete owned provider: %v", err)
			clean = false
		}
		for _, roleName := range roleNames {
			_, err := iam.GetRole(cleanup, &sdkiam.GetRoleInput{RoleName: aws.String(roleName)})
			var missing *iamtypes.NoSuchEntityException
			if !errors.As(err, &missing) {
				clean = false
				t.Errorf("owned role remains: %s", roleName)
			}
		}
		_, err := iam.GetSAMLProvider(cleanup, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: aws.String(f.provider.ARN)})
		var missing *iamtypes.NoSuchEntityException
		if !errors.As(err, &missing) {
			clean = false
			t.Errorf("owned provider remains")
		}
		fixture.CleanupVerified = clean
		if !clean {
			return
		}
		body, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Error(err)
			return
		}
		path := "testdata/saml_trust_aws.json"
		if useridOnly {
			path = "testdata/saml_userid_aws.json"
		}
		if err := os.WriteFile(path, append(body, '\n'), 0644); err != nil {
			t.Error(err)
		}
	}()
	type trustCase struct{ name, principal, condition, roleARN string }
	federated := fmt.Sprintf(`{"Federated":%q}`, f.provider.ARN)
	cases := []trustCase{{name: "explicit_federated", principal: federated}, {name: "principal_star", principal: `"*"`}, {name: "principal_aws_star", principal: `{"AWS":"*"}`}, {name: "principal_federated_star", principal: `{"Federated":"*"}`}}
	cases = append(cases, trustCase{name: "principal_star_assume_role", principal: `"*"`})
	for _, key := range []string{"aws:PrincipalAccount", "aws:PrincipalArn", "aws:PrincipalType", "aws:userid"} {
		for _, absent := range []bool{true, false} {
			cases = append(cases, trustCase{name: fmt.Sprintf("%s_null_%v", key, absent), principal: federated, condition: fmt.Sprintf(`,"Condition":{"Null":{%q:%q}}`, key, fmt.Sprint(absent))})
		}
	}
	for _, value := range []struct{ key, value string }{{"aws:PrincipalAccount", account}, {"aws:PrincipalAccount", "anonymous"}, {"aws:PrincipalArn", f.provider.ARN}, {"aws:PrincipalType", "Federated"}, {"aws:PrincipalType", "Anonymous"}} {
		cases = append(cases, trustCase{name: value.key + "_equals_" + strings.ReplaceAll(value.value, account, "ACCOUNT"), principal: federated, condition: fmt.Sprintf(`,"Condition":{"StringEquals":{%q:%q}}`, value.key, value.value)})
	}
	for _, kind := range []string{"SAMLUser", "WebIdentityUser", "FederatedUser", "AssumedRole", "User", "Role"} {
		cases = append(cases, trustCase{name: "aws:PrincipalType_equals_" + kind, principal: federated, condition: fmt.Sprintf(`,"Condition":{"StringEquals":{"aws:PrincipalType":%q}}`, kind)})
	}
	qualifier := sha1.Sum([]byte(f.provider.Issuers[0].EntityID + account + "/" + name))
	for _, candidate := range []struct{ name, value string }{{"namequalifier_subject", base64.StdEncoding.EncodeToString(qualifier[:]) + ":subject-123"}, {"provider_arn_subject", f.provider.ARN + ":subject-123"}, {"provider_name_subject", name + ":subject-123"}, {"subject", "subject-123"}} {
		cases = append(cases, trustCase{name: "aws:userid_equals_" + candidate.name, principal: federated, condition: fmt.Sprintf(`,"Condition":{"StringEquals":{"aws:userid":%q}}`, candidate.value)})
	}
	if useridOnly {
		cases = cases[:1]
		configured, err := iam.GetSAMLProvider(ctx, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: aws.String(f.provider.ARN)})
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range []struct{ name, value, operator string }{
			{"empty", "", "StringEquals"}, {"account", account, "StringEquals"}, {"caller_userid", aws.ToString(who.UserId), "StringEquals"}, {"provider_arn", f.provider.ARN, "StringEquals"}, {"provider_uuid", aws.ToString(configured.SAMLProviderUUID), "StringEquals"}, {"namequalifier", base64.StdEncoding.EncodeToString(qualifier[:]), "StringEquals"}, {"has_subject", "*subject-123*", "StringLike"}, {"has_colon", "*:*", "StringLike"}, {"nonempty", "?*", "StringLike"}, {"role_session", "AROA*:saml-session", "StringLike"}, {"AIDA", "AIDA*", "StringLike"},
		} {
			cases = append(cases, trustCase{name: "aws:userid_" + candidate.name, principal: federated, condition: fmt.Sprintf(`,"Condition":{%q:{"aws:userid":%q}}`, candidate.operator, candidate.value)})
		}
	}
	recordError := func(scenario string, err error) {
		scenario = strings.ReplaceAll(scenario, name, "PROVIDER")
		o := samlAWSObservation{Scenario: scenario, Code: "Success"}
		if err != nil {
			var api smithy.APIError
			if !errors.As(err, &api) {
				t.Fatal(err)
			}
			o.Code = api.ErrorCode()
			o.Message = strings.ReplaceAll(api.ErrorMessage(), account, "123456789012")
		}
		fixture.Observations = append(fixture.Observations, o)
		t.Logf("%s: %s", scenario, o.Code)
	}
	for i := range cases {
		roleName := fmt.Sprintf("%s-%02d", name, i)
		action := "sts:AssumeRoleWithSAML"
		if cases[i].name == "principal_star_assume_role" {
			action = "sts:AssumeRole"
		}
		trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":%s,"Action":%q%s}]}`, cases[i].principal, action, cases[i].condition)
		created, err := iam.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String(roleName), AssumeRolePolicyDocument: aws.String(trust)})
		if err != nil {
			recordError(cases[i].name+"_create", err)
			continue
		}
		roleNames = append(roleNames, roleName)
		cases[i].roleARN = aws.ToString(created.Role.Arn)
		if action == "sts:AssumeRole" {
			recordError(cases[i].name+"_create", nil)
		}
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(15 * time.Second):
	}
	assume := func(f samlTestFixture) error {
		f.now = time.Now().UTC().Truncate(time.Second)
		raw := samlTestBytes(t, f.response(f.sign(t, f.assertion())))
		_, err := sts.AssumeRoleWithSAML(ctx, &sdksts.AssumeRoleWithSAMLInput{PrincipalArn: aws.String(f.provider.ARN), RoleArn: aws.String(f.roleARN), SAMLAssertion: aws.String(base64.StdEncoding.EncodeToString(raw))})
		return err
	}
	for _, test := range cases {
		if test.roleARN == "" || test.name == "principal_star_assume_role" {
			continue
		}
		f.roleARN = test.roleARN
		recordError(test.name, assume(f))
	}
	if useridOnly {
		return
	}
	// Keep the first role's original trust policy while replacing only the
	// provider incarnation at the same ARN, then test old and new signing keys.
	f.roleARN = cases[0].roleARN
	if _, err := iam.DeleteSAMLProvider(ctx, &sdkiam.DeleteSAMLProviderInput{SAMLProviderArn: aws.String(f.provider.ARN)}); err != nil {
		t.Fatal(err)
	}
	newFixture := newSAMLTestFixture(t)
	newFixture.provider.ARN = f.provider.ARN
	newFixture.roleARN = f.roleARN
	if _, err := iam.CreateSAMLProvider(ctx, &sdkiam.CreateSAMLProviderInput{Name: aws.String(name), SAMLMetadataDocument: aws.String(samlProbeMetadata(newFixture))}); err != nil {
		t.Fatal(err)
	}
	var newErr error
	for attempt := 0; attempt < 15; attempt++ {
		newErr = assume(newFixture)
		if newErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	recordError("recreated_provider_new_key_existing_role_trust", newErr)
	recordError("recreated_provider_old_key", assume(f))
}
