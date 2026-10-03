package stackd_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
)

func TestKMSCrossAccountGrantTrustMatchesAWS(t *testing.T) {
	codes := kmsNativeCodes(t, "grants")
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	member := c.iam("222222222222", "test", "")
	policy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"kms:CreateGrant","Resource":"*"}]}`
	key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"owner", "trusted"} {
		t.Run(kind, func(t *testing.T) {
			role, err := member.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("cross-grant-" + kind), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			assume := func(document *string) *sts.AssumeRoleOutput {
				t.Helper()
				out, err := c.sts("222222222222", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("target"), Policy: document})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			session := assume(nil)
			limited := assume(aws.String(allow(`"s3:ListAllMyBuckets"`, "*")))
			issuer := owner
			if kind == "trusted" {
				issuer = c.kms("222222222222", "test", "")
			}
			for _, target := range []string{"session", "role"} {
				principal, operation := session.AssumedRoleUser.Arn, types.GrantOperationDescribeKey
				if target == "role" {
					principal, operation = role.Role.Arn, types.GrantOperationEncrypt
				}
				grant, err := issuer.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyMetadata.Arn, GranteePrincipal: principal, Operations: []types.GrantOperation{operation}})
				checkKMSNative(t, codes, "cross_"+kind+"_"+target+"_create", err)
				for _, limit := range []string{"no_identity_allow", "implicit_session_deny"} {
					client := c.sessionKMS(session.Credentials)
					if limit == "implicit_session_deny" {
						client = c.sessionKMS(limited.Credentials)
					}
					if target == "role" {
						_, err = client.Encrypt(t.Context(), &kms.EncryptInput{KeyId: key.KeyMetadata.Arn, Plaintext: []byte("cross account"), GrantTokens: []string{aws.ToString(grant.GrantToken)}})
					} else {
						_, err = client.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: key.KeyMetadata.Arn, GrantTokens: []string{aws.ToString(grant.GrantToken)}})
					}
					checkKMSNative(t, codes, "cross_"+kind+"_"+target+"_"+limit, err)
				}
			}
			putRolePolicy(t, member, aws.ToString(role.Role.RoleName), allow(`"kms:*"`, aws.ToString(key.KeyMetadata.Arn)))
			_, err = c.sessionKMS(session.Credentials).DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: key.KeyMetadata.Arn})
			checkKMSNative(t, codes, "cross_"+kind+"_identity_allowed", err)
			_, err = c.sessionKMS(limited.Credentials).DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: key.KeyMetadata.Arn})
			checkKMSNative(t, codes, "cross_"+kind+"_identity_allowed_limited", err)
		})
	}
}

func TestKMSCrossAccountGrantTrustCannotMixPrincipalKinds(t *testing.T) {
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	member := c.iam("222222222222", "test", "")
	role, err := member.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("grant-mixture"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.sts("222222222222", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("target"), Policy: aws.String(allow(`"s3:ListAllMyBuckets"`, "*"))})
	if err != nil {
		t.Fatal(err)
	}
	policy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"kms:CreateGrant","Resource":"*"}]}`
	key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	input := &kms.CreateGrantInput{KeyId: key.KeyMetadata.Arn, GranteePrincipal: session.AssumedRoleUser.Arn, Operations: []types.GrantOperation{types.GrantOperationDescribeKey}}
	if _, err := owner.CreateGrant(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	input.GranteePrincipal = role.Role.Arn
	if _, err := c.kms("222222222222", "test", "").CreateGrant(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	_, err = c.sessionKMS(session.Credentials).DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: key.KeyMetadata.Arn})
	assertAPIError(t, err, "AccessDeniedException")
	// Delegation to an account likewise cannot confer implicit identity access
	// on an independently matched grant issued by the key owner's account.
	input.GranteePrincipal = aws.String("arn:aws:iam::222222222222:root")
	if _, err := c.kms("222222222222", "test", "").CreateGrant(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	_, err = c.sessionKMS(session.Credentials).DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: key.KeyMetadata.Arn})
	assertAPIError(t, err, "AccessDeniedException")
}

func TestKMSCrossAccountRetirementRequiresCallerPermission(t *testing.T) {
	codes := kmsNativeCodes(t, "grants")
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	member := c.iam("222222222222", "test", "")
	role, err := member.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("retire-grant"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []string{"none", "session"} {
		var document *string
		if limit == "session" {
			document = aws.String(allow(`"s3:ListAllMyBuckets"`, "*"))
		}
		session, err := c.sts("222222222222", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("target"), Policy: document})
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{"session", "role"} {
			principal := session.AssumedRoleUser.Arn
			if target == "role" {
				principal = role.Role.Arn
			}
			for _, binding := range []string{"retiring", "grantee"} {
				input := &kms.CreateGrantInput{KeyId: key.KeyMetadata.Arn, GranteePrincipal: aws.String("arn:aws:iam::000000000000:root"), RetiringPrincipal: principal, Operations: []types.GrantOperation{types.GrantOperationDescribeKey}}
				if binding == "grantee" {
					input.GranteePrincipal, input.RetiringPrincipal = principal, nil
					input.Operations = []types.GrantOperation{types.GrantOperationRetireGrant}
				}
				name := fmt.Sprintf("cross_retire_%s_%s_%s", target, binding, limit)
				grant, err := owner.CreateGrant(t.Context(), input)
				checkKMSNative(t, codes, name+"_create", err)
				_, err = c.sessionKMS(session.Credentials).RetireGrant(t.Context(), &kms.RetireGrantInput{GrantToken: grant.GrantToken})
				checkKMSNative(t, codes, name, err)
			}
		}
	}
}
