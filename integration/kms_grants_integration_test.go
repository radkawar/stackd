package stackd_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd"
)

func kmsNativeCodes(t *testing.T, name string) map[string]string {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/kms/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct{ Observations []struct{ Case, Code string } }
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	codes := make(map[string]string)
	for _, row := range capture.Observations {
		codes[row.Case] = row.Code
	}
	return codes
}

func checkKMSNative(t *testing.T, codes map[string]string, name string, err error) {
	t.Helper()
	want, ok := codes[name]
	if !ok {
		t.Fatal("missing native KMS observation", name)
	}
	if want == "Success" {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return
	}
	assertAPIError(t, err, want)
}

func (c cloudClients) sessionKMS(credentials *ststypes.Credentials) *kms.Client {
	return c.kms(aws.ToString(credentials.AccessKeyId), aws.ToString(credentials.SecretAccessKey), aws.ToString(credentials.SessionToken))
}

func TestKMSGrantsSessionAndRolePermissionsMatchAWS(t *testing.T) {
	codes := kmsNativeCodes(t, "grants")
	c := clockCloud(t, stackd.Config{})
	root := c.iam("test", "test", "")
	owner := c.kms("test", "test", "")
	created, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := owner.Encrypt(t.Context(), &kms.EncryptInput{KeyId: created.KeyMetadata.KeyId, Plaintext: []byte("grant plaintext")})
	if err != nil {
		t.Fatal(err)
	}
	other := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}}`
	explicit := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"kms:*","Resource":"*"}]}`
	boundary, err := root.CreatePolicy(t.Context(), &iam.CreatePolicyInput{PolicyName: aws.String("grant-boundary"), PolicyDocument: &other})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"session", "role"} {
		t.Run(kind, func(t *testing.T) {
			role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("grant-" + kind), Path: aws.String("/application/"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			assume := func(name string, document *string) *sts.AssumeRoleOutput {
				t.Helper()
				out, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: &name, Policy: document})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			empty, limited, denied := assume("target", nil), assume("target", &other), assume("target", &explicit)
			principal := role.Role.Arn
			if kind == "session" {
				principal = empty.AssumedRoleUser.Arn
			}
			grant, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: created.KeyMetadata.KeyId, GranteePrincipal: principal, RetiringPrincipal: principal, Operations: []types.GrantOperation{types.GrantOperationDecrypt, types.GrantOperationRetireGrant}})
			checkKMSNative(t, codes, kind+"_create", err)
			decrypt := func(name string, credentials *ststypes.Credentials) {
				t.Helper()
				out, err := c.sessionKMS(credentials).Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, GrantTokens: []string{aws.ToString(grant.GrantToken)}})
				checkKMSNative(t, codes, name, err)
				if err == nil && !bytes.Equal(out.Plaintext, []byte("grant plaintext")) {
					t.Fatal("grant returned incorrect plaintext")
				}
			}
			decrypt(kind+"_no_identity_allow", empty.Credentials)
			decrypt(kind+"_implicit_session_deny", limited.Credentials)
			decrypt(kind+"_explicit_session_deny", denied.Credentials)
			if kind == "session" {
				decrypt("session_sibling", assume("sibling", nil).Credentials)
				decrypt("session_repeated_name", assume("target", nil).Credentials)
			}
			if _, err := root.PutRolePermissionsBoundary(t.Context(), &iam.PutRolePermissionsBoundaryInput{RoleName: role.Role.RoleName, PermissionsBoundary: boundary.Policy.Arn}); err != nil {
				t.Fatal(err)
			}
			decrypt(kind+"_implicit_boundary_deny", empty.Credentials)
			if _, err := root.DeleteRolePermissionsBoundary(t.Context(), &iam.DeleteRolePermissionsBoundaryInput{RoleName: role.Role.RoleName}); err != nil {
				t.Fatal(err)
			}
			// Grants never suppress explicit denies from current role policies.
			putRolePolicy(t, root, aws.ToString(role.Role.RoleName), explicit)
			_, err = c.sessionKMS(empty.Credentials).Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
			assertAPIError(t, err, "AccessDeniedException")
			if _, err := root.DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("access")}); err != nil {
				t.Fatal(err)
			}
			if kind == "session" {
				_, err := c.sessionKMS(limited.Credentials).RetireGrant(t.Context(), &kms.RetireGrantInput{GrantToken: grant.GrantToken})
				checkKMSNative(t, codes, "session_retire_limited", err)
				_, err = c.sessionKMS(empty.Credentials).Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
				assertAPIError(t, err, "AccessDeniedException")
			}
		})
	}
}

func TestKMSFederatedUserGrantMatchesAWS(t *testing.T) {
	codes := kmsNativeCodes(t, "grants")
	c := clockCloud(t, stackd.Config{})
	root := c.iam("test", "test", "")
	owner := c.kms("test", "test", "")
	_, access, secret := c.user(t, "test", "federator")
	putUserPolicy(t, root, "federator", allow(`"sts:GetFederationToken"`, "*"))
	fed, err := c.sts(access, secret, "").GetFederationToken(t.Context(), &sts.GetFederationTokenInput{Name: aws.String("grant-federated"), Policy: aws.String(allow(`"s3:ListAllMyBuckets"`, "*"))})
	if err != nil {
		t.Fatal(err)
	}
	key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := owner.Encrypt(t.Context(), &kms.EncryptInput{KeyId: key.KeyMetadata.KeyId, Plaintext: []byte("federated grant")})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: fed.FederatedUser.Arn, RetiringPrincipal: fed.FederatedUser.Arn, Operations: []types.GrantOperation{types.GrantOperationDecrypt}})
	checkKMSNative(t, codes, "federated_create", err)
	client := c.sessionKMS(fed.Credentials)
	out, err := client.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, GrantTokens: []string{aws.ToString(grant.GrantToken)}})
	checkKMSNative(t, codes, "federated_implicit_session_deny", err)
	if string(out.Plaintext) != "federated grant" {
		t.Fatal("federated grant returned incorrect plaintext")
	}
	_, err = client.RetireGrant(t.Context(), &kms.RetireGrantInput{GrantToken: grant.GrantToken})
	checkKMSNative(t, codes, "federated_retire", err)
}

func TestKMSGrantDelegationRequiresOneSufficientParent(t *testing.T) {
	codes := kmsNativeCodes(t, "grants")
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	root := c.iam("test", "test", "")
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("delegator"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("target")})
	if err != nil {
		t.Fatal(err)
	}
	key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: role.Role.Arn, Operations: []types.GrantOperation{types.GrantOperationCreateGrant, types.GrantOperationDecrypt}, Constraints: &types.GrantConstraints{EncryptionContextSubset: map[string]string{"department": "IT"}}})
	checkKMSNative(t, codes, "delegate_parent_create", err)
	second, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: role.Role.Arn, Operations: []types.GrantOperation{types.GrantOperationEncrypt}, Constraints: &types.GrantConstraints{EncryptionContextSubset: map[string]string{"project": "stackd"}}})
	checkKMSNative(t, codes, "delegate_second_create", err)
	input := &kms.CreateGrantInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: aws.String("arn:aws:iam::000000000000:root"), GrantTokens: []string{aws.ToString(first.GrantToken), aws.ToString(second.GrantToken)}}
	for _, tc := range []struct {
		name       string
		operations []types.GrantOperation
		constrain  bool
	}{
		{"delegate_combined_operations", []types.GrantOperation{types.GrantOperationDecrypt, types.GrantOperationEncrypt}, true},
		{"delegate_second_only", []types.GrantOperation{types.GrantOperationEncrypt}, true},
		{"delegate_broaden_constraint", []types.GrantOperation{types.GrantOperationDecrypt}, false},
		{"delegate_narrow_constraint", []types.GrantOperation{types.GrantOperationDecrypt}, true},
	} {
		input.Operations, input.Constraints = tc.operations, nil
		if tc.constrain {
			input.Constraints = &types.GrantConstraints{EncryptionContextEquals: map[string]string{"department": "IT", "project": "stackd"}}
		}
		_, err := c.sessionKMS(session.Credentials).CreateGrant(t.Context(), input)
		checkKMSNative(t, codes, tc.name, err)
	}
	// A policy can independently authorize CreateGrant; unrelated operation
	// permissions alone cannot expand a parent grant's delegation authority.
	putRolePolicy(t, root, "delegator", allow(`"kms:Encrypt"`, aws.ToString(key.KeyMetadata.Arn)))
	input.Operations = []types.GrantOperation{types.GrantOperationEncrypt}
	_, err = c.sessionKMS(session.Credentials).CreateGrant(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	putRolePolicy(t, root, "delegator", allow(`"kms:CreateGrant"`, aws.ToString(key.KeyMetadata.Arn)))
	input.Constraints = nil
	if _, err := c.sessionKMS(session.Credentials).CreateGrant(t.Context(), input); err != nil {
		t.Fatal(err)
	}
}
