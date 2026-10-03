package stackd_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
)

func TestKMSMACCrossAccountPoliciesAliasesAndGrants(t *testing.T) {
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	grantee, access, secret := c.user(t, "222222222222", "mac-user")
	client := c.kms(access, secret, "")
	ownerStatement := `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"}`
	policy := `{"Statement":[` + ownerStatement + `,{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":["kms:GenerateMac","kms:VerifyMac"],"Resource":"*","Condition":{"StringEquals":{"kms:MacAlgorithm":"HMAC_SHA_256"}}}]}`
	created, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{KeySpec: types.KeySpecHmac256, KeyUsage: types.KeyUsageTypeGenerateVerifyMac, Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	key := created.KeyMetadata
	alias := "alias/mac-signing"
	if _, err := owner.CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: &alias, TargetKeyId: key.KeyId}); err != nil {
		t.Fatal(err)
	}
	input := &kms.GenerateMacInput{KeyId: aws.String("arn:aws:kms:us-east-1:000000000000:" + alias), MacAlgorithm: types.MacAlgorithmSpecHmacSha256, Message: []byte("cross-account message")}
	_, err = client.GenerateMac(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	document := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":["kms:GenerateMac","kms:VerifyMac"],"Resource":%q,"Condition":{"StringEquals":{"kms:RequestAlias":%q}}}}`, aws.ToString(key.Arn), alias)
	putUserPolicy(t, c.iam("222222222222", "test", ""), "mac-user", document)
	generated, err := client.GenerateMac(t.Context(), input)
	if err != nil || len(generated.Mac) != 32 {
		t.Fatal("cross-account MAC with key and identity policy", err)
	}
	input.KeyId = key.Arn
	_, err = client.GenerateMac(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.KeyId = aws.String("arn:aws:kms:us-east-1:000000000000:" + alias)
	input.MacAlgorithm = types.MacAlgorithmSpecHmacSha512
	_, err = client.GenerateMac(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.MacAlgorithm = types.MacAlgorithmSpecHmacSha256
	verify := &kms.VerifyMacInput{KeyId: input.KeyId, MacAlgorithm: input.MacAlgorithm, Message: input.Message, Mac: generated.Mac}
	if result, err := client.VerifyMac(t.Context(), verify); err != nil || !result.MacValid {
		t.Fatal("cross-account verification", err)
	}
	policy = `{"Statement":[` + ownerStatement + `]}`
	if _, err := owner.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyId, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	_, err = client.VerifyMac(t.Context(), verify)
	assertAPIError(t, err, "AccessDeniedException")
	grant, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyId, GranteePrincipal: &grantee, Operations: []types.GrantOperation{types.GrantOperationVerifyMac}})
	if err != nil {
		t.Fatal(err)
	}
	verify.GrantTokens = []string{aws.ToString(grant.GrantToken)}
	if out, err := client.VerifyMac(t.Context(), verify); err != nil || !out.MacValid {
		t.Fatal("grant did not permit verification", err)
	}
	_, err = client.GenerateMac(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	policy = `{"Statement":[` + ownerStatement + `,{"Effect":"Deny","Principal":"*","Action":"kms:VerifyMac","Resource":"*"}]}`
	if _, err := owner.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyId, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	_, err = client.VerifyMac(t.Context(), verify)
	assertAPIError(t, err, "AccessDeniedException")
	policy = `{"Statement":[` + ownerStatement + `]}`
	if _, err := owner.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyId, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.RevokeGrant(t.Context(), &kms.RevokeGrantInput{KeyId: key.KeyId, GrantId: grant.GrantId}); err != nil {
		t.Fatal(err)
	}
	_, err = client.VerifyMac(t.Context(), verify)
	assertAPIError(t, err, "InvalidGrantTokenException")
	verify.GrantTokens = nil
	_, err = client.VerifyMac(t.Context(), verify)
	assertAPIError(t, err, "AccessDeniedException")
}
