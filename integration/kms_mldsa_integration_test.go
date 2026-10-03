package stackd_test

import (
	"crypto/sha3"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
)

func TestKMSMLDSACrossAccountExternalMuPoliciesAndGrants(t *testing.T) {
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	grantee, access, secret := c.user(t, "222222222222", "mldsa-user")
	client := c.kms(access, secret, "")
	ownerStatement := `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"}`
	policy := `{"Statement":[` + ownerStatement + `,{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":["kms:Sign","kms:Verify"],"Resource":"*","Condition":{"StringEquals":{"kms:SigningAlgorithm":"ML_DSA_SHAKE_256","kms:MessageType":"EXTERNAL_MU"}}}]}`
	created, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{KeySpec: types.KeySpecMlDsa65, KeyUsage: types.KeyUsageTypeSignVerify, Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	key := created.KeyMetadata
	public, err := owner.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: key.KeyId})
	if err != nil {
		t.Fatal(err)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(public.PublicKey, &spki); err != nil {
		t.Fatal(err)
	}
	message := []byte("cross-account ML-DSA signing")
	hash := sha3.NewSHAKE256()
	_, _ = hash.Write(spki.PublicKey.Bytes)
	tr := make([]byte, 64)
	_, _ = hash.Read(tr)
	hash.Reset()
	_, _ = hash.Write(tr)
	_, _ = hash.Write([]byte{0, 0})
	_, _ = hash.Write(message)
	mu := make([]byte, 64)
	_, _ = hash.Read(mu)
	alias := "alias/mldsa-signing"
	if _, err := owner.CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: &alias, TargetKeyId: key.KeyId}); err != nil {
		t.Fatal(err)
	}
	input := &kms.SignInput{KeyId: aws.String("arn:aws:kms:us-east-1:000000000000:" + alias), Message: mu, MessageType: types.MessageTypeExternalMu, SigningAlgorithm: types.SigningAlgorithmSpecMlDsaShake256}
	_, err = client.Sign(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	document := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":["kms:Sign","kms:Verify","kms:GetPublicKey"],"Resource":%q,"Condition":{"StringEquals":{"kms:RequestAlias":%q}}}}`, aws.ToString(key.Arn), alias)
	putUserPolicy(t, c.iam("222222222222", "test", ""), "mldsa-user", document)
	signed, err := client.Sign(t.Context(), input)
	if err != nil {
		t.Fatal("cross-account external-mu policy", err)
	}
	verified, err := owner.Verify(t.Context(), &kms.VerifyInput{KeyId: key.KeyId, Message: message, Signature: signed.Signature, SigningAlgorithm: input.SigningAlgorithm})
	if err != nil || !verified.SignatureValid {
		t.Fatal("verify against original RAW message", err)
	}
	input.MessageType = ""
	input.Message = message
	_, err = client.Sign(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.MessageType = types.MessageTypeExternalMu
	input.Message = mu
	input.SigningAlgorithm = types.SigningAlgorithmSpecRsassaPssSha256
	_, err = client.Sign(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.SigningAlgorithm = types.SigningAlgorithmSpecMlDsaShake256
	input.KeyId = key.Arn
	_, err = client.Sign(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.KeyId = aws.String("arn:aws:kms:us-east-1:000000000000:" + alias)
	_, err = client.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: input.KeyId})
	assertAPIError(t, err, "AccessDeniedException")
	policy = `{"Statement":[` + ownerStatement + `]}`
	if _, err := owner.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyId, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	grant, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyId, GranteePrincipal: &grantee, Operations: []types.GrantOperation{types.GrantOperationVerify}})
	if err != nil {
		t.Fatal(err)
	}
	verify := &kms.VerifyInput{KeyId: input.KeyId, Message: mu, MessageType: types.MessageTypeExternalMu, SigningAlgorithm: input.SigningAlgorithm, Signature: signed.Signature, GrantTokens: []string{aws.ToString(grant.GrantToken)}}
	if out, err := client.Verify(t.Context(), verify); err != nil || !out.SignatureValid {
		t.Fatal("external-mu verification grant", err)
	}
	_, err = client.Sign(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	policy = `{"Statement":[` + ownerStatement + `,{"Effect":"Deny","Principal":"*","Action":"kms:Verify","Resource":"*"}]}`
	if _, err := owner.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyId, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	_, err = client.Verify(t.Context(), verify)
	assertAPIError(t, err, "AccessDeniedException")
	if _, err := owner.RevokeGrant(t.Context(), &kms.RevokeGrantInput{KeyId: key.KeyId, GrantId: grant.GrantId}); err != nil {
		t.Fatal(err)
	}
	_, err = client.Verify(t.Context(), verify)
	assertAPIError(t, err, "InvalidGrantTokenException")
}
