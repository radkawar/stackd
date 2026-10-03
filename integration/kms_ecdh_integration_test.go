package stackd_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
)

func TestKMSECDHCrossAccountPoliciesAliasesAndGrants(t *testing.T) {
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	grantee, access, secret := c.user(t, "222222222222", "agreement-user")
	client := c.kms(access, secret, "")
	ownerStatement := `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"}`
	policy := `{"Statement":[` + ownerStatement + `,{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"kms:DeriveSharedSecret","Resource":"*","Condition":{"StringEquals":{"kms:KeyAgreementAlgorithm":"ECDH"}}}]}`
	created, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{KeySpec: types.KeySpecEccNistP256, KeyUsage: types.KeyUsageTypeKeyAgreement, Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	key := created.KeyMetadata
	public, err := owner.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: key.KeyId})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(public.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := parsed.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want, err := peer.ECDH(remote)
	if err != nil {
		t.Fatal(err)
	}
	peerDER, err := x509.MarshalPKIXPublicKey(peer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	alias := "alias/agreement"
	if _, err := owner.CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: &alias, TargetKeyId: key.KeyId}); err != nil {
		t.Fatal(err)
	}
	input := &kms.DeriveSharedSecretInput{KeyId: aws.String("arn:aws:kms:us-east-1:000000000000:" + alias), PublicKey: peerDER, KeyAgreementAlgorithm: types.KeyAgreementAlgorithmSpecEcdh}
	_, err = client.DeriveSharedSecret(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	document := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":["kms:DeriveSharedSecret","kms:GetPublicKey"],"Resource":%q,"Condition":{"StringEquals":{"kms:RequestAlias":%q}}}}`, aws.ToString(key.Arn), alias)
	putUserPolicy(t, c.iam("222222222222", "test", ""), "agreement-user", document)
	out, err := client.DeriveSharedSecret(t.Context(), input)
	if err != nil || !bytes.Equal(out.SharedSecret, want) {
		t.Fatal("cross-account key/identity intersection", err)
	}
	input.KeyId = key.Arn
	_, err = client.DeriveSharedSecret(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.KeyId = aws.String("arn:aws:kms:us-east-1:000000000000:" + alias)
	_, err = client.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: input.KeyId})
	assertAPIError(t, err, "AccessDeniedException")
	policy = `{"Statement":[` + ownerStatement + `]}`
	if _, err := owner.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyId, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	_, err = client.DeriveSharedSecret(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	grant, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyId, GranteePrincipal: &grantee, Operations: []types.GrantOperation{types.GrantOperationDeriveSharedSecret}})
	if err != nil {
		t.Fatal(err)
	}
	input.GrantTokens = []string{aws.ToString(grant.GrantToken)}
	out, err = client.DeriveSharedSecret(t.Context(), input)
	if err != nil || !bytes.Equal(out.SharedSecret, want) {
		t.Fatal("agreement grant", err)
	}
	_, err = client.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: input.KeyId, GrantTokens: input.GrantTokens})
	assertAPIError(t, err, "AccessDeniedException")
	policy = `{"Statement":[` + ownerStatement + `,{"Effect":"Deny","Principal":"*","Action":"kms:DeriveSharedSecret","Resource":"*","Condition":{"StringEquals":{"kms:KeyAgreementAlgorithm":"ECDH"}}}]}`
	if _, err := owner.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyId, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	input.PublicKey = []byte("malformed")
	_, err = client.DeriveSharedSecret(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	if _, err := owner.RevokeGrant(t.Context(), &kms.RevokeGrantInput{KeyId: key.KeyId, GrantId: grant.GrantId}); err != nil {
		t.Fatal(err)
	}
	input.PublicKey = peerDER
	_, err = client.DeriveSharedSecret(t.Context(), input)
	assertAPIError(t, err, "InvalidGrantTokenException")
}
