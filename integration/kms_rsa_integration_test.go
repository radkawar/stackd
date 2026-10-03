package stackd_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
)

func TestKMSRSACrossAccountSigningPoliciesAndGrants(t *testing.T) {
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	grantee, access, secret := c.user(t, "222222222222", "rsa-user")
	client := c.kms(access, secret, "")
	ownerStatement := `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"}`
	policy := `{"Statement":[` + ownerStatement + `,{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":["kms:Sign","kms:Verify"],"Resource":"*","Condition":{"StringEquals":{"kms:SigningAlgorithm":"RSASSA_PSS_SHA_256","kms:MessageType":"RAW"}}}]}`
	created, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{KeySpec: types.KeySpecRsa2048, KeyUsage: types.KeyUsageTypeSignVerify, Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	key := created.KeyMetadata
	alias := "alias/rsa-signing"
	if _, err := owner.CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: &alias, TargetKeyId: key.KeyId}); err != nil {
		t.Fatal(err)
	}
	input := &kms.SignInput{KeyId: aws.String("arn:aws:kms:us-east-1:000000000000:" + alias), Message: []byte("cross-account signing"), SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256}
	_, err = client.Sign(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	document := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":["kms:Sign","kms:Verify","kms:GetPublicKey"],"Resource":%q,"Condition":{"StringEquals":{"kms:RequestAlias":%q}}}}`, aws.ToString(key.Arn), alias)
	putUserPolicy(t, c.iam("222222222222", "test", ""), "rsa-user", document)
	signed, err := client.Sign(t.Context(), input)
	if err != nil {
		t.Fatal("default RAW condition", err)
	}
	input.MessageType = types.MessageTypeDigest
	input.Message = make([]byte, 32)
	_, err = client.Sign(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.MessageType = ""
	input.Message = []byte("cross-account signing")
	input.SigningAlgorithm = types.SigningAlgorithmSpecRsassaPssSha384
	_, err = client.Sign(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.SigningAlgorithm = types.SigningAlgorithmSpecRsassaPssSha256
	input.KeyId = key.Arn
	_, err = client.Sign(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.KeyId = aws.String("arn:aws:kms:us-east-1:000000000000:" + alias)
	verify := &kms.VerifyInput{KeyId: input.KeyId, Message: input.Message, Signature: signed.Signature, SigningAlgorithm: input.SigningAlgorithm}
	if out, err := client.Verify(t.Context(), verify); err != nil || !out.SignatureValid {
		t.Fatal("cross-account verification", err)
	}
	_, err = client.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: input.KeyId})
	assertAPIError(t, err, "AccessDeniedException")
	policy = `{"Statement":[` + ownerStatement + `]}`
	if _, err := owner.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyId, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	grant, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyId, GranteePrincipal: &grantee, Operations: []types.GrantOperation{types.GrantOperationVerify, types.GrantOperationGetPublicKey}})
	if err != nil {
		t.Fatal(err)
	}
	verify.GrantTokens = []string{aws.ToString(grant.GrantToken)}
	if out, err := client.Verify(t.Context(), verify); err != nil || !out.SignatureValid {
		t.Fatal("verification grant", err)
	}
	if out, err := client.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: input.KeyId, GrantTokens: verify.GrantTokens}); err != nil || len(out.PublicKey) == 0 {
		t.Fatal("public-key grant", err)
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
	_, err = client.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: input.KeyId, GrantTokens: verify.GrantTokens})
	assertAPIError(t, err, "InvalidGrantTokenException")
}

func TestKMSRSAReEncryptConditions(t *testing.T) {
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	_, access, secret := c.user(t, "test", "reencrypt-user")
	client := c.kms(access, secret, "")
	created, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{KeySpec: types.KeySpecRsa2048, KeyUsage: types.KeyUsageTypeEncryptDecrypt})
	if err != nil {
		t.Fatal(err)
	}
	source := created.KeyMetadata
	created, err = owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	destination := created.KeyMetadata
	message := []byte("re-encryption permissions")
	encrypted, err := owner.Encrypt(t.Context(), &kms.EncryptInput{KeyId: source.KeyId, Plaintext: message, EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha1})
	if err != nil {
		t.Fatal(err)
	}
	from := fmt.Sprintf(`{"Effect":"Allow","Action":"kms:ReEncryptFrom","Resource":%q,"Condition":{"StringEquals":{"kms:EncryptionAlgorithm":"RSAES_OAEP_SHA_1"},"Bool":{"kms:ReEncryptOnSameKey":false}}}`, aws.ToString(source.Arn))
	to := fmt.Sprintf(`{"Effect":"Allow","Action":"kms:ReEncryptTo","Resource":%q,"Condition":{"StringEquals":{"kms:EncryptionAlgorithm":"SYMMETRIC_DEFAULT","kms:EncryptionContext:purpose":"migration"},"Bool":{"kms:ReEncryptOnSameKey":false}}}`, aws.ToString(destination.Arn))
	putUserPolicy(t, c.iam("test", "test", ""), "reencrypt-user", `{"Statement":[`+from+`,`+to+`]}`)
	input := &kms.ReEncryptInput{SourceKeyId: source.KeyId, SourceEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha1, CiphertextBlob: encrypted.CiphertextBlob, DestinationKeyId: destination.KeyId, DestinationEncryptionContext: map[string]string{"purpose": "migration"}}
	moved, err := client.ReEncrypt(t.Context(), input)
	if err != nil {
		t.Fatal("independent encryption algorithm conditions", err)
	}
	plain, err := owner.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: moved.CiphertextBlob, EncryptionContext: input.DestinationEncryptionContext})
	if err != nil || !bytes.Equal(plain.Plaintext, message) {
		t.Fatal("re-encryption result", err)
	}
	input.DestinationEncryptionContext = nil
	_, err = client.ReEncrypt(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.DestinationEncryptionContext = map[string]string{"purpose": "migration"}
	for _, statement := range []string{from, to} {
		putUserPolicy(t, c.iam("test", "test", ""), "reencrypt-user", `{"Statement":[`+statement+`]}`)
		_, err = client.ReEncrypt(t.Context(), input)
		assertAPIError(t, err, "AccessDeniedException")
	}
	alias := "alias/same-rsa-key"
	if _, err := owner.CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: &alias, TargetKeyId: source.KeyId}); err != nil {
		t.Fatal(err)
	}
	document := `{"Statement":{"Effect":"Allow","Action":"kms:ReEncrypt*","Resource":"*","Condition":{"Bool":{"kms:ReEncryptOnSameKey":true}}}}`
	putUserPolicy(t, c.iam("test", "test", ""), "reencrypt-user", document)
	_, err = client.ReEncrypt(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.DestinationKeyId = &alias
	input.DestinationEncryptionAlgorithm = types.EncryptionAlgorithmSpecRsaesOaepSha256
	input.DestinationEncryptionContext = nil
	if _, err := client.ReEncrypt(t.Context(), input); err != nil {
		t.Fatal("same-key condition must compare resolved key identity", err)
	}
}

func TestKMSRSADataKeyPairPermissions(t *testing.T) {
	c := clockCloud(t, stackd.Config{})
	owner := c.kms("test", "test", "")
	grantee, access, secret := c.user(t, "222222222222", "pair-user")
	client := c.kms(access, secret, "")
	created, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	key := created.KeyMetadata
	document := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":["kms:GenerateDataKeyPair","kms:GenerateDataKeyPairWithoutPlaintext"],"Resource":%q,"Condition":{"StringEquals":{"kms:DataKeyPairSpec":"RSA_2048"}}}}`, aws.ToString(key.Arn))
	putUserPolicy(t, c.iam("222222222222", "test", ""), "pair-user", document)
	input := &kms.GenerateDataKeyPairWithoutPlaintextInput{KeyId: key.Arn, KeyPairSpec: types.DataKeyPairSpecRsa2048, EncryptionContext: map[string]string{"purpose": "signing"}}
	_, err = client.GenerateDataKeyPairWithoutPlaintext(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	grant, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyId, GranteePrincipal: &grantee, Operations: []types.GrantOperation{types.GrantOperationGenerateDataKeyPairWithoutPlaintext}, Constraints: &types.GrantConstraints{EncryptionContextEquals: input.EncryptionContext}})
	if err != nil {
		t.Fatal(err)
	}
	input.GrantTokens = []string{aws.ToString(grant.GrantToken)}
	if out, err := client.GenerateDataKeyPairWithoutPlaintext(t.Context(), input); err != nil || len(out.PrivateKeyCiphertextBlob) == 0 {
		t.Fatal("cross-account constrained pair grant", err)
	}
	input.KeyPairSpec = types.DataKeyPairSpecRsa3072
	_, err = client.GenerateDataKeyPairWithoutPlaintext(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	input.KeyPairSpec = types.DataKeyPairSpecRsa2048
	input.EncryptionContext = nil
	_, err = client.GenerateDataKeyPairWithoutPlaintext(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	_, err = client.GenerateDataKeyPair(t.Context(), &kms.GenerateDataKeyPairInput{KeyId: key.Arn, KeyPairSpec: types.DataKeyPairSpecRsa2048, EncryptionContext: map[string]string{"purpose": "signing"}, GrantTokens: input.GrantTokens})
	assertAPIError(t, err, "AccessDeniedException")
}
