package stackd_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
	"stackd/clock"
)

func TestKMSMultiRegionAsymmetricAndHMACMaterial(t *testing.T) {
	source := clock.NewManual(time.Now().UTC())
	c := clockCloud(t, stackd.Config{Clock: source})
	east, west := c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
	for _, tc := range []struct {
		spec  types.KeySpec
		usage types.KeyUsageType
	}{
		{types.KeySpecHmac256, types.KeyUsageTypeGenerateVerifyMac},
		{types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt},
		{types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify},
	} {
		t.Run(string(tc.spec), func(t *testing.T) {
			created, err := east.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true), KeySpec: tc.spec, KeyUsage: tc.usage})
			if err != nil {
				t.Fatal(err)
			}
			id := created.KeyMetadata.KeyId
			if _, err := east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-west-2")}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 5*time.Second)
			message := []byte("regional cryptographic material")
			switch tc.usage {
			case types.KeyUsageTypeGenerateVerifyMac:
				mac, err := east.GenerateMac(t.Context(), &kms.GenerateMacInput{KeyId: id, Message: message, MacAlgorithm: types.MacAlgorithmSpecHmacSha256})
				if err != nil {
					t.Fatal(err)
				}
				out, err := west.VerifyMac(t.Context(), &kms.VerifyMacInput{KeyId: id, Message: message, Mac: mac.Mac, MacAlgorithm: mac.MacAlgorithm})
				if err != nil || !out.MacValid {
					t.Fatal("replica HMAC differs", out, err)
				}
			case types.KeyUsageTypeEncryptDecrypt:
				encrypted, err := east.Encrypt(t.Context(), &kms.EncryptInput{KeyId: id, Plaintext: message, EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256})
				if err != nil {
					t.Fatal(err)
				}
				out, err := west.Decrypt(t.Context(), &kms.DecryptInput{KeyId: id, CiphertextBlob: encrypted.CiphertextBlob, EncryptionAlgorithm: encrypted.EncryptionAlgorithm})
				if err != nil || !bytes.Equal(out.Plaintext, message) {
					t.Fatal("replica RSA differs", err)
				}
			case types.KeyUsageTypeSignVerify:
				signature, err := east.Sign(t.Context(), &kms.SignInput{KeyId: id, Message: message, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
				if err != nil {
					t.Fatal(err)
				}
				out, err := west.Verify(t.Context(), &kms.VerifyInput{KeyId: id, Message: message, Signature: signature.Signature, SigningAlgorithm: signature.SigningAlgorithm})
				if err != nil || !out.SignatureValid {
					t.Fatal("replica ECDSA differs", out, err)
				}
			}
			if tc.usage != types.KeyUsageTypeGenerateVerifyMac {
				first, err := east.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: id})
				if err != nil {
					t.Fatal(err)
				}
				second, err := west.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: id})
				if err != nil || !bytes.Equal(first.PublicKey, second.PublicKey) {
					t.Fatal("different regional public keys", err)
				}
			}
		})
	}
}

func TestKMSMultiRegionGrantAndAccountIsolation(t *testing.T) {
	source := clock.NewManual(time.Now().UTC())
	c := clockCloud(t, stackd.Config{Clock: source})
	east, west := c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
	created, err := east.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	id := created.KeyMetadata.KeyId
	replica, err := east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-west-2")})
	if err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 5*time.Second)
	arn, access, secret := c.user(t, "test", "regional-grantee")
	input := &kms.CreateGrantInput{KeyId: id, GranteePrincipal: &arn, Operations: []types.GrantOperation{types.GrantOperationEncrypt, types.GrantOperationDecrypt}}
	grant, err := east.CreateGrant(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	from, to := c.kms(access, secret, ""), c.kmsRegion("us-west-2", access, secret, "")
	encrypted, err := from.Encrypt(t.Context(), &kms.EncryptInput{KeyId: id, Plaintext: []byte("grant scope")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = to.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	assertAPIError(t, err, "AccessDeniedException")
	if _, err := west.CreateGrant(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := east.RevokeGrant(t.Context(), &kms.RevokeGrantInput{KeyId: id, GrantId: grant.GrantId}); err != nil {
		t.Fatal(err)
	}
	out, err := to.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	if err != nil || !bytes.Equal(out.Plaintext, []byte("grant scope")) {
		t.Fatal("replica grant was not independent", err)
	}
	foreign := c.kmsRegion("us-west-2", "222222222222", "test", "")
	_, err = foreign.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id})
	assertAPIError(t, err, "NotFoundException")
	_, err = foreign.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	assertAPIError(t, err, "AccessDeniedException")
	shared := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::000000000000:root","arn:aws:iam::222222222222:root"]},"Action":"kms:*","Resource":"*"}]}`
	if _, err := west.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: id, Policy: &shared}); err != nil {
		t.Fatal(err)
	}
	out, err = foreign.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	if err != nil || aws.ToString(out.KeyId) != aws.ToString(replica.ReplicaKeyMetadata.Arn) {
		t.Fatal("cross-account replica decrypt", err)
	}
	_, err = foreign.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: replica.ReplicaKeyMetadata.Arn, ReplicaRegion: aws.String("us-east-2")})
	assertAPIError(t, err, "AccessDeniedException")
	_, err = foreign.UpdatePrimaryRegion(t.Context(), &kms.UpdatePrimaryRegionInput{KeyId: replica.ReplicaKeyMetadata.Arn, PrimaryRegion: aws.String("us-west-2")})
	assertAPIError(t, err, "AccessDeniedException")
}
