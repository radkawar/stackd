package kms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestSDKRSASignaturesMatchAWS(t *testing.T) {
	capture := readCryptoCapture(t, "rsa")
	for _, native := range capture.Keys {
		if native.KeyUsage != types.KeyUsageTypeSignVerify {
			continue
		}
		t.Run(string(native.KeySpec), func(t *testing.T) {
			backend := NewMemoryStorage(nil)
			scope := rootMetadata("111111111111", "us-east-1", "aws")
			c := sdkClient(t, NewWithStorage(backend, nil), scope)
			key := createAsymmetricSDKKey(t, c, native.KeySpec, native.KeyUsage)
			if key.CurrentKeyMaterialId != nil || !reflect.DeepEqual(key.SigningAlgorithms, native.SigningAlgorithms) || len(key.EncryptionAlgorithms) != 0 || len(key.MacAlgorithms) != 0 {
				t.Fatal("signing metadata differs from AWS")
			}
			public, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId})
			if err != nil {
				t.Fatal(err)
			}
			parsed := publicRSAKey(t, public.PublicKey)
			if !reflect.DeepEqual(public.SigningAlgorithms, native.SigningAlgorithms) || public.KeyUsage != native.KeyUsage {
				t.Fatal("public signing metadata differs from AWS")
			}
			c = sdkClient(t, NewWithStorage(backend, nil), scope)
			for _, algorithm := range native.SigningAlgorithms {
				t.Run(string(algorithm), func(t *testing.T) {
					hash := crypto.SHA256
					if strings.HasSuffix(string(algorithm), "384") {
						hash = crypto.SHA384
					}
					if strings.HasSuffix(string(algorithm), "512") {
						hash = crypto.SHA512
					}
					message := []byte("stackd RSA interoperability")
					h := hash.New()
					_, _ = h.Write(message)
					digest := h.Sum(nil)
					for _, messageType := range []types.MessageType{"", types.MessageTypeDigest} {
						input := message
						if messageType == types.MessageTypeDigest {
							input = digest
						}
						signed, err := c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: input, MessageType: messageType, SigningAlgorithm: algorithm})
						if err != nil {
							t.Fatal(err)
						}
						if len(signed.Signature) != parsed.Size() || signed.SigningAlgorithm != algorithm || aws.ToString(signed.KeyId) != aws.ToString(key.Arn) {
							t.Fatal("signature response differs from AWS")
						}
						if strings.HasPrefix(string(algorithm), "RSASSA_PSS_") {
							err = rsa.VerifyPSS(parsed, hash, digest, signed.Signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
						} else {
							err = rsa.VerifyPKCS1v15(parsed, hash, digest, signed.Signature)
						}
						if err != nil {
							t.Fatal("external verification rejected signature", err)
						}
						verified, err := c.Verify(t.Context(), &sdkkms.VerifyInput{KeyId: key.KeyId, Message: digest, MessageType: types.MessageTypeDigest, SigningAlgorithm: algorithm, Signature: signed.Signature})
						if err != nil || !verified.SignatureValid || verified.SigningAlgorithm != algorithm || aws.ToString(verified.KeyId) != aws.ToString(key.Arn) {
							t.Fatal("digest verification", err)
						}
						_, err = c.Verify(t.Context(), &sdkkms.VerifyInput{KeyId: key.KeyId, Message: message, SigningAlgorithm: algorithm, Signature: signed.Signature, DryRun: aws.Bool(true)})
						requireCode(t, err, "DryRunOperationException")
					}
					_, err = c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: []byte("short"), MessageType: types.MessageTypeDigest, SigningAlgorithm: algorithm})
					capture.requireError(t, err, "wrong_digest_length", native.KeySpec, native.KeyUsage, string(algorithm), true)
					for _, dry := range []bool{false, true} {
						name := "invalid_signature"
						if dry {
							name = "dry_invalid_signature"
						}
						_, err = c.Verify(t.Context(), &sdkkms.VerifyInput{KeyId: key.KeyId, Message: message, SigningAlgorithm: algorithm, Signature: bytes.Repeat([]byte("x"), parsed.Size()), DryRun: &dry})
						capture.requireError(t, err, name, native.KeySpec, native.KeyUsage, string(algorithm), true)
					}
					_, err = c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: message, SigningAlgorithm: algorithm, DryRun: aws.Bool(true)})
					requireCode(t, err, "DryRunOperationException")
				})
			}
			algorithm := native.SigningAlgorithms[len(native.SigningAlgorithms)-1]
			_, err = c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: bytes.Repeat([]byte("a"), 64), MessageType: types.MessageTypeExternalMu, SigningAlgorithm: algorithm})
			capture.requireError(t, err, "external_mu", native.KeySpec, native.KeyUsage, string(algorithm), true)
			_, err = c.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: key.KeyId, Plaintext: []byte("message"), EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256})
			requireCode(t, err, "InvalidKeyUsageException")
			grant := &sdkkms.CreateGrantInput{KeyId: key.KeyId, GranteePrincipal: aws.String("arn:aws:iam::111111111111:root"), Operations: []types.GrantOperation{types.GrantOperationGetPublicKey, types.GrantOperationSign, types.GrantOperationVerify}}
			if _, err := c.CreateGrant(t.Context(), grant); err != nil {
				t.Fatal(err)
			}
			grant.Constraints = &types.GrantConstraints{EncryptionContextEquals: map[string]string{"purpose": "probe"}}
			_, err = c.CreateGrant(t.Context(), grant)
			capture.requireError(t, err, "constrained_grant", native.KeySpec, native.KeyUsage, "", true)
			if _, err := c.DisableKey(t.Context(), &sdkkms.DisableKeyInput{KeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			_, err = c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: []byte("message"), SigningAlgorithm: algorithm})
			requireCode(t, err, "DisabledException")
		})
	}
}

func TestSDKRSAKeyUsageValidation(t *testing.T) {
	c := sdkClient(t, New(), rootMetadata("111111111111", "us-east-1", "aws"))
	for _, usage := range []types.KeyUsageType{"", types.KeyUsageTypeGenerateVerifyMac, types.KeyUsageTypeKeyAgreement} {
		_, err := c.CreateKey(t.Context(), &sdkkms.CreateKeyInput{KeySpec: types.KeySpecRsa2048, KeyUsage: usage})
		requireCode(t, err, "ValidationException")
	}
	key := createSDKKey(t, c)
	_, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId})
	readCryptoCapture(t, "rsa").requireError(t, err, "symmetric_public_key", types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, "", true)
	key = createAsymmetricSDKKey(t, c, types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt)
	_, err = c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: []byte("message"), SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256})
	requireCode(t, err, "InvalidKeyUsageException")
}

func TestSDKRSAVerifyExternalSignatures(t *testing.T) {
	backend := NewMemoryStorage(nil)
	sc := rootMetadata("111111111111", "us-east-1", "aws")
	c := sdkClient(t, NewWithStorage(backend, nil), sc)
	key := createAsymmetricSDKKey(t, c, types.KeySpecRsa2048, types.KeyUsageTypeSignVerify)
	var private *rsa.PrivateKey
	if err := backend.View(t.Context(), func(tx Reader) error {
		set, err := tx.KeySet(KeyOwner{Partition: sc.Partition, AccountID: sc.AccountID}, aws.ToString(key.KeyId))
		if err != nil {
			return err
		}
		decoded, err := x509.ParsePKCS8PrivateKey(set.Materials[0].Material)
		if err != nil {
			return err
		}
		private = decoded.(*rsa.PrivateKey)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	message := []byte("offline signature")
	hash := crypto.SHA256.New()
	_, _ = hash.Write(message)
	digest := hash.Sum(nil)
	for _, salt := range []int{rsa.PSSSaltLengthEqualsHash, rsa.PSSSaltLengthAuto} {
		signature, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: salt})
		if err != nil {
			t.Fatal(err)
		}
		out, err := c.Verify(t.Context(), &sdkkms.VerifyInput{KeyId: key.KeyId, Message: message, Signature: signature, SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256})
		if salt == rsa.PSSSaltLengthAuto {
			// AWS requires salt length equal to digest length, unlike Go's
			// default, which also accepts longer salts during verification.
			requireCode(t, err, "KMSInvalidSignatureException")
		} else if err != nil || !out.SignatureValid {
			t.Fatal("external PSS signature", err)
		}
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	in := &sdkkms.VerifyInput{KeyId: key.KeyId, Message: message, Signature: signature, SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256}
	if out, err := c.Verify(t.Context(), in); err != nil || !out.SignatureValid {
		t.Fatal("external PKCS1 signature", err)
	}
	in.Message = []byte("altered message")
	_, err = c.Verify(t.Context(), in)
	requireCode(t, err, "KMSInvalidSignatureException")
}
