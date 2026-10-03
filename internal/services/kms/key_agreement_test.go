package kms

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestSDKECDHMatchesAWS(t *testing.T) {
	capture := readCryptoCapture(t, "ecc")
	for _, native := range capture.Keys {
		if native.KeyUsage != types.KeyUsageTypeKeyAgreement {
			continue
		}
		t.Run(string(native.KeySpec), func(t *testing.T) {
			backend := NewMemoryStorage(nil)
			scope := rootMetadata("111111111111", "us-east-1", "aws")
			c := sdkClient(t, NewWithStorage(backend, nil), scope)
			key := createAsymmetricSDKKey(t, c, native.KeySpec, native.KeyUsage)
			if !reflect.DeepEqual(key.KeyAgreementAlgorithms, native.KeyAgreementAlgorithms) || len(key.SigningAlgorithms) != 0 || len(key.EncryptionAlgorithms) != 0 {
				t.Fatal("ECDH metadata differs from AWS")
			}
			public, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(public.KeyAgreementAlgorithms, native.KeyAgreementAlgorithms) {
				t.Fatal("public agreement metadata differs from AWS")
			}
			parsed, err := x509.ParsePKIXPublicKey(public.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			remote, err := parsed.(*ecdsa.PublicKey).ECDH()
			if err != nil {
				t.Fatal(err)
			}
			peer, err := remote.Curve().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			peerDER, err := x509.MarshalPKIXPublicKey(peer.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			want, err := peer.ECDH(remote)
			if err != nil {
				t.Fatal(err)
			}
			alias := "alias/ecdh"
			if _, err := c.CreateAlias(t.Context(), &sdkkms.CreateAliasInput{AliasName: &alias, TargetKeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			c = sdkClient(t, NewWithStorage(backend, nil), scope)
			input := &sdkkms.DeriveSharedSecretInput{KeyId: &alias, PublicKey: peerDER, KeyAgreementAlgorithm: types.KeyAgreementAlgorithmSpecEcdh}
			out, err := c.DeriveSharedSecret(t.Context(), input)
			if err != nil || !bytes.Equal(out.SharedSecret, want) || aws.ToString(out.KeyId) != aws.ToString(key.Arn) || out.KeyOrigin != types.OriginTypeAwsKms || out.KeyAgreementAlgorithm != types.KeyAgreementAlgorithmSpecEcdh {
				t.Fatal("ECDH interoperability", err)
			}
			for _, row := range capture.Observations {
				if row.Spec == string(native.KeySpec) && row.Case == "derive" {
					var nativeOutput struct{ SharedSecretBytes int }
					if err := json.Unmarshal(row.Output, &nativeOutput); err != nil {
						t.Fatal(err)
					}
					if len(out.SharedSecret) != nativeOutput.SharedSecretBytes {
						t.Fatal("shared secret length differs from AWS")
					}
				}
			}
			input.DryRun = aws.Bool(true)
			_, err = c.DeriveSharedSecret(t.Context(), input)
			requireCode(t, err, "DryRunOperationException")
			input.PublicKey = []byte("invalid")
			_, err = c.DeriveSharedSecret(t.Context(), input)
			capture.requireError(t, err, "dry_invalid_public_key", native.KeySpec, native.KeyUsage, "", true)
			input.DryRun = nil
			otherCurve := ecdh.P256()
			if native.KeySpec == types.KeySpecEccNistP256 {
				otherCurve = ecdh.P384()
			}
			wrong, err := otherCurve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			input.PublicKey, err = x509.MarshalPKIXPublicKey(wrong.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.DeriveSharedSecret(t.Context(), input)
			capture.requireError(t, err, "wrong_curve", native.KeySpec, native.KeyUsage, "", true)
			input.PublicKey = public.PublicKey
			if _, err := c.DeriveSharedSecret(t.Context(), input); err != nil {
				t.Fatal("AWS accepts self agreement", err)
			}
			grant := &sdkkms.CreateGrantInput{KeyId: key.KeyId, GranteePrincipal: aws.String("arn:aws:iam::111111111111:root"), Operations: []types.GrantOperation{types.GrantOperationGetPublicKey, types.GrantOperationDeriveSharedSecret}}
			if _, err := c.CreateGrant(t.Context(), grant); err != nil {
				t.Fatal(err)
			}
			grant.Constraints = &types.GrantConstraints{EncryptionContextEquals: map[string]string{"purpose": "probe"}}
			_, err = c.CreateGrant(t.Context(), grant)
			capture.requireError(t, err, "constrained_grant", native.KeySpec, native.KeyUsage, "", true)
			if _, err := c.DisableKey(t.Context(), &sdkkms.DisableKeyInput{KeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			_, err = c.DeriveSharedSecret(t.Context(), input)
			requireCode(t, err, "DisabledException")
			if _, err := c.ScheduleKeyDeletion(t.Context(), &sdkkms.ScheduleKeyDeletionInput{KeyId: key.KeyId, PendingWindowInDays: aws.Int32(7)}); err != nil {
				t.Fatal(err)
			}
			_, err = c.DeriveSharedSecret(t.Context(), input)
			requireCode(t, err, "KMSInvalidStateException")
			if _, err := c.CancelKeyDeletion(t.Context(), &sdkkms.CancelKeyDeletionInput{KeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.EnableKey(t.Context(), &sdkkms.EnableKeyInput{KeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			input.PublicKey = peerDER
			out, err = c.DeriveSharedSecret(t.Context(), input)
			if err != nil || !bytes.Equal(out.SharedSecret, want) {
				t.Fatal("lifecycle lost private material", err)
			}
		})
	}
}

func TestSDKECDHRejectsSigningKeys(t *testing.T) {
	c := sdkClient(t, New(), rootMetadata("111111111111", "us-east-1", "aws"))
	for _, spec := range []types.KeySpec{types.KeySpecEccNistP256, types.KeySpecEccSecgP256k1, types.KeySpecEccNistEdwards25519} {
		key := createAsymmetricSDKKey(t, c, spec, types.KeyUsageTypeSignVerify)
		_, err := c.DeriveSharedSecret(t.Context(), &sdkkms.DeriveSharedSecretInput{KeyId: key.KeyId, PublicKey: []byte("invalid"), KeyAgreementAlgorithm: types.KeyAgreementAlgorithmSpecEcdh})
		requireCode(t, err, "InvalidKeyUsageException")
		if spec != types.KeySpecEccNistP256 {
			_, err = c.CreateKey(t.Context(), &sdkkms.CreateKeyInput{KeySpec: spec, KeyUsage: types.KeyUsageTypeKeyAgreement})
			requireCode(t, err, "ValidationException")
		}
	}
}
