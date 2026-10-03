package kms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func parseECCPublic(t *testing.T, encoded []byte, spec types.KeySpec) crypto.PublicKey {
	t.Helper()
	if spec != types.KeySpecEccSecgP256k1 {
		public, err := x509.ParsePKIXPublicKey(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return public
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(encoded, &spki)
	if err != nil || len(rest) != 0 || !spki.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}) {
		t.Fatal("invalid secp256k1 SPKI", err)
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &oid); err != nil || !oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 10}) {
		t.Fatal("incorrect secp256k1 curve OID", err)
	}
	public, err := secp256k1.ParsePubKey(spki.PublicKey.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func TestSDKECCSigningMatchesAWS(t *testing.T) {
	capture := readCryptoCapture(t, "ecc")
	for _, native := range capture.Keys {
		if native.KeyUsage != types.KeyUsageTypeSignVerify {
			continue
		}
		t.Run(string(native.KeySpec), func(t *testing.T) {
			backend := NewMemoryStorage(nil)
			scope := rootMetadata("111111111111", "us-east-1", "aws")
			c := sdkClient(t, NewWithStorage(backend, nil), scope)
			key := createAsymmetricSDKKey(t, c, native.KeySpec, native.KeyUsage)
			if !reflect.DeepEqual(key.SigningAlgorithms, native.SigningAlgorithms) || len(key.EncryptionAlgorithms) != 0 || len(key.KeyAgreementAlgorithms) != 0 || key.CurrentKeyMaterialId != nil {
				t.Fatal("ECC key metadata differs from AWS")
			}
			public, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId})
			if err != nil {
				t.Fatal(err)
			}
			parsed := parseECCPublic(t, public.PublicKey, native.KeySpec)
			if !reflect.DeepEqual(public.SigningAlgorithms, native.SigningAlgorithms) || public.KeyUsage != native.KeyUsage || public.KeySpec != native.KeySpec || aws.ToString(public.KeyId) != aws.ToString(key.Arn) {
				t.Fatal("ECC public metadata differs from AWS")
			}
			// Exercise the stored PKCS8 key again after replacing the provider.
			c = sdkClient(t, NewWithStorage(backend, nil), scope)
			for _, row := range capture.Observations {
				if row.Spec != string(native.KeySpec) || row.Usage != "SIGN_VERIFY" {
					continue
				}
				if row.Case != "sign" && row.Case != "short_digest" && row.Case != "wrong_algorithm" && row.Case != "dry_sign" && row.Case != "invalid_signature" && row.Case != "dry_invalid_signature" {
					continue
				}
				t.Run(row.Case+"/"+row.SigningAlgorithm+"/"+row.MessageType, func(t *testing.T) {
					message := []byte("stackd ECC interoperability")
					hash := crypto.SHA256
					if row.SigningAlgorithm == "ECDSA_SHA_384" {
						hash = crypto.SHA384
					}
					if row.SigningAlgorithm == "ECDSA_SHA_512" || native.KeySpec == types.KeySpecEccNistEdwards25519 {
						hash = crypto.SHA512
					}
					h := hash.New()
					_, _ = h.Write(message)
					digest := h.Sum(nil)
					if row.MessageType == "DIGEST" {
						message = digest
					}
					if row.MessageType == "EXTERNAL_MU" {
						message = bytes.Repeat([]byte("a"), 64)
					}
					if row.Case == "short_digest" {
						message = []byte("short")
					}
					var err error
					var signed *sdkkms.SignOutput
					if row.Case == "invalid_signature" || row.Case == "dry_invalid_signature" {
						_, err = c.Verify(t.Context(), &sdkkms.VerifyInput{KeyId: key.KeyId, Message: message, MessageType: types.MessageType(row.MessageType), SigningAlgorithm: types.SigningAlgorithmSpec(row.SigningAlgorithm), Signature: []byte("invalid"), DryRun: aws.Bool(row.Case == "dry_invalid_signature")})
					} else {
						signed, err = c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: message, MessageType: types.MessageType(row.MessageType), SigningAlgorithm: types.SigningAlgorithmSpec(row.SigningAlgorithm), DryRun: aws.Bool(row.Case == "dry_sign")})
					}
					if row.Code != "Success" {
						requireCode(t, err, row.Code)
						var apiErr smithy.APIError
						if row.Code != "DryRunOperationException" && (!errors.As(err, &apiErr) || apiErr.ErrorMessage() != row.Error.Message) {
							t.Fatalf("AWS message %q differs from %v", row.Error.Message, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if aws.ToString(signed.KeyId) != aws.ToString(key.Arn) || string(signed.SigningAlgorithm) != row.SigningAlgorithm {
						t.Fatal("signature metadata differs")
					}
					verified, err := c.Verify(t.Context(), &sdkkms.VerifyInput{KeyId: key.KeyId, Message: message, MessageType: types.MessageType(row.MessageType), SigningAlgorithm: signed.SigningAlgorithm, Signature: signed.Signature})
					if err != nil || !verified.SignatureValid {
						t.Fatal("SDK verification", err)
					}
					repeated, err := c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: message, MessageType: types.MessageType(row.MessageType), SigningAlgorithm: signed.SigningAlgorithm})
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Equal(signed.Signature, repeated.Signature) != (native.KeySpec == types.KeySpecEccNistEdwards25519) {
						t.Fatal("signature repeatability differs from AWS")
					}
					switch public := parsed.(type) {
					case *ecdsa.PublicKey:
						if !ecdsa.VerifyASN1(public, digest, signed.Signature) {
							t.Fatal("external ECDSA verification failed")
						}
					case *secp256k1.PublicKey:
						decoded, err := secpecdsa.ParseDERSignature(signed.Signature)
						if err != nil || !decoded.Verify(digest, public) {
							t.Fatal("external secp256k1 verification failed", err)
						}
					case ed25519.PublicKey:
						options := &ed25519.Options{}
						if row.SigningAlgorithm == "ED25519_PH_SHA_512" {
							h := crypto.SHA512.New()
							_, _ = h.Write(message)
							message = h.Sum(nil)
							options.Hash = crypto.SHA512
						}
						if err := ed25519.VerifyWithOptions(public, message, signed.Signature, options); err != nil {
							t.Fatal("external Ed25519 verification failed", err)
						}
					}
				})
			}
			for _, usage := range []types.KeyUsageType{"", types.KeyUsageTypeEncryptDecrypt} {
				_, err := c.CreateKey(t.Context(), &sdkkms.CreateKeyInput{KeySpec: native.KeySpec, KeyUsage: usage})
				requireCode(t, err, "ValidationException")
			}
			if _, err := c.DisableKey(t.Context(), &sdkkms.DisableKeyInput{KeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId}); err != nil {
				t.Fatal("disabled public key retrieval", err)
			}
			_, err = c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: []byte("message"), SigningAlgorithm: native.SigningAlgorithms[0]})
			requireCode(t, err, "DisabledException")
		})
	}
}

func TestVerifyNativeECCSignatures(t *testing.T) {
	// Replay real AWS public signatures through the verifier used by Verify.
	// This checks Ed25519ph's extra hash independently of local Sign.
	capture := readCryptoCapture(t, "ecc")
	publics := map[string]crypto.PublicKey{}
	for _, row := range capture.Observations {
		if row.Usage != "SIGN_VERIFY" || row.Code != "Success" {
			continue
		}
		if row.Case == "public_key" {
			var out sdkkms.GetPublicKeyOutput
			if err := json.Unmarshal(row.Output, &out); err != nil {
				t.Fatal(err)
			}
			publics[row.Spec] = parseECCPublic(t, out.PublicKey, types.KeySpec(row.Spec))
		}
		if row.Case != "sign" {
			continue
		}
		t.Run(row.Spec+"/"+row.SigningAlgorithm+"/"+row.MessageType, func(t *testing.T) {
			var out sdkkms.SignOutput
			if err := json.Unmarshal(row.Output, &out); err != nil {
				t.Fatal(err)
			}
			var algorithm signingAlgorithm
			for _, candidate := range signingAlgorithms(row.Spec) {
				if string(candidate.name) == row.SigningAlgorithm {
					algorithm = candidate
				}
			}
			message := []byte("stackd ECC interoperability")
			if row.MessageType == "DIGEST" {
				h := algorithm.hash.New()
				_, _ = h.Write(message)
				message = h.Sum(nil)
			}
			prepared, options, err := signingMessage(algorithm, row.Spec, row.MessageType, message)
			if err != nil {
				t.Fatal(err)
			}
			if !verifySignature(publics[row.Spec], prepared, out.Signature, options) {
				t.Fatal("native AWS signature rejected")
			}
		})
	}
}
