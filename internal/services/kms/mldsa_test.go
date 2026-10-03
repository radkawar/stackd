package kms

import (
	"bytes"
	"crypto/sha3"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/metacubex/mldsa/mldsa"
)

func parseMLDSAPublic(t *testing.T, encoded []byte) *mldsa.PublicKey {
	t.Helper()
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(encoded, &spki)
	if err != nil || len(rest) != 0 || len(spki.Algorithm.Parameters.FullBytes) != 0 {
		t.Fatal("invalid ML-DSA SPKI", err)
	}
	var public *mldsa.PublicKey
	switch spki.Algorithm.Algorithm.String() {
	case "2.16.840.1.101.3.4.3.17":
		public, err = mldsa.NewPublicKey44(spki.PublicKey.Bytes)
	case "2.16.840.1.101.3.4.3.18":
		public, err = mldsa.NewPublicKey65(spki.PublicKey.Bytes)
	case "2.16.840.1.101.3.4.3.19":
		public, err = mldsa.NewPublicKey87(spki.PublicKey.Bytes)
	default:
		t.Fatal("unexpected ML-DSA public-key OID", spki.Algorithm.Algorithm)
	}
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func externalMLDSAMu(public *mldsa.PublicKey, message []byte) []byte {
	// Independent client-side FIPS 204 calculation. The native probe computes
	// this in Python and confirms cross-verification with AWS RAW signatures.
	hash := sha3.NewSHAKE256()
	_, _ = hash.Write(public.Bytes())
	tr := make([]byte, 64)
	_, _ = hash.Read(tr)
	hash.Reset()
	_, _ = hash.Write(tr)
	_, _ = hash.Write([]byte{0, 0})
	_, _ = hash.Write(message)
	mu := make([]byte, 64)
	_, _ = hash.Read(mu)
	return mu
}

func TestSDKMLDSAMatchesAWS(t *testing.T) {
	capture := readCryptoCapture(t, "mldsa")
	for _, native := range capture.Keys {
		t.Run(string(native.KeySpec), func(t *testing.T) {
			backend := NewMemoryStorage(nil)
			scope := rootMetadata("111111111111", "us-east-1", "aws")
			c := sdkClient(t, NewWithStorage(backend, nil), scope)
			key := createAsymmetricSDKKey(t, c, native.KeySpec, native.KeyUsage)
			if !reflect.DeepEqual(key.SigningAlgorithms, native.SigningAlgorithms) || key.CurrentKeyMaterialId != nil || len(key.EncryptionAlgorithms) != 0 || len(key.KeyAgreementAlgorithms) != 0 || len(key.MacAlgorithms) != 0 {
				t.Fatal("ML-DSA metadata differs from AWS")
			}
			public, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId})
			if err != nil {
				t.Fatal(err)
			}
			parsed := parseMLDSAPublic(t, public.PublicKey)
			if !reflect.DeepEqual(public.SigningAlgorithms, native.SigningAlgorithms) || public.KeySpec != native.KeySpec || public.KeyUsage != native.KeyUsage || aws.ToString(public.KeyId) != aws.ToString(key.Arn) {
				t.Fatal("public-key metadata differs from AWS")
			}
			// The production storage decoder must recover the signing seed when
			// replacing the service instance, for every ML-DSA parameter set.
			c = sdkClient(t, NewWithStorage(backend, nil), scope)
			message := []byte("stackd ML-DSA interoperability")
			mu := externalMLDSAMu(parsed, message)
			algorithm := types.SigningAlgorithmSpecMlDsaShake256
			for _, messageType := range []types.MessageType{"", types.MessageTypeExternalMu} {
				input := message
				if messageType == types.MessageTypeExternalMu {
					input = mu
				}
				signed, err := c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: input, MessageType: messageType, SigningAlgorithm: algorithm})
				if err != nil {
					t.Fatal(err)
				}
				if signed.SigningAlgorithm != algorithm || aws.ToString(signed.KeyId) != aws.ToString(key.Arn) {
					t.Fatal("signature metadata differs from AWS")
				}
				for _, row := range capture.Observations {
					if row.Spec == string(native.KeySpec) && row.Case == "sign_raw" {
						var nativeSignature sdkkms.SignOutput
						if err := json.Unmarshal(row.Output, &nativeSignature); err != nil {
							t.Fatal(err)
						}
						if len(signed.Signature) != len(nativeSignature.Signature) {
							t.Fatal("signature size differs from AWS")
						}
					}
				}
				if err := mldsa.Verify(parsed, message, signed.Signature, ""); err != nil {
					t.Fatal("external RAW verification", err)
				}
				if err := mldsa.VerifyExternalMu(parsed, mu, signed.Signature); err != nil {
					t.Fatal("external mu verification", err)
				}
				for _, verifyType := range []types.MessageType{types.MessageTypeRaw, types.MessageTypeExternalMu} {
					verifyMessage := message
					if verifyType == types.MessageTypeExternalMu {
						verifyMessage = mu
					}
					out, err := c.Verify(t.Context(), &sdkkms.VerifyInput{KeyId: key.KeyId, Message: verifyMessage, MessageType: verifyType, SigningAlgorithm: algorithm, Signature: signed.Signature})
					if err != nil || !out.SignatureValid || out.SigningAlgorithm != algorithm || aws.ToString(out.KeyId) != aws.ToString(key.Arn) {
						t.Fatal("SDK RAW/external-mu cross-verification", err)
					}
				}
				repeat, err := c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: input, MessageType: messageType, SigningAlgorithm: algorithm})
				if err != nil || bytes.Equal(signed.Signature, repeat.Signature) {
					t.Fatal("ML-DSA signatures must be randomized", err)
				}
				_, err = c.Verify(t.Context(), &sdkkms.VerifyInput{KeyId: key.KeyId, Message: input, MessageType: messageType, SigningAlgorithm: algorithm, Signature: signed.Signature, DryRun: aws.Bool(true)})
				requireCode(t, err, "DryRunOperationException")
				signed.Signature[0] ^= 1
				for _, dry := range []bool{false, true} {
					_, err = c.Verify(t.Context(), &sdkkms.VerifyInput{KeyId: key.KeyId, Message: input, MessageType: messageType, SigningAlgorithm: algorithm, Signature: signed.Signature, DryRun: &dry})
					capture.requireError(t, err, "invalid_signature", native.KeySpec, native.KeyUsage, "", true)
				}
			}
			for _, row := range capture.Observations {
				if row.Spec != string(native.KeySpec) {
					continue
				}
				var err error
				switch row.Case {
				case "default_usage", "encryption_usage", "agreement_usage":
					usage := types.KeyUsageType("")
					if row.Case == "encryption_usage" {
						usage = types.KeyUsageTypeEncryptDecrypt
					}
					if row.Case == "agreement_usage" {
						usage = types.KeyUsageTypeKeyAgreement
					}
					_, err = c.CreateKey(t.Context(), &sdkkms.CreateKeyInput{KeySpec: native.KeySpec, KeyUsage: usage})
				case "sign_digest", "mu_length_1", "mu_length_63", "mu_length_65", "wrong_algorithm":
					in := &sdkkms.SignInput{KeyId: key.KeyId, Message: mu, MessageType: types.MessageType(row.MessageType), SigningAlgorithm: types.SigningAlgorithmSpec(row.SigningAlgorithm)}
					if row.Case == "mu_length_1" {
						in.Message = []byte("x")
					}
					if row.Case == "mu_length_63" {
						in.Message = mu[:63]
					}
					if row.Case == "mu_length_65" {
						in.Message = append(bytes.Clone(mu), 0)
					}
					_, err = c.Sign(t.Context(), in)
				default:
					continue
				}
				capture.requireError(t, err, row.Case, native.KeySpec, native.KeyUsage, "", true)
			}
			for _, size := range []int{0, 4096, 4097} {
				_, err := c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: bytes.Repeat([]byte("x"), size), SigningAlgorithm: algorithm})
				if size == 4096 {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					requireCode(t, err, "ValidationException")
				}
			}
			// ML-DSA is not a modeled data-key-pair specification. The generated
			// frontend rejects it before the shared key-material generator runs.
			_, err = c.GenerateDataKeyPair(t.Context(), &sdkkms.GenerateDataKeyPairInput{KeyId: key.KeyId, KeyPairSpec: types.DataKeyPairSpec(native.KeySpec)})
			requireCode(t, err, "ValidationException")
			if _, err := c.DisableKey(t.Context(), &sdkkms.DisableKeyInput{KeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			if out, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId}); err != nil || !bytes.Equal(out.PublicKey, public.PublicKey) {
				t.Fatal("disabled public-key retrieval", err)
			}
			_, err = c.Sign(t.Context(), &sdkkms.SignInput{KeyId: key.KeyId, Message: message, SigningAlgorithm: algorithm})
			requireCode(t, err, "DisabledException")
			if _, err := c.ScheduleKeyDeletion(t.Context(), &sdkkms.ScheduleKeyDeletionInput{KeyId: key.KeyId, PendingWindowInDays: aws.Int32(7)}); err != nil {
				t.Fatal(err)
			}
			_, err = c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId})
			requireCode(t, err, "KMSInvalidStateException")
		})
	}
}

func TestVerifyNativeMLDSASignatures(t *testing.T) {
	capture := readCryptoCapture(t, "mldsa")
	publics := map[string]*mldsa.PublicKey{}
	for _, row := range capture.Observations {
		if row.Code != "Success" {
			continue
		}
		if row.Case == "public_key" {
			var out sdkkms.GetPublicKeyOutput
			if err := json.Unmarshal(row.Output, &out); err != nil {
				t.Fatal(err)
			}
			publics[row.Spec] = parseMLDSAPublic(t, out.PublicKey)
		}
		if row.Case != "sign_raw" && row.Case != "sign_mu" {
			continue
		}
		t.Run(row.Spec+"/"+row.Case, func(t *testing.T) {
			var out sdkkms.SignOutput
			if err := json.Unmarshal(row.Output, &out); err != nil {
				t.Fatal(err)
			}
			message := []byte("stackd ML-DSA interoperability")
			mu := externalMLDSAMu(publics[row.Spec], message)
			if !verifySignature(publics[row.Spec], message, out.Signature, mldsaSignerOptions{}) {
				t.Fatal("native RAW signature rejected")
			}
			if !verifySignature(publics[row.Spec], mu, out.Signature, mldsaSignerOptions{externalMu: true}) {
				t.Fatal("native external-mu signature rejected")
			}
		})
	}
}
