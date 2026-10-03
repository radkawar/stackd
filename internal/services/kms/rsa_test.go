package kms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

type cryptoCapture struct {
	Keys         []types.KeyMetadata
	Observations []struct {
		Case, Spec, Usage, Code, EncryptionAlgorithm, SigningAlgorithm, MessageType string
		Output                                                                      json.RawMessage
		Error                                                                       struct{ Message string }
	}
}

func readCryptoCapture(t *testing.T, family string) cryptoCapture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/kms/" + family + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var capture cryptoCapture
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	return capture
}

func (capture cryptoCapture) requireError(t *testing.T, err error, name string, spec types.KeySpec, usage types.KeyUsageType, algorithm string, message bool) {
	t.Helper()
	for _, row := range capture.Observations {
		if row.Case != name || row.Spec != string(spec) || row.Usage != string(usage) || (algorithm != "" && row.EncryptionAlgorithm != algorithm && row.SigningAlgorithm != algorithm) {
			continue
		}
		requireCode(t, err, row.Code)
		var apiErr smithy.APIError
		want := row.Error.Message
		var generic *smithy.GenericAPIError
		if want == "" && errors.As(err, &generic) {
			// The SDK supplies this default for unmodeled errors with no message.
			// ecc.json includes native Go SDK observations of this behavior.
			want = "UnknownError"
		}
		if message && (!errors.As(err, &apiErr) || apiErr.ErrorMessage() != want) {
			t.Fatalf("%s differs from AWS message %q: %v", name, row.Error.Message, err)
		}
		return
	}
	t.Fatalf("missing native observation: %s %s %s %s", name, spec, usage, algorithm)
}

func createAsymmetricSDKKey(t *testing.T, c *sdkkms.Client, spec types.KeySpec, usage types.KeyUsageType) *types.KeyMetadata {
	t.Helper()
	out, err := c.CreateKey(t.Context(), &sdkkms.CreateKeyInput{KeySpec: spec, KeyUsage: usage})
	if err != nil {
		t.Fatal(err)
	}
	return out.KeyMetadata
}

func publicRSAKey(t *testing.T, encoded []byte) *rsa.PublicKey {
	t.Helper()
	public, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	rsaPublic, ok := public.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T", public)
	}
	return rsaPublic
}

func TestSDKRSAEncryptionMatchesAWS(t *testing.T) {
	capture := readCryptoCapture(t, "rsa")
	for _, native := range capture.Keys {
		if native.KeySpec == types.KeySpecSymmetricDefault || native.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
			continue
		}
		t.Run(string(native.KeySpec), func(t *testing.T) {
			backend := NewMemoryStorage(nil)
			scope := rootMetadata("111111111111", "us-east-1", "aws")
			c := sdkClient(t, NewWithStorage(backend, nil), scope)
			key := createAsymmetricSDKKey(t, c, native.KeySpec, native.KeyUsage)
			if key.CurrentKeyMaterialId != nil || !reflect.DeepEqual(key.EncryptionAlgorithms, native.EncryptionAlgorithms) || len(key.SigningAlgorithms) != 0 || len(key.MacAlgorithms) != 0 {
				t.Fatalf("RSA metadata differs from AWS: %+v", key)
			}
			public, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId})
			if err != nil {
				t.Fatal(err)
			}
			parsed := publicRSAKey(t, public.PublicKey)
			if parsed.N.BitLen() != rsaBits(string(native.KeySpec)) || public.KeySpec != native.KeySpec || public.KeyUsage != native.KeyUsage || aws.ToString(public.KeyId) != aws.ToString(key.Arn) || !reflect.DeepEqual(public.EncryptionAlgorithms, native.EncryptionAlgorithms) {
				t.Fatal("public key metadata differs from AWS")
			}
			alias := "alias/rsa-encryption"
			if _, err := c.CreateAlias(t.Context(), &sdkkms.CreateAliasInput{AliasName: &alias, TargetKeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			// Reconstruct the provider before decrypting: the typed repository must
			// retain the actual private key, not just the public metadata.
			c = sdkClient(t, NewWithStorage(backend, nil), scope)
			for _, algorithm := range native.EncryptionAlgorithms {
				t.Run(string(algorithm), func(t *testing.T) {
					hash := crypto.SHA256
					if algorithm == types.EncryptionAlgorithmSpecRsaesOaepSha1 {
						hash = crypto.SHA1
					}
					message := []byte("stackd RSA interoperability")
					external, err := rsa.EncryptOAEP(hash.New(), rand.Reader, parsed, message, nil)
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := c.Decrypt(t.Context(), &sdkkms.DecryptInput{KeyId: &alias, CiphertextBlob: external, EncryptionAlgorithm: algorithm, EncryptionContext: map[string]string{}})
					if err != nil || !bytes.Equal(decoded.Plaintext, message) || decoded.KeyMaterialId != nil || decoded.EncryptionAlgorithm != algorithm || aws.ToString(decoded.KeyId) != aws.ToString(key.Arn) {
						t.Fatalf("external OAEP decrypt failed: %v", err)
					}
					maximum := parsed.Size() - 2*hash.Size() - 2
					plaintext := bytes.Repeat([]byte("a"), maximum)
					encrypted, err := c.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: &alias, Plaintext: plaintext, EncryptionAlgorithm: algorithm, EncryptionContext: map[string]string{}})
					if err != nil {
						t.Fatal(err)
					}
					if len(encrypted.CiphertextBlob) != parsed.Size() || encrypted.EncryptionAlgorithm != algorithm || aws.ToString(encrypted.KeyId) != aws.ToString(key.Arn) {
						t.Fatal("RSA ciphertext is not a raw modulus-sized value")
					}
					decoded, err = c.Decrypt(t.Context(), &sdkkms.DecryptInput{KeyId: key.KeyId, CiphertextBlob: encrypted.CiphertextBlob, EncryptionAlgorithm: algorithm})
					if err != nil || !bytes.Equal(decoded.Plaintext, plaintext) {
						t.Fatalf("maximum plaintext round trip: %v", err)
					}
					_, err = c.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: key.KeyId, Plaintext: append(plaintext, 'a'), EncryptionAlgorithm: algorithm})
					capture.requireError(t, err, "encrypt_too_large", native.KeySpec, native.KeyUsage, string(algorithm), true)
					_, err = c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: external, EncryptionAlgorithm: algorithm})
					capture.requireError(t, err, "decrypt_no_key", native.KeySpec, native.KeyUsage, string(algorithm), true)
					_, err = c.Decrypt(t.Context(), &sdkkms.DecryptInput{KeyId: key.KeyId, CiphertextBlob: external})
					capture.requireError(t, err, "decrypt_default_algorithm", native.KeySpec, native.KeyUsage, "", false)
					_, err = c.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: key.KeyId, Plaintext: message, EncryptionAlgorithm: algorithm, EncryptionContext: map[string]string{"purpose": "probe"}})
					capture.requireError(t, err, "encryption_context", native.KeySpec, native.KeyUsage, string(algorithm), true)
					for _, dry := range []bool{false, true} {
						name := "invalid_ciphertext"
						if dry {
							name = "dry_invalid_ciphertext"
						}
						_, err = c.Decrypt(t.Context(), &sdkkms.DecryptInput{KeyId: key.KeyId, CiphertextBlob: bytes.Repeat([]byte("x"), parsed.Size()), EncryptionAlgorithm: algorithm, DryRun: &dry})
						capture.requireError(t, err, name, native.KeySpec, native.KeyUsage, string(algorithm), true)
					}
					_, err = c.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: key.KeyId, Plaintext: message, EncryptionAlgorithm: algorithm, DryRun: aws.Bool(true)})
					requireCode(t, err, "DryRunOperationException")
				})
			}
			_, err = c.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: key.KeyId, Plaintext: []byte("message")})
			capture.requireError(t, err, "encrypt_default_algorithm", native.KeySpec, native.KeyUsage, "", false)
			if _, err := c.DisableKey(t.Context(), &sdkkms.DisableKeyInput{KeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			disabledPublic, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId})
			if err != nil || !bytes.Equal(disabledPublic.PublicKey, public.PublicKey) {
				t.Fatal("disabled public key retrieval differs from AWS", err)
			}
			_, err = c.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: key.KeyId, Plaintext: []byte("message"), EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256})
			requireCode(t, err, "DisabledException")
			if _, err := c.ScheduleKeyDeletion(t.Context(), &sdkkms.ScheduleKeyDeletionInput{KeyId: key.KeyId, PendingWindowInDays: aws.Int32(7)}); err != nil {
				t.Fatal(err)
			}
			_, err = c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId})
			capture.requireError(t, err, "deleting_public_key", native.KeySpec, native.KeyUsage, "", false)
			if _, err := c.CancelKeyDeletion(t.Context(), &sdkkms.CancelKeyDeletionInput{KeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.GetPublicKey(t.Context(), &sdkkms.GetPublicKeyInput{KeyId: key.KeyId}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSDKRSAReEncryptAcrossAlgorithms(t *testing.T) {
	c := sdkClient(t, New(), rootMetadata("111111111111", "us-east-1", "aws"))
	one := createAsymmetricSDKKey(t, c, types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt)
	two := createAsymmetricSDKKey(t, c, types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt)
	symmetric := createSDKKey(t, c)
	message := []byte("reencryption interoperability")
	current, err := c.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: one.KeyId, Plaintext: message, EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha1})
	if err != nil {
		t.Fatal(err)
	}
	algorithm, source, blob := current.EncryptionAlgorithm, one, current.CiphertextBlob
	var encryptionContext map[string]string
	for _, destination := range []struct {
		key       *types.KeyMetadata
		algorithm types.EncryptionAlgorithmSpec
		context   map[string]string
	}{
		{two, types.EncryptionAlgorithmSpecRsaesOaepSha256, nil},
		{symmetric, types.EncryptionAlgorithmSpecSymmetricDefault, map[string]string{"purpose": "migration"}},
		{one, types.EncryptionAlgorithmSpecRsaesOaepSha256, nil},
	} {
		out, err := c.ReEncrypt(t.Context(), &sdkkms.ReEncryptInput{SourceKeyId: source.KeyId, CiphertextBlob: blob, SourceEncryptionAlgorithm: algorithm, SourceEncryptionContext: encryptionContext, DestinationKeyId: destination.key.KeyId, DestinationEncryptionAlgorithm: destination.algorithm, DestinationEncryptionContext: destination.context})
		if err != nil {
			t.Fatal(err)
		}
		if out.SourceEncryptionAlgorithm != algorithm || out.DestinationEncryptionAlgorithm != destination.algorithm || aws.ToString(out.SourceKeyId) != aws.ToString(source.Arn) || aws.ToString(out.KeyId) != aws.ToString(destination.key.Arn) || (out.SourceKeyMaterialId != nil) != (source == symmetric) || (out.DestinationKeyMaterialId != nil) != (destination.key == symmetric) {
			t.Fatal("re-encryption metadata differs from AWS")
		}
		plain, err := c.Decrypt(t.Context(), &sdkkms.DecryptInput{KeyId: destination.key.KeyId, CiphertextBlob: out.CiphertextBlob, EncryptionAlgorithm: destination.algorithm, EncryptionContext: destination.context})
		if err != nil || !bytes.Equal(plain.Plaintext, message) {
			t.Fatal("re-encryption lost plaintext", err)
		}
		source, algorithm, encryptionContext, blob = destination.key, destination.algorithm, destination.context, out.CiphertextBlob
	}
}
