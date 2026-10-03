package stackd_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
	"stackd/clock"
)

func kmsExternalKey(t *testing.T, c *kms.Client, spec types.KeySpec, usage types.KeyUsageType, multi bool) *types.KeyMetadata {
	t.Helper()
	out, err := c.CreateKey(t.Context(), &kms.CreateKeyInput{Origin: types.OriginTypeExternal, KeySpec: spec, KeyUsage: usage, MultiRegion: aws.Bool(multi)})
	if err != nil {
		t.Fatal(err)
	}
	if out.KeyMetadata.KeyState != types.KeyStatePendingImport || out.KeyMetadata.CurrentKeyMaterialId != nil || out.KeyMetadata.Origin != types.OriginTypeExternal || out.KeyMetadata.ExpirationModel != "" {
		t.Fatal("external key was not created without material", out)
	}
	return out.KeyMetadata
}

func kmsImportParameters(t *testing.T, c *kms.Client, id *string, algorithm types.AlgorithmSpec, spec types.WrappingKeySpec) *kms.GetParametersForImportOutput {
	t.Helper()
	p, err := c.GetParametersForImport(t.Context(), &kms.GetParametersForImportInput{KeyId: id, WrappingAlgorithm: algorithm, WrappingKeySpec: spec})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func importOpenSSL(t *testing.T, input []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "openssl", args...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl %s: %v: %s", args[0], err, stderr.String())
	}
	return out
}

func kmsImportRequest(t *testing.T, id *string, p *kms.GetParametersForImportOutput, material []byte, algorithm types.AlgorithmSpec) *kms.ImportKeyMaterialInput {
	t.Helper()
	decoded, err := x509.ParsePKIXPublicKey(p.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public := decoded.(*rsa.PublicKey)
	hash := crypto.SHA256
	if strings.HasSuffix(string(algorithm), "SHA_1") {
		hash = crypto.SHA1
	}
	var suffix []byte
	if strings.HasPrefix(string(algorithm), "RSA_AES_") {
		kek := make([]byte, 32)
		_, _ = rand.Read(kek)
		suffix = importOpenSSL(t, material, "enc", "-id-aes256-wrap-pad", "-K", hex.EncodeToString(kek), "-iv", "A65959A6")
		material = kek
		defer clear(kek)
	}
	wrapped, err := rsa.EncryptOAEP(hash.New(), rand.Reader, public, material, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &kms.ImportKeyMaterialInput{KeyId: id, ImportToken: p.ImportToken, EncryptedKeyMaterial: append(wrapped, suffix...), ExpirationModel: types.ExpirationModelTypeKeyMaterialDoesNotExpire}
}

func kmsImportHistory(t *testing.T, c *kms.Client, id *string) []types.RotationsListEntry {
	t.Helper()
	out, err := c.ListKeyRotations(t.Context(), &kms.ListKeyRotationsInput{KeyId: id, IncludeKeyMaterial: types.IncludeKeyMaterialAllKeyMaterial})
	if err != nil {
		t.Fatal(err)
	}
	return out.Rotations
}

func kmsImportMetadata(t *testing.T, c *kms.Client, id *string, state types.KeyState) *types.KeyMetadata {
	t.Helper()
	out, err := c.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id})
	if err != nil {
		t.Fatal(err)
	}
	if out.KeyMetadata.KeyState != state {
		t.Fatalf("key state %s; want %s", out.KeyMetadata.KeyState, state)
	}
	return out.KeyMetadata
}

func TestKMSImportedSymmetricNativeLifecycle(t *testing.T) {
	codes := kmsNativeCodes(t, "imports")
	source := clock.NewManual(time.Now().UTC())
	c := clockCloud(t, stackd.Config{Clock: source}).kms("test", "test", "")
	k := kmsExternalKey(t, c, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, false)
	id := k.KeyId
	_, err := c.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: id})
	checkKMSNative(t, codes, "symmetric_delete_empty", err)
	_, err = c.EnableKeyRotation(t.Context(), &kms.EnableKeyRotationInput{KeyId: id})
	checkKMSNative(t, codes, "pending_enable-key-rotation", err)
	_, err = c.DisableKeyRotation(t.Context(), &kms.DisableKeyRotationInput{KeyId: id})
	checkKMSNative(t, codes, "pending_disable-key-rotation", err)
	_, err = c.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: id})
	assertAPIError(t, err, "KMSInvalidStateException")
	p := kmsImportParameters(t, c, id, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	if !p.ParametersValidTo.Equal(source.Now().Add(24*time.Hour).Truncate(time.Millisecond)) || aws.ToString(p.KeyId) != aws.ToString(k.Arn) {
		t.Fatal("invalid wrapping parameters", p.ParametersValidTo)
	}
	// Issuing a newer wrapping key does not revoke a previous pair.
	_ = kmsImportParameters(t, c, id, types.AlgorithmSpecRsaesOaepSha1, types.WrappingKeySpecRsa3072)
	a := kmsImportRequest(t, id, p, bytes.Repeat([]byte{'A'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	a.KeyMaterialDescription = aws.String("first material")
	first, err := c.ImportKeyMaterial(t.Context(), a)
	checkKMSNative(t, codes, "initial_import_old_token", err)
	if len(aws.ToString(first.KeyMaterialId)) != 64 {
		t.Fatal("missing imported identity", first)
	}
	_, err = c.ImportKeyMaterial(t.Context(), a)
	if err != nil {
		t.Fatal("token was consumed by import", err)
	}
	plain := []byte("imported encryption")
	encrypted, err := c.Encrypt(t.Context(), &kms.EncryptInput{KeyId: id, Plaintext: plain})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: id})
	checkKMSNative(t, codes, "imported_rotate-key-on-demand", err)
	b := kmsImportRequest(t, id, p, bytes.Repeat([]byte{'B'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	_, err = c.ImportKeyMaterial(t.Context(), b)
	assertAPIError(t, err, "IncorrectKeyMaterialException")
	b.ImportType = types.ImportTypeNewKeyMaterial
	b.KeyMaterialDescription = aws.String("pending second")
	second, err := c.ImportKeyMaterial(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	history := kmsImportHistory(t, c, id)
	if len(history) != 2 || history[0].KeyMaterialState != types.KeyMaterialStateCurrent || history[1].KeyMaterialState != types.KeyMaterialStatePendingRotation || history[1].ImportState != types.ImportStateImported {
		t.Fatal("pending rotation history", history)
	}
	_, err = c.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: id, KeyMaterialId: second.KeyMaterialId})
	checkKMSNative(t, codes, "delete_pending_rotation", err)
	if len(kmsImportHistory(t, c, id)) != 1 {
		t.Fatal("discarded material retained")
	}
	b.KeyMaterialDescription = nil
	readded, err := c.ImportKeyMaterial(t.Context(), b)
	if err != nil || aws.ToString(readded.KeyMaterialId) != aws.ToString(second.KeyMaterialId) {
		t.Fatal("material identity changed", readded, err)
	}
	_, err = c.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: id})
	checkKMSNative(t, codes, "rotate_imported", err)
	advanceClock(t, source, 2*time.Minute)
	history = kmsImportHistory(t, c, id)
	if history[1].KeyMaterialState != types.KeyMaterialStateCurrent || history[1].KeyMaterialDescription != nil || history[1].RotationType != types.RotationTypeOnDemand {
		t.Fatal("rotation did not promote imported material", history)
	}
	decrypted, err := c.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	if err != nil || !bytes.Equal(decrypted.Plaintext, plain) {
		t.Fatal("rotation lost previous ciphertext", err)
	}
	_, err = c.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: id, KeyMaterialId: first.KeyMaterialId})
	checkKMSNative(t, codes, "delete_noncurrent", err)
	m := kmsImportMetadata(t, c, id, types.KeyStatePendingImport)
	if aws.ToString(m.CurrentKeyMaterialId) != aws.ToString(second.KeyMaterialId) || m.ExpirationModel != "" {
		t.Fatal("missing old material metadata", m)
	}
	_, err = c.Encrypt(t.Context(), &kms.EncryptInput{KeyId: id, Plaintext: plain})
	assertAPIError(t, err, "KMSInvalidStateException")
	if _, err := c.ImportKeyMaterial(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: id}); err != nil {
		t.Fatal(err)
	}
	b.ImportType = types.ImportTypeExistingKeyMaterial
	_, err = c.ImportKeyMaterial(t.Context(), b)
	checkKMSNative(t, codes, "reimport_disabled", err)
	kmsImportMetadata(t, c, id, types.KeyStateEnabled)
	b.ExpirationModel, b.ValidTo = types.ExpirationModelTypeKeyMaterialExpires, aws.Time(source.Now().Add(20*time.Second))
	if _, err := c.ImportKeyMaterial(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 20*time.Second)
	kmsImportMetadata(t, c, id, types.KeyStatePendingImport)
	b.ExpirationModel, b.ValidTo = types.ExpirationModelTypeKeyMaterialDoesNotExpire, nil
	_, err = c.ImportKeyMaterial(t.Context(), b)
	checkKMSNative(t, codes, "reimport_expired_current", err)
	for _, name := range []string{"delete_current", "delete_current_again"} {
		_, err = c.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: id})
		checkKMSNative(t, codes, name, err)
	}
	if _, err := c.ScheduleKeyDeletion(t.Context(), &kms.ScheduleKeyDeletionInput{KeyId: id, PendingWindowInDays: aws.Int32(7)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CancelKeyDeletion(t.Context(), &kms.CancelKeyDeletionInput{KeyId: id}); err != nil {
		t.Fatal(err)
	}
	kmsImportMetadata(t, c, id, types.KeyStatePendingImport)
}
