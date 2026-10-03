package stackd_test

import (
	"bytes"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

func TestKMSImportedMultiRegionStorageRotationAndExpiry(t *testing.T) {
	codes := kmsNativeCodes(t, "imports_multi_region")
	source := clock.NewManual(time.Now().UTC().Truncate(time.Second))
	backends := storage.NewMemory()
	backend := &failingReplicaStorage{Storage: backends.KMS}
	backends.KMS = backend
	config := stackd.Config{Clock: source, Storage: backends}
	cloud, err := stackd.New(config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(cloud)
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = cloud.Close() })
	c := cloudClients{server}
	east, west := c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
	k := kmsExternalKey(t, east, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, true)
	id := k.KeyId
	_, err = east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-west-2")})
	checkKMSNative(t, codes, "replicate_pending_import", err)
	p := kmsImportParameters(t, east, id, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	a := kmsImportRequest(t, id, p, bytes.Repeat([]byte{'A'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	a.KeyMaterialDescription = aws.String("primary first")
	first, err := east.ImportKeyMaterial(t.Context(), a)
	checkKMSNative(t, codes, "primary_first_import", err)
	_, err = east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-west-2")})
	checkKMSNative(t, codes, "replicate_imported_primary", err)
	advanceClock(t, source, 5*time.Second)
	kmsImportMetadata(t, west, id, types.KeyStatePendingImport)
	history := kmsImportHistory(t, west, id)
	if len(history) != 1 || history[0].ImportState != types.ImportStatePendingImport || aws.ToString(history[0].KeyMaterialDescription) != "primary first" || aws.ToString(history[0].KeyMaterialId) != aws.ToString(first.KeyMaterialId) {
		t.Fatal("replica lost shared metadata", history)
	}
	_, err = west.ImportKeyMaterial(t.Context(), a)
	assertAPIError(t, err, "ValidationException") // Description is primary-owned.
	noDescription := *a
	noDescription.KeyMaterialDescription = nil
	_, err = west.ImportKeyMaterial(t.Context(), &noDescription)
	assertAPIError(t, err, "InvalidImportTokenException") // Tokens are regional.
	wp := kmsImportParameters(t, west, id, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	wa := kmsImportRequest(t, id, wp, bytes.Repeat([]byte{'A'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	if _, err := west.ImportKeyMaterial(t.Context(), wa); err != nil {
		t.Fatal(err)
	}
	before, err := east.Encrypt(t.Context(), &kms.EncryptInput{KeyId: id, Plaintext: []byte("shared imported bytes")})
	if err != nil {
		t.Fatal(err)
	}
	b := kmsImportRequest(t, id, p, bytes.Repeat([]byte{'B'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	b.ImportType = types.ImportTypeNewKeyMaterial
	second, err := east.ImportKeyMaterial(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = east.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: id})
	checkKMSNative(t, codes, "rotate_before_replica_import", err)
	wb := kmsImportRequest(t, id, wp, bytes.Repeat([]byte{'B'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	if _, err := west.ImportKeyMaterial(t.Context(), wb); err != nil {
		t.Fatal(err)
	}
	backend.fail.Store(true)
	_, err = east.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: id, KeyMaterialId: second.KeyMaterialId})
	assertAPIError(t, err, "KMSInternalException")
	backend.fail.Store(false)
	for _, client := range []*kms.Client{east, west} {
		history := kmsImportHistory(t, client, id)
		if len(history) != 2 || history[1].ImportState != types.ImportStateImported {
			t.Fatal("failed deletion committed material loss", history)
		}
	}
	_, err = east.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: id, KeyMaterialId: second.KeyMaterialId})
	checkKMSNative(t, codes, "delete_primary_pending", err)
	if len(kmsImportHistory(t, west, id)) != 1 {
		t.Fatal("primary pending deletion did not reach replica")
	}
	if _, err := east.ImportKeyMaterial(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if _, err := west.ImportKeyMaterial(t.Context(), wb); err != nil {
		t.Fatal(err)
	}
	_, err = east.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: id})
	checkKMSNative(t, codes, "rotate_imported_multi", err)
	server.Close()
	if err := cloud.Close(); err != nil {
		t.Fatal(err)
	}
	c = clockCloud(t, config)
	east, west = c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
	advanceClock(t, source, 2*time.Minute)
	for _, client := range []*kms.Client{east, west} {
		m := kmsImportMetadata(t, client, id, types.KeyStateEnabled)
		if aws.ToString(m.CurrentKeyMaterialId) != aws.ToString(second.KeyMaterialId) {
			t.Fatal("rotation lost imported identity")
		}
		out, err := client.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: before.CiphertextBlob})
		if err != nil || string(out.Plaintext) != "shared imported bytes" {
			t.Fatal("rotation lost prior imported ciphertext", err)
		}
	}
	// The original token/wrapping pairs survive service reconstruction.
	b.ImportType, b.ExpirationModel, b.ValidTo = types.ImportTypeExistingKeyMaterial, types.ExpirationModelTypeKeyMaterialExpires, aws.Time(source.Now().Add(20*time.Second))
	if _, err := east.ImportKeyMaterial(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 20*time.Second)
	kmsImportMetadata(t, east, id, types.KeyStatePendingImport)
	kmsImportMetadata(t, west, id, types.KeyStateEnabled)
	if _, err := west.Encrypt(t.Context(), &kms.EncryptInput{KeyId: id, Plaintext: []byte("regional expiry")}); err != nil {
		t.Fatal(err)
	}
	b.ExpirationModel, b.ValidTo = types.ExpirationModelTypeKeyMaterialDoesNotExpire, nil
	if _, err := east.ImportKeyMaterial(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	_, err = west.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: id, KeyMaterialId: first.KeyMaterialId})
	checkKMSNative(t, codes, "delete_replica_noncurrent", err)
	kmsImportMetadata(t, west, id, types.KeyStatePendingImport)
	kmsImportMetadata(t, east, id, types.KeyStateEnabled)
	if _, err := west.ImportKeyMaterial(t.Context(), wa); err != nil {
		t.Fatal(err)
	}
	if _, err := east.UpdatePrimaryRegion(t.Context(), &kms.UpdatePrimaryRegionInput{KeyId: id, PrimaryRegion: aws.String("us-west-2")}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 5*time.Second)
	wa.KeyMaterialDescription = aws.String("new primary owns description")
	if _, err := west.ImportKeyMaterial(t.Context(), wa); err != nil {
		t.Fatal(err)
	}
	if got := aws.ToString(kmsImportHistory(t, east, id)[0].KeyMaterialDescription); got != "new primary owns description" {
		t.Fatal("promotion did not transfer description ownership", got)
	}
}
