package stackd_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
	kmsstore "stackd/storage/kms"
)

func TestKMSAcceptedRotationSurvivesReplicaMaterialLoss(t *testing.T) {
	codes := kmsNativeCodes(t, "imports_rotation_replica")
	source := clock.NewManual(time.Now().UTC().Truncate(time.Second))
	backends := storage.NewMemory()
	backend := &failingReplicaStorage{Storage: backends.KMS}
	backends.KMS = backend
	c := clockCloud(t, stackd.Config{Clock: source, Storage: backends})
	east, west := c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
	k := kmsExternalKey(t, east, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, true)
	ep := kmsImportParameters(t, east, k.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	a := kmsImportRequest(t, k.KeyId, ep, bytes.Repeat([]byte{'A'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	first, err := east.ImportKeyMaterial(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: k.KeyId, ReplicaRegion: aws.String("us-west-2")}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 5*time.Second)
	wp := kmsImportParameters(t, west, k.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	wa := kmsImportRequest(t, k.KeyId, wp, bytes.Repeat([]byte{'A'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	if _, err := west.ImportKeyMaterial(t.Context(), wa); err != nil {
		t.Fatal(err)
	}
	b := kmsImportRequest(t, k.KeyId, ep, bytes.Repeat([]byte{'B'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	b.ImportType = types.ImportTypeNewKeyMaterial
	second, err := east.ImportKeyMaterial(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	wb := kmsImportRequest(t, k.KeyId, wp, bytes.Repeat([]byte{'B'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	if _, err := west.ImportKeyMaterial(t.Context(), wb); err != nil {
		t.Fatal(err)
	}
	_, err = east.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: k.KeyId})
	checkKMSNative(t, codes, "rotate_primary", err)
	_, err = west.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: k.KeyId, KeyMaterialId: second.KeyMaterialId})
	checkKMSNative(t, codes, "delete_replica_pending", err)
	status, err := east.GetKeyRotationStatus(t.Context(), &kms.GetKeyRotationStatusInput{KeyId: k.KeyId})
	checkKMSNative(t, codes, "status_after_replica_delete", err)
	if status.OnDemandRotationStartDate == nil {
		t.Fatal("replica deletion canceled primary request")
	}
	advanceClock(t, source, 2*time.Minute)
	// A failed regional commit must not publish shared rotation without the
	// replica's PendingImport state. Retrying observes the same retained job.
	backend.fail.Store(true)
	_, err = east.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: k.KeyId})
	assertAPIError(t, err, "KMSInternalException")
	if err := backend.Storage.Transact(t.Context(), func(tx kmsstore.Transaction) error {
		set, err := tx.KeySet(kmsstore.KeyOwner{Partition: "aws", AccountID: aws.ToString(k.AWSAccountId)}, aws.ToString(k.KeyId))
		if err != nil {
			return err
		}
		if set.CurrentMaterialID != aws.ToString(first.KeyMaterialId) || set.Rotation.OnDemandStarted.IsZero() {
			return errors.New("failed regional commit published rotation or lost its accepted request")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	backend.fail.Store(false)
	for _, tc := range []struct {
		c     *kms.Client
		state types.KeyState
	}{{east, types.KeyStateEnabled}, {west, types.KeyStatePendingImport}} {
		m := kmsImportMetadata(t, tc.c, k.KeyId, tc.state)
		if aws.ToString(m.CurrentKeyMaterialId) != aws.ToString(second.KeyMaterialId) {
			t.Fatal("accepted rotation was lost", m)
		}
	}
	history := kmsImportHistory(t, west, k.KeyId)
	if len(history) != 2 || history[1].KeyMaterialState != types.KeyMaterialStateCurrent || history[1].ImportState != types.ImportStatePendingImport || history[1].RotationDate == nil {
		t.Fatal("missing replica did not inherit current material history", history)
	}
	encrypted, err := east.Encrypt(t.Context(), &kms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("regional rotation")})
	checkKMSNative(t, codes, "encrypt_after_rotation_us-east-1", err)
	_, err = west.Encrypt(t.Context(), &kms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("regional rotation")})
	checkKMSNative(t, codes, "encrypt_after_rotation_us-west-2", err)
	_, err = west.ImportKeyMaterial(t.Context(), wb)
	checkKMSNative(t, codes, "replica_restore", err)
	out, err := west.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	if err != nil || string(out.Plaintext) != "regional rotation" {
		t.Fatal("reimport did not restore related-key decryption", err)
	}
}
