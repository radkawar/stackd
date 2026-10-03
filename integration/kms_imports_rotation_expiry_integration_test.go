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

func TestKMSImportedExpiredPendingMaterialRotatesBeforeExpiry(t *testing.T) {
	codes := kmsNativeCodes(t, "imports_rotation_expiry")
	for _, waitBeforeRotation := range []time.Duration{0, 20 * time.Second} {
		t.Run(waitBeforeRotation.String(), func(t *testing.T) {
			source := clock.NewManual(time.Now().UTC().Truncate(time.Second))
			c := clockCloud(t, stackd.Config{Clock: source}).kms("test", "test", "")
			k := kmsExternalKey(t, c, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, false)
			p := kmsImportParameters(t, c, k.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
			a := kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{'A'}, 32), types.AlgorithmSpecRsaesOaepSha256)
			if _, err := c.ImportKeyMaterial(t.Context(), a); err != nil {
				t.Fatal(err)
			}
			before, err := c.Encrypt(t.Context(), &kms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("old material")})
			if err != nil {
				t.Fatal(err)
			}
			b := kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{'B'}, 32), types.AlgorithmSpecRsaesOaepSha256)
			b.ImportType, b.ExpirationModel, b.ValidTo = types.ImportTypeNewKeyMaterial, types.ExpirationModelTypeKeyMaterialExpires, aws.Time(source.Now().Add(15*time.Second))
			second, err := c.ImportKeyMaterial(t.Context(), b)
			checkKMSNative(t, codes, "expiring_pending", err)
			advanceClock(t, source, waitBeforeRotation)
			kmsImportMetadata(t, c, k.KeyId, types.KeyStateEnabled)
			history := kmsImportHistory(t, c, k.KeyId)
			if len(history) != 2 || history[1].ImportState != types.ImportStateImported || history[1].KeyMaterialState != types.KeyMaterialStatePendingRotation || !history[1].ValidTo.Equal(*b.ValidTo) {
				t.Fatal("expired pending material disappeared", history)
			}
			_, err = c.Encrypt(t.Context(), &kms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("pending expiry")})
			checkKMSNative(t, codes, "encrypt_with_expired_pending", err)
			_, err = c.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: k.KeyId})
			checkKMSNative(t, codes, "rotate_expired_pending", err)
			rotatedAt := source.Now().Add(2 * time.Minute)
			advanceClock(t, source, 2*time.Minute)
			m := kmsImportMetadata(t, c, k.KeyId, types.KeyStatePendingImport)
			if aws.ToString(m.CurrentKeyMaterialId) != aws.ToString(second.KeyMaterialId) || m.ExpirationModel != "" {
				t.Fatal("expired material was not promoted before making the key unusable", m)
			}
			history = kmsImportHistory(t, c, k.KeyId)
			if len(history) != 2 || history[1].KeyMaterialState != types.KeyMaterialStateCurrent || !history[1].RotationDate.Equal(rotatedAt) {
				t.Fatal("lost activation history", history)
			}
			_, err = c.Encrypt(t.Context(), &kms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("after rotation")})
			checkKMSNative(t, codes, "encrypt_after_expired_rotation", err)
			_, err = c.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: before.CiphertextBlob})
			checkKMSNative(t, codes, "decrypt_initial_after_expired_rotation", err)
			b.ImportType, b.ExpirationModel, b.ValidTo = types.ImportTypeExistingKeyMaterial, types.ExpirationModelTypeKeyMaterialDoesNotExpire, nil
			_, err = c.ImportKeyMaterial(t.Context(), b)
			checkKMSNative(t, codes, "restore_expired_pending", err)
			kmsImportMetadata(t, c, k.KeyId, types.KeyStateEnabled)
			decrypted, err := c.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: before.CiphertextBlob})
			checkKMSNative(t, codes, "decrypt_initial_after_restore", err)
			if string(decrypted.Plaintext) != "old material" {
				t.Fatal("restoration lost earlier ciphertext")
			}
		})
	}
}

func TestKMSImportedPendingExpiryRemainsRegionalAfterRotation(t *testing.T) {
	source := clock.NewManual(time.Now().UTC().Truncate(time.Second))
	c := clockCloud(t, stackd.Config{Clock: source})
	east, west := c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
	k := kmsExternalKey(t, east, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, true)
	ep := kmsImportParameters(t, east, k.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	a := kmsImportRequest(t, k.KeyId, ep, bytes.Repeat([]byte{'A'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	if _, err := east.ImportKeyMaterial(t.Context(), a); err != nil {
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
	b.ImportType, b.ExpirationModel, b.ValidTo = types.ImportTypeNewKeyMaterial, types.ExpirationModelTypeKeyMaterialExpires, aws.Time(source.Now().Add(15*time.Second))
	second, err := east.ImportKeyMaterial(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	wb := kmsImportRequest(t, k.KeyId, wp, bytes.Repeat([]byte{'B'}, 32), types.AlgorithmSpecRsaesOaepSha256)
	if _, err := west.ImportKeyMaterial(t.Context(), wb); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 20*time.Second)
	kmsImportMetadata(t, east, k.KeyId, types.KeyStateEnabled)
	if _, err := east.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 2*time.Minute)
	kmsImportMetadata(t, east, k.KeyId, types.KeyStatePendingImport)
	wm := kmsImportMetadata(t, west, k.KeyId, types.KeyStateEnabled)
	if aws.ToString(wm.CurrentKeyMaterialId) != aws.ToString(second.KeyMaterialId) || wm.ExpirationModel != types.ExpirationModelTypeKeyMaterialDoesNotExpire {
		t.Fatal("primary expiry changed replica material", wm)
	}
	encrypted, err := west.Encrypt(t.Context(), &kms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("replica still has current material")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = east.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	assertAPIError(t, err, "KMSInvalidStateException")
	b.ImportType, b.ExpirationModel, b.ValidTo = types.ImportTypeExistingKeyMaterial, types.ExpirationModelTypeKeyMaterialDoesNotExpire, nil
	if _, err := east.ImportKeyMaterial(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	out, err := east.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	if err != nil || string(out.Plaintext) != "replica still has current material" {
		t.Fatal("reimport did not restore shared decryption", err)
	}
}
