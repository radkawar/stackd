package stackd_test

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd/clock"
	"stackd/storage"
)

func TestSQLiteKMSRestoresWrappingKeysAndImportExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	source := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	c, close := openSQLiteCloud(t, path, storage.NewMemory(), source)
	owner := c.kms("test", "test", "")
	key := kmsExternalKey(t, owner, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, false)
	parameters := kmsImportParameters(t, owner, key.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	request := kmsImportRequest(t, key.KeyId, parameters, bytes.Repeat([]byte{3}, 32), types.AlgorithmSpecRsaesOaepSha256)
	request.ExpirationModel = types.ExpirationModelTypeKeyMaterialExpires
	request.ValidTo = aws.Time(source.Now().Add(time.Hour))
	close()
	c, close = openSQLiteCloud(t, path, storage.NewMemory(), source)
	owner = c.kms("test", "test", "")
	if _, err := owner.ImportKeyMaterial(t.Context(), request); err != nil {
		t.Fatal("wrapping key/token was not restored", err)
	}
	plain := []byte("imported key material survives reopening")
	encrypted, err := owner.Encrypt(t.Context(), &kms.EncryptInput{KeyId: key.KeyId, Plaintext: plain})
	if err != nil {
		t.Fatal(err)
	}
	close()
	advanceClock(t, source, 2*time.Hour)
	c, close = openSQLiteCloud(t, path, storage.NewMemory(), source)
	owner = c.kms("test", "test", "")
	kmsImportMetadata(t, owner, key.KeyId, types.KeyStatePendingImport)
	_, err = owner.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	assertAPIError(t, err, "KMSInvalidStateException")
	// The original 24-hour token is still usable after expired material was
	// removed. Its wrapping private key and the material identity are durable.
	request.ExpirationModel, request.ValidTo = types.ExpirationModelTypeKeyMaterialDoesNotExpire, nil
	if _, err := owner.ImportKeyMaterial(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	close()
	c, _ = openSQLiteCloud(t, path, storage.NewMemory(), source)
	owner = c.kms("test", "test", "")
	metadata := kmsImportMetadata(t, owner, key.KeyId, types.KeyStateEnabled)
	if metadata.ValidTo != nil || metadata.ExpirationModel != types.ExpirationModelTypeKeyMaterialDoesNotExpire {
		t.Fatal("reimport retained the old expiry", metadata)
	}
	out, err := owner.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob})
	if err != nil || !bytes.Equal(out.Plaintext, plain) {
		t.Fatal("reimport lost the original material identity", err)
	}
}
