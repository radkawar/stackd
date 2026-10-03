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

func TestKMSAcceptedImportRotationCanUseReplacementMaterial(t *testing.T) {
	codes := kmsNativeCodes(t, "imports_rotation_replacement")
	for _, replace := range []bool{false, true} {
		name := "empty"
		if replace {
			name = "replacement"
		}
		t.Run(name, func(t *testing.T) {
			source := clock.NewManual(time.Now().UTC().Truncate(time.Second))
			config := stackd.Config{Clock: source, Storage: storage.NewMemory()}
			cloud, err := stackd.New(config)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(cloud)
			t.Cleanup(server.Close)
			t.Cleanup(func() { _ = cloud.Close() })
			c := cloudClients{server}.kms("test", "test", "")
			k := kmsExternalKey(t, c, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, false)
			p := kmsImportParameters(t, c, k.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
			a := kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{'A'}, 32), types.AlgorithmSpecRsaesOaepSha256)
			first, err := c.ImportKeyMaterial(t.Context(), a)
			checkKMSNative(t, codes, "first_import", err)
			before, err := c.Encrypt(t.Context(), &kms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("first material")})
			if err != nil {
				t.Fatal(err)
			}
			b := kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{'B'}, 32), types.AlgorithmSpecRsaesOaepSha256)
			b.ImportType = types.ImportTypeNewKeyMaterial
			second, err := c.ImportKeyMaterial(t.Context(), b)
			checkKMSNative(t, codes, "second_import", err)
			_, err = c.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: k.KeyId})
			checkKMSNative(t, codes, "rotate_second", err)
			started := source.Now()
			_, err = c.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: k.KeyId, KeyMaterialId: second.KeyMaterialId})
			checkKMSNative(t, codes, "delete_second", err)
			wantID := first.KeyMaterialId
			if replace {
				next := kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{'C'}, 32), types.AlgorithmSpecRsaesOaepSha256)
				next.ImportType = types.ImportTypeNewKeyMaterial
				third, err := c.ImportKeyMaterial(t.Context(), next)
				checkKMSNative(t, codes, "third_import_without_rotate", err)
				wantID = third.KeyMaterialId
			}
			// Reconstruct after material deletion/replacement; the accepted request
			// belongs to retained storage and must not require another API call.
			server.Close()
			if err := cloud.Close(); err != nil {
				t.Fatal(err)
			}
			c = clockCloud(t, config).kms("test", "test", "")
			status, err := c.GetKeyRotationStatus(t.Context(), &kms.GetKeyRotationStatusInput{KeyId: k.KeyId})
			checkKMSNative(t, codes, "status_after_delete_second", err)
			if status.OnDemandRotationStartDate == nil || !status.OnDemandRotationStartDate.Equal(started) {
				t.Fatal("material deletion discarded accepted rotation", status)
			}
			advanceClock(t, source, 2*time.Minute)
			status, err = c.GetKeyRotationStatus(t.Context(), &kms.GetKeyRotationStatusInput{KeyId: k.KeyId})
			if err != nil || status.OnDemandRotationStartDate != nil {
				t.Fatal("rotation request did not complete", status, err)
			}
			m := kmsImportMetadata(t, c, k.KeyId, types.KeyStateEnabled)
			if aws.ToString(m.CurrentKeyMaterialId) != aws.ToString(wantID) {
				t.Fatal("request did not evaluate current pending material", m)
			}
			history := kmsImportHistory(t, c, k.KeyId)
			wantCount := 1
			if replace {
				wantCount = 2
			}
			if len(history) != wantCount {
				t.Fatal("deleted material entered rotation history", history)
			}
			if replace && (history[1].RotationType != types.RotationTypeOnDemand || !history[1].RotationDate.Equal(started.Add(2*time.Minute))) {
				t.Fatal("replacement did not retain request timing", history)
			}
			out, err := c.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: before.CiphertextBlob})
			if err != nil || string(out.Plaintext) != "first material" {
				t.Fatal("rotation discarded earlier ciphertext", err)
			}
			_, err = c.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: k.KeyId})
			checkKMSNative(t, codes, "rotate_third", err)
		})
	}
}
