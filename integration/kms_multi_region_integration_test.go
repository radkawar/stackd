package stackd_test

import (
	"bytes"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

func TestKMSMultiRegionCryptoRotationPromotionAndRecovery(t *testing.T) {
	for _, backendName := range []string{"memory", "sqlite"} {
		t.Run(backendName, func(t *testing.T) {
			codes := kmsNativeCodes(t, "multi_region")
			source := clock.NewManual(time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC))
			backends := storage.NewMemory()
			closeDatabase := func() {}
			path := filepath.Join(t.TempDir(), "state.sqlite")
			if backendName == "sqlite" {
				// KMS, IAM, the journal and scheduler discovery must share one
				// transaction domain, including after recovery.
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
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
			created, err := east.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true), Description: aws.String("primary"), Tags: []types.Tag{{TagKey: aws.String("location"), TagValue: aws.String("primary")}}})
			if err != nil {
				t.Fatal(err)
			}
			primary := created.KeyMetadata
			if !aws.ToBool(primary.MultiRegion) || !strings.HasPrefix(aws.ToString(primary.KeyId), "mrk-") || len(aws.ToString(primary.KeyId)) != 36 || primary.MultiRegionConfiguration.MultiRegionKeyType != types.MultiRegionKeyTypePrimary {
				t.Fatal("invalid primary metadata", primary)
			}
			ec := map[string]string{"purpose": "mrk"}
			plaintext := []byte("multi-Region plaintext")
			encrypted, err := east.Encrypt(t.Context(), &kms.EncryptInput{KeyId: primary.KeyId, Plaintext: plaintext, EncryptionContext: ec})
			checkKMSNative(t, codes, "encrypt_primary_before", err)
			_, err = east.EnableKeyRotation(t.Context(), &kms.EnableKeyRotationInput{KeyId: primary.KeyId, RotationPeriodInDays: aws.Int32(90)})
			checkKMSNative(t, codes, "enable_rotation_primary", err)
			replica, err := east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: primary.KeyId, ReplicaRegion: aws.String("us-west-2")})
			checkKMSNative(t, codes, "replicate_west", err)
			if replica.ReplicaKeyMetadata.KeyState != types.KeyStateCreating || replica.ReplicaKeyMetadata.CurrentKeyMaterialId != nil || aws.ToString(replica.ReplicaKeyMetadata.Description) != "" || len(replica.ReplicaTags) != 0 || replica.ReplicaPolicy == nil {
				t.Fatal("replication did not preserve native defaults", replica)
			}
			_, err = west.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: ec})
			assertAPIError(t, err, "KMSInvalidStateException")
			advanceClock(t, source, 5*time.Second)
			for _, tc := range []struct {
				name string
				id   *string
			}{
				{"implicit", nil}, {"id", primary.KeyId}, {"replica_arn", replica.ReplicaKeyMetadata.Arn}, {"primary_arn", primary.Arn},
			} {
				out, err := west.Decrypt(t.Context(), &kms.DecryptInput{KeyId: tc.id, CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: ec})
				checkKMSNative(t, codes, "decrypt_replica_"+tc.name, err)
				if err == nil && (!bytes.Equal(out.Plaintext, plaintext) || aws.ToString(out.KeyId) != aws.ToString(replica.ReplicaKeyMetadata.Arn)) {
					t.Fatal("replica did not decrypt locally", out)
				}
			}
			_, err = west.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: map[string]string{"purpose": "wrong"}})
			assertAPIError(t, err, "InvalidCiphertextException")
			same, err := west.ReEncrypt(t.Context(), &kms.ReEncryptInput{CiphertextBlob: encrypted.CiphertextBlob, SourceEncryptionContext: ec, DestinationKeyId: primary.KeyId})
			checkKMSNative(t, codes, "replica_reencrypt_same", err)
			if aws.ToString(same.SourceKeyId) != aws.ToString(replica.ReplicaKeyMetadata.Arn) || aws.ToString(same.KeyId) != aws.ToString(same.SourceKeyId) {
				t.Fatal("regional re-encryption identity", same)
			}
			_, err = east.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: primary.KeyId})
			checkKMSNative(t, codes, "disable_primary", err)
			_, err = west.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: ec})
			checkKMSNative(t, codes, "decrypt_replica_primary_disabled", err)
			_, err = east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: primary.KeyId, ReplicaRegion: aws.String("us-west-2")})
			checkKMSNative(t, codes, "replicate_disabled_primary", err)
			if _, err = east.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: primary.KeyId}); err != nil {
				t.Fatal(err)
			}
			_, err = east.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: primary.KeyId})
			checkKMSNative(t, codes, "rotate_primary", err)
			// Reconstruct services while rotation is pending. Only retained storage owns
			// the topology, material history and accepted transition.
			server.Close()
			if err := cloud.Close(); err != nil {
				t.Fatal(err)
			}
			if backendName == "sqlite" {
				closeDatabase()
				config.Storage, _ = openSQLiteBackends(t, path)
			}
			c = clockCloud(t, config)
			east, west = c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
			advanceClock(t, source, 2*time.Minute)
			history, err := west.ListKeyRotations(t.Context(), &kms.ListKeyRotationsInput{KeyId: primary.KeyId, IncludeKeyMaterial: types.IncludeKeyMaterialAllKeyMaterial})
			checkKMSNative(t, codes, "replica_rotation_history", err)
			if len(history.Rotations) != 2 || aws.ToString(history.Rotations[0].KeyMaterialId) != aws.ToString(primary.CurrentKeyMaterialId) || history.Rotations[1].RotationType != types.RotationTypeOnDemand {
				t.Fatal("lost shared rotation history", history)
			}
			old, err := west.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: ec})
			checkKMSNative(t, codes, "replica_decrypt_old_material", err)
			if !bytes.Equal(old.Plaintext, plaintext) {
				t.Fatal("rotation lost old material")
			}
			_, err = east.UpdatePrimaryRegion(t.Context(), &kms.UpdatePrimaryRegionInput{KeyId: primary.KeyId, PrimaryRegion: aws.String("us-west-2")})
			checkKMSNative(t, codes, "promote_replica", err)
			for _, client := range []*kms.Client{east, west} {
				out, err := client.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: primary.KeyId})
				if err != nil || out.KeyMetadata.KeyState != types.KeyStateUpdating || out.KeyMetadata.Enabled {
					t.Fatal("promotion omitted Updating", out, err)
				}
				if _, err := client.Decrypt(t.Context(), &kms.DecryptInput{CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: ec}); err != nil {
					t.Fatal("Updating interrupted crypto", err)
				}
				_, err = client.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: primary.KeyId})
				assertAPIError(t, err, "KMSInvalidStateException")
			}
			advanceClock(t, source, 5*time.Second)
			status, err := west.GetKeyRotationStatus(t.Context(), &kms.GetKeyRotationStatusInput{KeyId: primary.KeyId})
			checkKMSNative(t, codes, "new_primary_rotation", err)
			if !status.KeyRotationEnabled || aws.ToInt32(status.RotationPeriodInDays) != 90 {
				t.Fatal("promotion lost rotation settings", status)
			}
			// Only the primary's enabled state controls automatic rotation.
			if _, err := west.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: primary.KeyId}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 91*24*time.Hour)
			out, err := east.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: primary.KeyId})
			if err != nil || aws.ToString(out.KeyMetadata.CurrentKeyMaterialId) != aws.ToString(history.Rotations[1].KeyMaterialId) {
				t.Fatal("replica rotated while primary disabled", err)
			}
			if _, err := west.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: primary.KeyId}); err != nil {
				t.Fatal(err)
			}
			out, err = east.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: primary.KeyId})
			if err != nil || aws.ToString(out.KeyMetadata.CurrentKeyMaterialId) == aws.ToString(history.Rotations[1].KeyMaterialId) {
				t.Fatal("replica missed primary rotation", err)
			}
		})
	}
}
