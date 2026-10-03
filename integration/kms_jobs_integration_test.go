package stackd_test

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
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

func TestKMSJobsSDKLifecycleAndRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.sqlite")
			backends := storage.NewMemory()
			manual := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			start := func() (*stackd.Stack, cloudClients, func()) {
				closeDB := func() {}
				if backend == "sqlite" {
					backends, closeDB = openSQLiteBackends(t, path)
				}
				cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: manual})
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(cloud)
				close := func() { server.Close(); _ = cloud.Close(); closeDB() }
				t.Cleanup(close)
				return cloud, cloudClients{server}, close
			}
			cloud, c, closeFirst := start()
			east := c.kms("test", "test", "")
			created, err := east.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			id := aws.ToString(created.KeyMetadata.KeyId)
			if _, err := east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: &id, ReplicaRegion: aws.String("us-west-2")}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, manual, 5*time.Second)
			if _, err := cloud.RunDueJobs(t.Context(), 20); err != nil {
				t.Fatal(err)
			}
			owner := kmsstore.KeyOwner{Partition: "aws", AccountID: "000000000000"}
			checkRegions := func(wantState, primary string, versions int) {
				t.Helper()
				if err := backends.KMS.Transact(t.Context(), func(tx kmsstore.Transaction) error {
					set, err := tx.KeySet(owner, id)
					if err != nil {
						return err
					}
					if set.PrimaryRegion != primary || len(set.Materials) != versions {
						t.Errorf("stored topology/material count = %s/%d, want %s/%d", set.PrimaryRegion, len(set.Materials), primary, versions)
					}
					for _, region := range []string{"us-east-1", "us-west-2"} {
						keys, err := tx.Keys(kmsstore.StorageScope{Partition: "aws", AccountID: owner.AccountID, Region: region})
						if err != nil {
							return err
						}
						found := false
						for _, key := range keys {
							if key.ID == id {
								found = true
								if key.State != wantState {
									t.Errorf("stored %s key state = %s, want %s", region, key.State, wantState)
								}
							}
						}
						if !found {
							t.Error("missing regional key", region)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			checkRegions("Enabled", "us-east-1", 1)
			ciphertext, err := east.Encrypt(t.Context(), &kms.EncryptInput{KeyId: &id, Plaintext: []byte("before scheduled rotation")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := east.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: &id}); err != nil {
				t.Fatal(err)
			}
			other := c.kms("222222222222", "test", "")
			otherKey, err := other.CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := other.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: otherKey.KeyMetadata.KeyId}); err != nil {
				t.Fatal(err)
			}
			external := kmsExternalKey(t, east, types.KeySpecSymmetricDefault, types.KeyUsageTypeEncryptDecrypt, false)
			parameters := kmsImportParameters(t, east, external.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
			request := kmsImportRequest(t, external.KeyId, parameters, bytes.Repeat([]byte{42}, 32), types.AlgorithmSpecRsaesOaepSha256)
			request.ExpirationModel, request.ValidTo = types.ExpirationModelTypeKeyMaterialExpires, aws.Time(manual.Now().Add(time.Minute))
			if _, err := east.ImportKeyMaterial(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			closeFirst()
			advanceClock(t, manual, 2*time.Minute)
			cloud, c, _ = start()
			// Recovery must run automatically, without a drain or a KMS request.
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				ready := false
				err := backends.KMS.Transact(ctx, func(tx kmsstore.Transaction) error {
					first, err := tx.KeySet(owner, id)
					if err != nil {
						return err
					}
					second, err := tx.KeySet(kmsstore.KeyOwner{Partition: "aws", AccountID: "222222222222"}, aws.ToString(otherKey.KeyMetadata.KeyId))
					ready = len(first.Materials) == 2 && len(second.Materials) == 2
					return err
				})
				if err != nil {
					t.Fatal("automatic lifecycle recovery", err)
				}
				if ready {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("automatic recovery did not complete retained rotations", ctx.Err())
				case <-ticker.C:
				}
			}
			// Read the backend before any KMS request can apply lazy transitions.
			checkRegions("Enabled", "us-east-1", 2)
			if err := backends.KMS.Transact(t.Context(), func(tx kmsstore.Transaction) error {
				set, err := tx.KeySet(kmsstore.KeyOwner{Partition: "aws", AccountID: "222222222222"}, aws.ToString(otherKey.KeyMetadata.KeyId))
				if err != nil {
					return err
				}
				if len(set.Materials) != 2 {
					t.Error("recovery missed another account's rotation")
				}
				keys, err := tx.Keys(kmsstore.StorageScope{Partition: "aws", AccountID: owner.AccountID, Region: "us-east-1"})
				if err != nil {
					return err
				}
				for _, key := range keys {
					if key.ID == aws.ToString(external.KeyId) && (key.State != "PendingImport" || len(key.Imports) != 0) {
						t.Error("import expiry required API traffic", key.State)
					}
				}
				set, err = tx.KeySet(owner, aws.ToString(external.KeyId))
				if err == nil && len(set.Materials[0].Material) != 0 {
					t.Error("expiry retained deleted material bytes")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			east, west := c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
			plain, err := west.Decrypt(t.Context(), &kms.DecryptInput{KeyId: &id, CiphertextBlob: ciphertext.CiphertextBlob})
			if err != nil || string(plain.Plaintext) != "before scheduled rotation" {
				t.Fatal("rotation lost old ciphertext across regions", err)
			}
			_, err = east.Encrypt(t.Context(), &kms.EncryptInput{KeyId: external.KeyId, Plaintext: []byte("expired")})
			assertAPIError(t, err, "KMSInvalidStateException")
			if _, err := east.UpdatePrimaryRegion(t.Context(), &kms.UpdatePrimaryRegionInput{KeyId: &id, PrimaryRegion: aws.String("us-west-2")}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, manual, 5*time.Second)
			if _, err := cloud.RunDueJobs(t.Context(), 20); err != nil {
				t.Fatal(err)
			}
			checkRegions("Enabled", "us-west-2", 2)
			for _, client := range []*kms.Client{east, west} {
				if _, err := client.CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: aws.String("alias/scheduled"), TargetKeyId: &id}); err != nil {
					t.Fatal(err)
				}
				if _, err := client.ScheduleKeyDeletion(t.Context(), &kms.ScheduleKeyDeletionInput{KeyId: &id, PendingWindowInDays: aws.Int32(7)}); err != nil {
					t.Fatal(err)
				}
			}
			advanceClock(t, manual, 15*24*time.Hour)
			if _, err := cloud.RunDueJobs(t.Context(), 20); err != nil {
				t.Fatal(err)
			}
			if err := backends.KMS.Transact(t.Context(), func(tx kmsstore.Transaction) error {
				if _, err := tx.KeySet(owner, id); !errors.Is(err, kmsstore.ErrKeySetNotFound) {
					t.Error("scheduled deletion retained shared material", err)
				}
				for _, region := range []string{"us-east-1", "us-west-2"} {
					sc := kmsstore.StorageScope{Partition: "aws", AccountID: owner.AccountID, Region: region}
					aliases, err := tx.Aliases(sc)
					if err != nil {
						return err
					}
					if len(aliases) != 0 {
						t.Error("key deletion retained regional aliases", region)
					}
					keys, err := tx.Keys(sc)
					if err != nil {
						return err
					}
					for _, key := range keys {
						if key.ID == id {
							t.Error("deletion retained a regional key", region)
						}
						for _, parameter := range key.ImportParameters {
							if len(parameter.PrivateKey) != 0 {
								t.Error("expired import parameters retained a wrapping private key")
							}
						}
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestKMSJobsSDKFailedRegionalCommit(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
			}
			stored := backends.KMS
			failing := &failingReplicaStorage{Storage: stored}
			backends.KMS = failing
			manual := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: manual})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cloud.Close() })
			server := httptest.NewServer(cloud)
			t.Cleanup(server.Close)
			client := (cloudClients{server}).kms("test", "test", "")
			created, err := client.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			id := created.KeyMetadata.KeyId
			if _, err := client.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-west-2")}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, manual, 5*time.Second)
			if _, err := cloud.RunDueJobs(t.Context(), 20); err != nil {
				t.Fatal(err)
			}
			if _, err := client.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: id}); err != nil {
				t.Fatal(err)
			}
			failing.fail.Store(true)
			advanceClock(t, manual, 2*time.Minute)
			if _, err := cloud.RunDueJobs(t.Context(), 20); err == nil {
				t.Fatal("failed replica commit was reported as successful work")
			}
			if err := stored.Transact(t.Context(), func(tx kmsstore.Transaction) error {
				set, err := tx.KeySet(kmsstore.KeyOwner{Partition: "aws", AccountID: "000000000000"}, aws.ToString(id))
				if err == nil && (len(set.Materials) != 1 || set.Rotation.OnDemandStarted.IsZero()) {
					t.Error("failed regional commit published shared rotation")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			failing.fail.Store(false)
			if _, err := cloud.RunDueJobs(t.Context(), 20); err != nil {
				t.Fatal("retained rotation could not retry", err)
			}
			out, err := client.ListKeyRotations(t.Context(), &kms.ListKeyRotationsInput{KeyId: id})
			if err != nil || len(out.Rotations) != 1 {
				t.Fatal("retry duplicated or lost rotation", out, err)
			}
		})
	}
}
