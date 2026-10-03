package stackd_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
	kmsstore "stackd/storage/kms"
)

type failingReplicaStorage struct {
	kmsstore.Storage
	fail atomic.Bool
}

func (s *failingReplicaStorage) Transact(ctx context.Context, fn func(kmsstore.Transaction) error) error {
	return s.Storage.Transact(ctx, func(tx kmsstore.Transaction) error { return fn(failingReplicaTx{tx, s.fail.Load()}) })
}

func (s *failingReplicaStorage) Attempt(ctx context.Context, fn func(kmsstore.Transaction) error) error {
	return s.Storage.Attempt(ctx, func(tx kmsstore.Transaction) error { return fn(failingReplicaTx{tx, s.fail.Load()}) })
}

type failingReplicaTx struct {
	kmsstore.Transaction
	fail bool
}

func (tx failingReplicaTx) PutKey(sc kmsstore.StorageScope, k kmsstore.KeyRecord) error {
	if err := tx.Transaction.PutKey(sc, k); err != nil {
		return err
	}
	if tx.fail && sc.Region == "us-west-2" {
		return errors.New("replica write failed")
	}
	return nil
}

func TestKMSMultiRegionTransitionsCommitAtomically(t *testing.T) {
	for _, backendName := range []string{"memory", "sqlite"} {
		t.Run(backendName, func(t *testing.T) {
			backends := storage.NewMemory()
			if backendName == "sqlite" {
				var closeDatabase func()
				backends, closeDatabase = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
				t.Cleanup(closeDatabase)
			}
			backend := &failingReplicaStorage{Storage: backends.KMS}
			backends.KMS = backend
			source := clock.NewManual(time.Now().UTC())
			c := clockCloud(t, stackd.Config{Clock: source, Storage: backends})
			east, west := c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
			created, err := east.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			id := created.KeyMetadata.KeyId
			backend.fail.Store(true)
			_, err = east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-west-2")})
			assertAPIError(t, err, "KMSInternalException")
			backend.fail.Store(false)
			primary, err := east.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id})
			if err != nil || len(primary.KeyMetadata.MultiRegionConfiguration.ReplicaKeys) != 0 {
				t.Fatal("failed replication committed topology", primary, err)
			}
			list, err := west.ListKeys(t.Context(), &kms.ListKeysInput{})
			if err != nil || len(list.Keys) != 0 {
				t.Fatal("failed replication committed regional key", list, err)
			}
			if _, err := east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-west-2")}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 5*time.Second)
			// Persist readiness before testing promotion rollback.
			if _, err := west.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id}); err != nil {
				t.Fatal(err)
			}
			backend.fail.Store(true)
			_, err = east.UpdatePrimaryRegion(t.Context(), &kms.UpdatePrimaryRegionInput{KeyId: id, PrimaryRegion: aws.String("us-west-2")})
			assertAPIError(t, err, "KMSInternalException")
			backend.fail.Store(false)
			for _, client := range []*kms.Client{east, west} {
				out, err := client.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id})
				if err != nil || out.KeyMetadata.KeyState != types.KeyStateEnabled || aws.ToString(out.KeyMetadata.MultiRegionConfiguration.PrimaryKey.Region) != "us-east-1" {
					t.Fatal("failed promotion committed partial state", out, err)
				}
			}
			// Removing a replica must keep old material for its primary. Re-replication
			// creates independent regional metadata over the surviving key set.
			if _, err := west.ScheduleKeyDeletion(t.Context(), &kms.ScheduleKeyDeletionInput{KeyId: id, PendingWindowInDays: aws.Int32(7)}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 7*24*time.Hour)
			out, err := east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-west-2")})
			if err != nil || out.ReplicaKeyMetadata.KeyState != types.KeyStateCreating {
				t.Fatal("re-replication after expiry", err)
			}
			advanceClock(t, source, 5*time.Second)
			primary, err = west.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id})
			if err != nil || aws.ToString(primary.KeyMetadata.CurrentKeyMaterialId) != aws.ToString(created.KeyMetadata.CurrentKeyMaterialId) {
				t.Fatal("replica deletion destroyed shared material", err)
			}
		})
	}
}

func TestKMSCreationRollsBackDependentServiceRole(t *testing.T) {
	for _, backendName := range []string{"memory", "sqlite"} {
		t.Run(backendName, func(t *testing.T) {
			backends := storage.NewMemory()
			if backendName == "sqlite" {
				var closeDatabase func()
				backends, closeDatabase = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
				t.Cleanup(closeDatabase)
			}
			backend := &failingReplicaStorage{Storage: backends.KMS}
			backends.KMS = backend
			c := clockCloud(t, stackd.Config{Storage: backends})
			keys := c.kmsRegion("us-west-2", "test", "test", "")
			roles := c.iam("test", "test", "")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			backend.fail.Store(true)
			_, err := keys.CreateKey(ctx, &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
			assertAPIError(t, err, "KMSInternalException")
			backend.fail.Store(false)
			list, err := keys.ListKeys(ctx, &kms.ListKeysInput{})
			if err != nil || len(list.Keys) != 0 {
				t.Fatal("failed creation committed a key", list, err)
			}
			roleName := aws.String("AWSServiceRoleForKeyManagementServiceMultiRegionKeys")
			_, err = roles.GetRole(ctx, &iam.GetRoleInput{RoleName: roleName})
			assertAPIError(t, err, "NoSuchEntity")
			if _, err := keys.CreateKey(ctx, &kms.CreateKeyInput{MultiRegion: aws.Bool(true)}); err != nil {
				t.Fatal("retry failed", err)
			}
			role, err := roles.GetRole(ctx, &iam.GetRoleInput{RoleName: roleName})
			if err != nil {
				t.Fatal("successful creation lost its service role", err)
			}
			// A later failed key creation must preserve the already committed role.
			backend.fail.Store(true)
			_, err = keys.CreateKey(ctx, &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
			assertAPIError(t, err, "KMSInternalException")
			backend.fail.Store(false)
			retained, err := roles.GetRole(ctx, &iam.GetRoleInput{RoleName: roleName})
			if err != nil || aws.ToString(retained.Role.RoleId) != aws.ToString(role.Role.RoleId) {
				t.Fatal("failed creation changed the existing role", retained, err)
			}
			list, err = keys.ListKeys(ctx, &kms.ListKeysInput{})
			if err != nil || len(list.Keys) != 1 {
				t.Fatal("failed creation changed the committed keys", list, err)
			}
		})
	}
}
