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
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"

	"stackd"
	"stackd/internal/awsctx"
	"stackd/storage"
	iamstore "stackd/storage/iam"
	orgstore "stackd/storage/organizations"
)

type organizationRoleDependencyKey struct{}

type organizationRoleReadRepository struct{ iamstore.Repository }

func (r organizationRoleReadRepository) Update(ctx context.Context, fn func(iamstore.WriteTx) error) error {
	return r.Repository.Update(context.WithValue(ctx, organizationRoleDependencyKey{}, true), fn)
}

type organizationRoleReadStorage struct {
	orgstore.Storage
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (s *organizationRoleReadStorage) Load(ctx context.Context, partition string) (orgstore.PartitionRecord, uint64, error) {
	record, revision, err := s.Storage.Load(ctx, partition)
	// The IAM deletion worker has no originating HTTP request metadata. Wait only
	// at its dependency read, after the ordinary signed API has queued its job.
	if err == nil && ctx.Value(organizationRoleDependencyKey{}) == true && awsctx.FromContext(ctx).RequestID == "" && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		select {
		case <-ctx.Done():
			return orgstore.PartitionRecord{}, 0, ctx.Err()
		case <-s.release:
		}
	}
	return record, revision, err
}

func TestOrganizationsMembershipStableThroughServiceRoleDeletionSDK(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) { testOrganizationsMembershipStableThroughServiceRoleDeletionSDK(t, backend) })
	}
}

func testOrganizationsMembershipStableThroughServiceRoleDeletionSDK(t *testing.T, backend string) {
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
	}
	backends.IAM = organizationRoleReadRepository{backends.IAM}
	store := &organizationRoleReadStorage{Storage: backends.Organizations, entered: make(chan struct{}), release: make(chan struct{})}
	backends.Organizations = store
	f := newOrganizationReportFixture(t, backends)
	// This is the native commit of an independent DeleteOrganization request
	// that already read and authorized the empty organization. Its revision is
	// current, but it must wait while IAM checks the role's live dependency.
	removed, revision, err := store.Load(t.Context(), "aws")
	if err != nil {
		t.Fatal(err)
	}
	removed.Organizations = nil
	store.armed.Store(true)
	deletion, err := f.iam.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: aws.String(organizationsRoleName)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case <-store.entered:
	case <-ctx.Done():
		t.Fatal("deletion did not read Organizations", ctx.Err())
	}
	func() {
		defer close(store.release)
		writeCtx, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		defer stop()
		committed, err := store.CompareAndSwap(writeCtx, "aws", revision, removed, nil)
		if committed || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("membership changed during deletion: committed=%v, err=%v", committed, err)
		}
	}()
	status := waitOrganizationRoleDeletion(t, f.iam, deletion.DeletionTaskId)
	if status.Status != iamtypes.DeletionTaskStatusTypeFailed {
		t.Fatalf("required service role deleted: %+v", status)
	}
	if _, err := f.iam.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(organizationsRoleName)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.org.DeleteOrganization(t.Context(), &organizations.DeleteOrganizationInput{}); err != nil {
		t.Fatal("membership write did not resume after deletion check", err)
	}
	retry, err := f.iam.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: aws.String(organizationsRoleName)})
	if err != nil {
		t.Fatal(err)
	}
	if status := waitOrganizationRoleDeletion(t, f.iam, retry.DeletionTaskId); status.Status != iamtypes.DeletionTaskStatusTypeSucceeded {
		t.Fatalf("released service role not deleted: %+v", status)
	}
}

func TestOrganizationAndServiceRoleRollbackTogetherSDK(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) { testOrganizationAndServiceRoleRollbackTogetherSDK(t, backend) })
	}
}

func testOrganizationAndServiceRoleRollbackTogetherSDK(t *testing.T, backend string) {
	for _, mode := range []string{"IAM commit", "IAM cancellation", "Organizations commit"} {
		t.Run(mode, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
			}
			repository := &accountRoleRepository{Repository: backends.IAM}
			orgs := &accountCreationStorage{Storage: backends.Organizations}
			backends.IAM, backends.Organizations = repository, orgs
			c := clockCloud(t, stackd.Config{Storage: backends})
			org := c.organizations("test", "test")
			switch mode {
			case "IAM commit":
				repository.mode.Store(1)
			case "IAM cancellation":
				repository.mode.Store(2)
			case "Organizations commit":
				orgs.fail.Store(true)
			}
			_, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
			assertAPIError(t, err, "ServiceException")
			repository.mode.Store(0)
			orgs.fail.Store(false)
			_, err = org.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
			assertAPIError(t, err, "AWSOrganizationsNotInUseException")
			root := c.iam("test", "test", "")
			_, err = root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(organizationsRoleName)})
			assertAPIError(t, err, "NoSuchEntity")
			if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{}); err != nil {
				t.Fatal("retry failed", err)
			}
			if _, err := root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(organizationsRoleName)}); err != nil {
				t.Fatal("retry did not provision service role", err)
			}
		})
	}
}
