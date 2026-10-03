package stackd_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
	iamstore "stackd/storage/iam"
	orgstore "stackd/storage/organizations"
)

// Fail after the repository has staged its actual writes, using the same
// borrowed transaction contract as IAM/Organizations cross-service operations.
type delegationCommitStorage struct {
	orgstore.Storage
	identities          iamstore.Repository
	failNext, pauseNext atomic.Bool
	entered, resume     chan struct{}
}

func (s *delegationCommitStorage) CompareAndSwap(ctx context.Context, partition string, revision uint64, record orgstore.PartitionRecord, commit func(context.Context) error) (bool, error) {
	if s.pauseNext.Swap(false) {
		close(s.entered)
		select {
		case <-s.resume:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	if s.failNext.Swap(false) {
		err := s.identities.Update(ctx, func(tx iamstore.WriteTx) error {
			if _, err := s.Storage.CompareAndSwap(tx.Context(), partition, revision, record, commit); err != nil {
				return err
			}
			return errors.New("injected parent transaction failure")
		})
		return false, err
	}
	return s.Storage.CompareAndSwap(ctx, partition, revision, record, commit)
}

func TestOrganizationsDelegationCommitFailureAndRevocation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "delegation.sqlite"))
			}
			repository := &delegationCommitStorage{Storage: backends.Organizations, identities: backends.IAM, entered: make(chan struct{}), resume: make(chan struct{})}
			backends.Organizations = repository
			f := newOrganizationReportFixture(t, backends)
			member := f.account(t, f.rootID, "delegated")
			targetID := f.policy(t, "original", allow(`"*"`, "*"), "")
			target, err := f.org.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			if err != nil {
				t.Fatal(err)
			}
			content := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":"organizations:UpdatePolicy","Resource":%q}}`, member, *target.Policy.PolicySummary.Arn)
			input := &organizations.PutResourcePolicyInput{Content: &content, Tags: []orgtypes.Tag{{Key: aws.String("owner"), Value: aws.String("platform")}}}
			repository.failNext.Store(true)
			_, err = f.org.PutResourcePolicy(t.Context(), input)
			assertAPIError(t, err, "ServiceException")
			_, err = f.org.DescribeResourcePolicy(t.Context(), &organizations.DescribeResourcePolicyInput{})
			assertAPIError(t, err, "ResourcePolicyNotFoundException")
			saved, err := f.org.PutResourcePolicy(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			changed := fmt.Sprintf(`{"Statement":{"Effect":"Deny","Principal":{"AWS":%q},"Action":"organizations:UpdatePolicy","Resource":%q}}`, member, *target.Policy.PolicySummary.Arn)
			repository.failNext.Store(true)
			_, err = f.org.PutResourcePolicy(t.Context(), &organizations.PutResourcePolicyInput{Content: &changed})
			assertAPIError(t, err, "ServiceException")
			repository.failNext.Store(true)
			_, err = f.org.DeleteResourcePolicy(t.Context(), &organizations.DeleteResourcePolicyInput{})
			assertAPIError(t, err, "ServiceException")
			restored, err := f.org.DescribeResourcePolicy(t.Context(), &organizations.DescribeResourcePolicyInput{})
			if err != nil || !reflect.DeepEqual(restored.ResourcePolicy, saved.ResourcePolicy) {
				t.Fatalf("failed commit changed delegation: %+v, %v", restored, err)
			}
			tags, err := f.org.ListTagsForResource(t.Context(), &organizations.ListTagsForResourceInput{ResourceId: saved.ResourcePolicy.ResourcePolicySummary.Id})
			if err != nil || !reflect.DeepEqual(tags.Tags, input.Tags) {
				t.Fatalf("failed commit changed tags: %+v, %v", tags, err)
			}
			// Revoke the resource policy after an authorized command has prepared its
			// update. Its stale partition revision must not publish that command.
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			repository.pauseNext.Store(true)
			result := make(chan error, 1)
			actor := f.cloud.organizations(member, "test")
			go func() {
				_, err := actor.UpdatePolicy(ctx, &organizations.UpdatePolicyInput{PolicyId: &targetID, Name: aws.String("must-not-commit")})
				result <- err
			}()
			select {
			case <-repository.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if _, err := f.org.DeleteResourcePolicy(ctx, &organizations.DeleteResourcePolicyInput{}); err != nil {
				t.Fatal(err)
			}
			close(repository.resume)
			select {
			case err := <-result:
				assertAPIError(t, err, "AccessDeniedException")
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			current, err := f.org.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			if err != nil || aws.ToString(current.Policy.PolicySummary.Name) != "original" {
				t.Fatalf("revoked command committed: %+v, %v", current, err)
			}
		})
	}
}

func TestSQLiteDelegationMigrationRetainsOrganization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.sqlite")
	backends, closeDB := openSQLiteBackends(t, path)
	_, c, close := creationEventCloud(t, backends, clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)))
	org := c.organizations("test", "test")
	created, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	close()
	current := path
	path = filepath.Join(t.TempDir(), "version8.sqlite")
	db := awstest.HistoricalSQLite(t, path, "../storage/sqlite/schema", 8, current, map[string]string{
		"kernel_events": "SELECT * FROM fixture.kernel_events WHERE 0",
	})
	closeDB()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	c, _ = openSQLiteCloud(t, path, backends, nil)
	org = c.organizations("test", "test")
	restored, err := org.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
	if err != nil || !reflect.DeepEqual(restored.Organization, created.Organization) {
		t.Fatalf("migration lost organization: %+v, %v", restored, err)
	}
	_, err = org.DescribeResourcePolicy(t.Context(), &organizations.DescribeResourcePolicyInput{})
	assertAPIError(t, err, "ResourcePolicyNotFoundException")
	content := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"000000000000"},"Action":"organizations:DescribePolicy","Resource":"*"}}`
	if _, err := org.PutResourcePolicy(t.Context(), &organizations.PutResourcePolicyInput{Content: &content}); err != nil {
		t.Fatal(err)
	}
}
