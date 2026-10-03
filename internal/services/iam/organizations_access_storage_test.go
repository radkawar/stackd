package iam_test

import (
	"errors"
	"testing"
	"time"

	"stackd/internal/services/iam"
)

func TestOrganizationAccessReportStorageRollbackAndDetachedResults(t *testing.T) {
	repo := iam.NewMemoryRepository(nil)
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	created := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	report := iam.AccessReport{ID: "report", Owner: "owner", RequestedAt: created, Organization: &iam.OrganizationAccessReport{
		EntityPath: "o-aaaaaaaaaa/r-abcd", PolicyID: "p-00000000",
		Services: []iam.OrganizationServiceAccess{{Namespace: "sqs", AuthenticatedAccounts: 2, LastActivity: &iam.AccountActivity{EntityPath: "o-aaaaaaaaaa/r-abcd/111111111111", Region: "eu-west-1", LastAuthenticated: created}}},
	}}
	abort := errors.New("abort report acceptance")
	if err := repo.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := tx.PutAccessReport(scope, report); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if err := repo.View(t.Context(), func(tx iam.ReadTx) error {
		_, err := tx.LatestOrganizationAccessReport(scope, report.Owner, report.Organization.EntityPath, report.Organization.PolicyID)
		return err
	}); !errors.Is(err, iam.ErrRecordNotFound) {
		t.Fatalf("aborted generation leaked into reuse: %v", err)
	}
	if err := repo.Update(t.Context(), func(tx iam.WriteTx) error { return tx.PutAccessReport(scope, report) }); err != nil {
		t.Fatal(err)
	}
	report.Organization.Services[0].LastActivity.Region = "mutated"
	for range 2 {
		if err := repo.View(t.Context(), func(tx iam.ReadTx) error {
			stored, err := tx.LatestOrganizationAccessReport(scope, "owner", "o-aaaaaaaaaa/r-abcd", "p-00000000")
			if err != nil {
				return err
			}
			if stored.Organization.Services[0].LastActivity.Region != "eu-west-1" {
				t.Fatal("repository leaked report activity ownership")
			}
			stored.Organization.Services[0].LastActivity.Region = "reader mutation"
			stored.Organization.PolicyID = "changed selector"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Failed reports use the same storage and reuse path; error details must
	// remain immutable after publication just like completed activity rows.
	failed := iam.AccessReport{ID: "failed", Owner: "owner", RequestedAt: created, Organization: &iam.OrganizationAccessReport{EntityPath: "o-aaaaaaaaaa/r-abcd/missing", Error: &iam.AccessReportError{Code: "INVALID_ORGANIZATIONS_ENTITY_PATH", Message: "missing"}}}
	if err := repo.Update(t.Context(), func(tx iam.WriteTx) error { return tx.PutAccessReport(scope, failed) }); err != nil {
		t.Fatal(err)
	}
	failed.Organization.Error.Code = "mutated"
	for range 2 {
		if err := repo.View(t.Context(), func(tx iam.ReadTx) error {
			stored, err := tx.AccessReport(scope, "failed")
			if err != nil {
				return err
			}
			if stored.Organization.Error.Code != "INVALID_ORGANIZATIONS_ENTITY_PATH" {
				t.Fatal("repository leaked report failure ownership")
			}
			stored.Organization.Error.Code = "reader mutation"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
