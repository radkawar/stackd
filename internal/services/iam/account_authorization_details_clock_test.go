package iam_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/clock"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

func TestAccountAuthorizationDetailsRoleUseAtEarlyEpoch(t *testing.T) {
	for _, epoch := range []time.Time{{}, time.Date(0, 12, 31, 0, 0, 0, 0, time.UTC)} {
		t.Run(epoch.Format(time.RFC3339), func(t *testing.T) {
			source := clock.NewManual(epoch)
			repository := iam.NewMemoryRepository(nil)
			service := iam.NewWithConfig(iam.Config{Clock: source, Repository: repository})
			client := clientFor(t, service, "123456789012", "us-east-1")
			created, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("early-role"), AssumeRolePolicyDocument: aws.String(trustEC2)})
			if err != nil {
				t.Fatal(err)
			}
			assertUsage := func(wantDate *time.Time) {
				t.Helper()
				report, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeRole}})
				if err != nil || len(report.RoleDetailList) != 1 {
					t.Fatalf("report=%+v error=%v", report, err)
				}
				get, err := client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: created.Role.RoleName})
				if err != nil {
					t.Fatal(err)
				}
				for _, used := range []*types.RoleLastUsed{report.RoleDetailList[0].RoleLastUsed, get.Role.RoleLastUsed} {
					if used == nil {
						t.Fatal("missing RoleLastUsed container")
					}
					if wantDate == nil {
						if used.LastUsedDate != nil || used.Region != nil {
							t.Fatalf("unused role has history: %+v", used)
						}
					} else if used.LastUsedDate == nil || !used.LastUsedDate.Equal(*wantDate) || aws.ToString(used.Region) != "eu-west-1" {
						t.Fatalf("role history=%+v, want %v in eu-west-1", used, wantDate)
					}
				}
			}
			assertUsage(nil)
			credentials := iam.NewCredentialRepository(repository, nil)
			record := identity.Record{Credential: identity.Credential{
				AccessKeyID: "ASIAEARLYROLE", AccountID: "123456789012",
				IssuerARN: aws.ToString(created.Role.Arn), IssuerID: aws.ToString(created.Role.RoleId),
			}, Status: identity.Active, LastUsed: identity.LastUsed{Service: "N/A", Region: "N/A"}}
			put := func() {
				t.Helper()
				if err := credentials.Update(t.Context(), func(tx identity.Transaction) error { return tx.Put(record) }); err != nil {
					t.Fatal(err)
				}
			}
			put()
			assertUsage(nil)
			record.LastUsed = identity.LastUsed{Date: epoch, Service: "sqs", Region: "eu-west-1"}
			put()
			assertUsage(&epoch)
			// A late-arriving older usage record cannot regress reported history.
			record.LastUsed.Date = epoch.Add(-time.Hour)
			put()
			assertUsage(&epoch)
			if err := source.Advance(400 * 24 * time.Hour); err != nil {
				t.Fatal(err)
			}
			assertUsage(nil)
		})
	}
}
