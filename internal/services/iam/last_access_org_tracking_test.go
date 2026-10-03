package iam_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/clock"
	iampolicy "stackd/iam/policy"
	"stackd/internal/services/iam"
	"stackd/internal/services/organizations"
)

type windowOrganizationSource struct {
	snapshot organizations.AccessReportSnapshot
	onRead   func() error
}

func (s windowOrganizationSource) AccessReportSnapshot(context.Context, string, string) (organizations.AccessReportSnapshot, error) {
	return s.snapshot, s.onRead()
}

func (windowOrganizationSource) CheckAccessReportAccess(context.Context) error { return nil }

func TestOrganizationAccessReportWindowSDK(t *testing.T) {
	for _, epoch := range []time.Time{{}, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)} {
		t.Run(epoch.Format(time.RFC3339), func(t *testing.T) {
			// The first account has a valid zero-epoch attempt and another older
			// identity. Other accounts have only boundary, old or future activity.
			snapshotTime := epoch.Add(400*24*time.Hour - time.Nanosecond)
			source := clock.NewManual(snapshotTime)
			repository := iam.NewMemoryRepository(nil)
			path := "o-1234567890/r-1234/ou-1234-window1234"
			snapshot := organizations.AccessReportSnapshot{PolicyLevels: []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: `{"Statement":{"Effect":"Allow","Action":["iam:GetUser","s3:ListAllMyBuckets"],"Resource":"*"}}`}}}}}
			for _, id := range []string{"111111111111", "222222222222", "333333333333", "444444444444"} {
				snapshot.Accounts = append(snapshot.Accounts, organizations.AccessReportAccount{AccountID: id, EntityPath: path + "/" + id})
			}
			service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source, OrganizationReports: windowOrganizationSource{snapshot: snapshot, onRead: func() error {
				// Eligibility must use IAM's captured transaction time even if the
				// dependency call advances the clock to the exact expiry boundary.
				return source.Advance(time.Nanosecond)
			}}})
			t.Cleanup(func() { _ = service.Close() })
			client := clientFor(t, service, "123456789012", "us-east-1")
			var retained []iam.PrincipalActivity
			if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
				for i, account := range snapshot.Accounts {
					used := epoch.Add(-time.Duration(i) * time.Nanosecond)
					if i == 3 {
						used = snapshotTime.Add(time.Second)
					}
					activity := iam.PrincipalActivity{PrincipalID: "principal", PrincipalARN: "arn:aws:iam::" + account.AccountID + ":user/window", ServiceNamespace: "iam", ActionName: "GetUser", Region: "eu-west-1", LastAuthenticated: used}
					if err := tx.PutPrincipalActivity(iam.Scope{Partition: "aws", AccountID: account.AccountID}, activity); err != nil {
						return err
					}
				}
				scope := iam.Scope{Partition: "aws", AccountID: snapshot.Accounts[0].AccountID}
				older := iam.PrincipalActivity{PrincipalID: "older-principal", ServiceNamespace: "iam", ActionName: "GetUser", Region: "ap-northeast-1", LastAuthenticated: epoch.Add(-24 * time.Hour)}
				if err := tx.PutPrincipalActivity(scope, older); err != nil {
					return err
				}
				foreign := older
				foreign.LastAuthenticated = snapshotTime
				foreign.Region = "cn-north-1"
				if err := tx.PutPrincipalActivity(iam.Scope{Partition: "aws-cn", AccountID: scope.AccountID}, foreign); err != nil {
					return err
				}
				var err error
				retained, err = tx.PrincipalActivities(scope)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			generated, err := client.GenerateOrganizationsAccessReport(t.Context(), &sdkiam.GenerateOrganizationsAccessReportInput{EntityPath: &path})
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := service.RunDueJobs(t.Context(), 100); err != nil {
				t.Fatal(err)
			}
			out, err := client.GetOrganizationsAccessReport(t.Context(), &sdkiam.GetOrganizationsAccessReportInput{JobId: generated.JobId})
			if err != nil || out.JobStatus != types.JobStatusTypeCompleted || len(out.AccessDetails) != 2 || aws.ToInt32(out.NumberOfServicesNotAccessed) != 1 {
				t.Fatalf("report=%+v error=%v", out, err)
			}
			entry := out.AccessDetails[0]
			if aws.ToString(entry.ServiceNamespace) != "iam" || entry.LastAuthenticatedTime == nil || !entry.LastAuthenticatedTime.Equal(epoch) || aws.ToInt32(entry.TotalAuthenticatedEntities) != 1 || aws.ToString(entry.EntityPath) != snapshot.Accounts[0].EntityPath || aws.ToString(entry.Region) != "eu-west-1" {
				t.Fatalf("window/count/partition/time capture mismatch: %+v", entry)
			}
			before, err := json.Marshal(out.AccessDetails)
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Advance(401 * 24 * time.Hour); err != nil {
				t.Fatal(err)
			}
			out, err = client.GetOrganizationsAccessReport(t.Context(), &sdkiam.GetOrganizationsAccessReportInput{JobId: generated.JobId})
			if err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(out.AccessDetails)
			if err != nil || string(before) != string(after) {
				t.Fatalf("saved Organization snapshot aged: %s -> %s, %v", before, after, err)
			}
			newJob, err := client.GenerateOrganizationsAccessReport(t.Context(), &sdkiam.GenerateOrganizationsAccessReportInput{EntityPath: &path})
			if err != nil || aws.ToString(newJob.JobId) == aws.ToString(generated.JobId) {
				t.Fatalf("new generation=%+v error=%v", newJob, err)
			}
			if err := source.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := service.RunDueJobs(t.Context(), 100); err != nil {
				t.Fatal(err)
			}
			out, err = client.GetOrganizationsAccessReport(t.Context(), &sdkiam.GetOrganizationsAccessReportInput{JobId: newJob.JobId})
			if err != nil || len(out.AccessDetails) != 2 || aws.ToInt32(out.NumberOfServicesNotAccessed) != 2 {
				t.Fatalf("aged report=%+v error=%v", out, err)
			}
			for _, entry := range out.AccessDetails {
				if entry.LastAuthenticatedTime != nil || entry.EntityPath != nil || aws.ToInt32(entry.TotalAuthenticatedEntities) != 0 {
					t.Fatalf("old/future source rows leaked: %+v", entry)
				}
			}
			if err := repository.View(t.Context(), func(tx iam.ReadTx) error {
				rows, err := tx.PrincipalActivities(iam.Scope{Partition: "aws", AccountID: snapshot.Accounts[0].AccountID})
				if err == nil && !slices.Equal(rows, retained) {
					t.Fatalf("report pruned raw activity: %+v -> %+v", retained, rows)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
