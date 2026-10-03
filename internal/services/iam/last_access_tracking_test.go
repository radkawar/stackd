package iam_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/clock"
	"stackd/internal/services/iam"
)

func TestAccessReportServiceWindowSDK(t *testing.T) {
	// AWS documents days rather than an exact sub-day boundary. These cases
	// protect the local (snapshot-400d, snapshot] convention and distinguish it
	// from action history, whose tracking period is not a rolling 400 days.
	for _, epoch := range []time.Time{{}, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)} {
		t.Run(epoch.Format(time.RFC3339), func(t *testing.T) {
			for _, test := range []struct {
				name       string
				age        time.Duration
				future     bool
				serviceUse bool
			}{
				{name: "current", serviceUse: true},
				{name: "just inside", age: 400*24*time.Hour - time.Nanosecond, serviceUse: true},
				{name: "at cutoff", age: 400 * 24 * time.Hour},
				{name: "before cutoff", age: 400*24*time.Hour + time.Nanosecond},
				{name: "old action", age: 1000 * 24 * time.Hour},
				{name: "future activity", future: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					repository := iam.NewMemoryRepository(nil)
					source := clock.NewManual(epoch)
					service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
					t.Cleanup(func() { _ = service.Close() })
					client := clientFor(t, service, "123456789012", "us-east-1")
					user, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("window-subject")})
					if err != nil {
						t.Fatal(err)
					}
					_, err = client.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("Report"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}}`)})
					if err != nil {
						t.Fatal(err)
					}
					used := epoch
					if test.future {
						used = used.Add(time.Second)
					}
					activity := iam.PrincipalActivity{PrincipalID: aws.ToString(user.User.UserId), PrincipalARN: aws.ToString(user.User.Arn), ServiceNamespace: "iam", ActionName: "GetUser", Region: "eu-west-1", LastAuthenticated: used}
					scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
					if err := repository.Update(t.Context(), func(tx iam.WriteTx) error { return tx.PutPrincipalActivity(scope, activity) }); err != nil {
						t.Fatal(err)
					}
					if err := source.Advance(test.age); err != nil {
						t.Fatal(err)
					}
					generated, err := client.GenerateServiceLastAccessedDetails(t.Context(), &sdkiam.GenerateServiceLastAccessedDetailsInput{Arn: user.User.Arn, Granularity: types.AccessAdvisorUsageGranularityTypeActionLevel})
					if err != nil {
						t.Fatal(err)
					}
					out := finishAccessReport(t, service, source, client, generated.JobId)
					if len(out.ServicesLastAccessed) != 1 {
						t.Fatalf("services=%+v", out.ServicesLastAccessed)
					}
					row := out.ServicesLastAccessed[0]
					wantCount := int32(0)
					if test.serviceUse {
						wantCount = 1
					}
					if (row.LastAuthenticated != nil) != test.serviceUse || aws.ToInt32(row.TotalAuthenticatedEntities) != wantCount {
						t.Fatalf("service window: %+v, want activity=%v", row, test.serviceUse)
					}
					if test.serviceUse {
						if !row.LastAuthenticated.Equal(used) || aws.ToString(row.LastAuthenticatedEntity) != activity.PrincipalARN || aws.ToString(row.LastAuthenticatedRegion) != activity.Region {
							t.Fatalf("service history changed: %+v", row)
						}
					} else if row.LastAuthenticatedEntity != nil || row.LastAuthenticatedRegion != nil {
						t.Fatalf("absent service activity leaked entity/region: %+v", row)
					}
					if len(row.TrackedActionsLastAccessed) != 1 {
						t.Fatalf("tracked actions=%+v", row.TrackedActionsLastAccessed)
					}
					action := row.TrackedActionsLastAccessed[0]
					if (action.LastAccessedTime == nil) != test.future || !test.future && !action.LastAccessedTime.Equal(used) {
						t.Fatalf("action history was aged with service: %+v", action)
					}
					entities, err := client.GetServiceLastAccessedDetailsWithEntities(t.Context(), &sdkiam.GetServiceLastAccessedDetailsWithEntitiesInput{JobId: generated.JobId, ServiceNamespace: aws.String("iam")})
					if err != nil || len(entities.EntityDetailsList) != 1 || (entities.EntityDetailsList[0].LastAuthenticated != nil) != test.serviceUse {
						t.Fatalf("entity window=%+v error=%v", entities, err)
					}
					rows := activityRows(t, repository, scope, activity.PrincipalID)
					if len(rows) != 1 || rows[0] != activity {
						t.Fatalf("report generation mutated raw history: %+v", rows)
					}
				})
			}
		})
	}
}

func TestAccessReportSnapshotDoesNotAgeWhenRead(t *testing.T) {
	f := newActivityFixture(t, nil, time.Time{})
	key := f.user(t, "frozen-window")
	_, err := f.root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: aws.String("frozen-window"), PolicyName: aws.String("Use"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client("eu-west-1", key).GetUser(t.Context(), &sdkiam.GetUserInput{}); err != nil {
		t.Fatal(err)
	}
	generated, err := f.root.GenerateServiceLastAccessedDetails(t.Context(), &sdkiam.GenerateServiceLastAccessedDetailsInput{Arn: &key.PrincipalARN, Granularity: types.AccessAdvisorUsageGranularityTypeActionLevel})
	if err != nil {
		t.Fatal(err)
	}
	out := finishAccessReport(t, f.service, f.clock, f.root, generated.JobId)
	before, err := json.Marshal(out.ServicesLastAccessed)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.clock.Advance(401 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	// Job lifetime has no documented fixed TTL. Generation reuse, activity
	// windows, and credential expiration do not age a saved report in place.
	out, err = f.root.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId})
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(out.ServicesLastAccessed)
	if err != nil || string(before) != string(after) {
		t.Fatalf("saved snapshot aged: %s -> %s, %v", before, after, err)
	}
	newJob, err := f.root.GenerateServiceLastAccessedDetails(t.Context(), &sdkiam.GenerateServiceLastAccessedDetailsInput{Arn: &key.PrincipalARN, Granularity: types.AccessAdvisorUsageGranularityTypeActionLevel})
	if err != nil {
		t.Fatal(err)
	}
	current := finishAccessReport(t, f.service, f.clock, f.root, newJob.JobId)
	if len(current.ServicesLastAccessed) != 1 {
		t.Fatalf("services=%+v", current.ServicesLastAccessed)
	}
	row := current.ServicesLastAccessed[0]
	if row.LastAuthenticated != nil || aws.ToInt32(row.TotalAuthenticatedEntities) != 0 || len(row.TrackedActionsLastAccessed) != 1 || row.TrackedActionsLastAccessed[0].LastAccessedTime == nil || !row.TrackedActionsLastAccessed[0].LastAccessedTime.IsZero() {
		t.Fatalf("new snapshot did not separate windows: %+v", row)
	}
}
