package iam_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/clock"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

func TestPasswordUsageHistoryFiveMinuteWindowAndZeroTime(t *testing.T) {
	for _, start := range []time.Time{{}, time.Unix(0, 0).UTC()} {
		t.Run(start.Format(time.RFC3339), func(t *testing.T) {
			ctx := t.Context()
			manual := clock.NewManual(start)
			repository := iam.NewMemoryRepository(nil)
			service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: manual})
			client := clientFor(t, service, "123456789012", "us-east-1")
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			name := "password-history"
			if _, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: &name}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: &name, Password: aws.String(loginPasswordA), PasswordResetRequired: true}); err != nil {
				t.Fatal(err)
			}
			read := func() *time.Time {
				t.Helper()
				out, err := client.GetUser(ctx, &sdkiam.GetUserInput{UserName: &name})
				if err != nil {
					t.Fatal(err)
				}
				return out.User.PasswordLastUsed
			}
			result, err := service.VerifyPassword(ctx, scope, name, loginPasswordA)
			if err != nil || !result.PasswordChangeRequired || read() != nil {
				t.Fatalf("incomplete sign-in recorded usage: %+v %v", result, err)
			}
			if _, err := client.UpdateLoginProfile(ctx, &sdkiam.UpdateLoginProfileInput{UserName: &name, PasswordResetRequired: aws.Bool(false)}); err != nil {
				t.Fatal(err)
			}
			if _, err := service.VerifyPassword(ctx, scope, name, loginPasswordA); err != nil {
				t.Fatal(err)
			}
			assertDate := func(want time.Time) {
				t.Helper()
				if got := read(); got == nil || !got.Equal(want) {
					t.Fatalf("PasswordLastUsed=%v, want %v", got, want)
				}
			}
			assertDate(start)
			if err := manual.Advance(5*time.Minute - time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			var group sync.WaitGroup
			failures := make(chan error, 6)
			for range 6 {
				group.Go(func() {
					_, err := service.VerifyPassword(ctx, scope, name, loginPasswordA)
					failures <- err
				})
			}
			group.Wait()
			close(failures)
			for err := range failures {
				if err != nil {
					t.Fatal(err)
				}
			}
			assertDate(start)
			if err := manual.Advance(time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			if _, err := service.VerifyPassword(ctx, scope, name, "incorrect"); !errors.Is(err, iam.ErrInvalidPassword) {
				t.Fatal(err)
			}
			assertDate(start)
			if _, err := service.VerifyPassword(ctx, scope, name, loginPasswordA); err != nil {
				t.Fatal(err)
			}
			assertDate(start.Add(5 * time.Minute))
			// A second service instance can reopen the same durable history
			// with an earlier clock; successful verification cannot erase it.
			earlier := iam.NewWithConfig(iam.Config{Repository: repository, Clock: clock.NewManual(start)})
			if _, err := earlier.VerifyPassword(ctx, scope, name, loginPasswordA); err != nil {
				t.Fatal(err)
			}
			assertDate(start.Add(5 * time.Minute))
		})
	}
}

func TestAccessKeyLastUsedReportsZeroTimeAndCoherentWindowThroughSDK(t *testing.T) {
	for _, start := range []time.Time{{}, time.Unix(0, 0).UTC()} {
		t.Run(start.Format(time.RFC3339), func(t *testing.T) {
			ctx := t.Context()
			manual := clock.NewManual(start)
			repository := iam.NewMemoryRepository(nil)
			credentials := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(repository, nil), Clock: manual})
			service := iam.NewWithConfig(iam.Config{Credentials: credentials, Repository: repository, Clock: manual})
			client := clientFor(t, service, "123456789012", "us-east-1")
			name := "key-history"
			if _, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: &name}); err != nil {
				t.Fatal(err)
			}
			key, err := client.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{UserName: &name})
			if err != nil {
				t.Fatal(err)
			}
			assertUse := func(when *time.Time, service, region string) {
				t.Helper()
				out, err := client.GetAccessKeyLastUsed(ctx, &sdkiam.GetAccessKeyLastUsedInput{AccessKeyId: key.AccessKey.AccessKeyId})
				if err != nil {
					t.Fatal(err)
				}
				got := out.AccessKeyLastUsed
				if (when == nil) != (got.LastUsedDate == nil) || (when != nil && !when.Equal(*got.LastUsedDate)) || aws.ToString(got.ServiceName) != service || aws.ToString(got.Region) != region {
					t.Fatalf("GetAccessKeyLastUsed=%+v, want %v/%s/%s", got, when, service, region)
				}
			}
			assertUse(nil, "N/A", "N/A")
			use := func(service, region string) {
				t.Helper()
				if err := credentials.RecordUsage(ctx, aws.ToString(key.AccessKey.AccessKeyId), service, region); err != nil {
					t.Fatal(err)
				}
			}
			use("sts", "eu-west-1")
			assertUse(&start, "sts", "eu-west-1")
			if err := manual.Advance(15*time.Minute - time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			use("kms", "us-west-2")
			assertUse(&start, "sts", "eu-west-1")
			if err := manual.Advance(time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			use("iam", "us-east-1")
			current := manual.Now()
			assertUse(&current, "iam", "N/A")
		})
	}
}

func TestRoleUsageStillRecordsRequestsWithinAccessKeyWindow(t *testing.T) {
	ctx := t.Context()
	start := time.Date(2037, 4, 5, 6, 7, 8, 0, time.UTC)
	manual := clock.NewManual(start)
	repository := iam.NewMemoryRepository(nil)
	credentials := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(repository, nil), Clock: manual})
	service := iam.NewWithConfig(iam.Config{Credentials: credentials, Repository: repository, Clock: manual})
	client := clientFor(t, service, "123456789012", "us-east-1")
	role, err := client.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("usage-role"), AssumeRolePolicyDocument: aws.String(trustEC2)})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := credentials.Resolve(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	session, err := credentials.IssueRoleSession(ctx, parent, identity.RoleSessionSpec{
		Role:        identity.Principal{AccountID: "123456789012", ARN: aws.ToString(role.Role.Arn), ID: aws.ToString(role.Role.RoleId)},
		SessionName: "used", Duration: time.Hour, MaxSessionDuration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, region := range []string{"us-east-1", "eu-west-1"} {
		if err := manual.Advance(time.Second); err != nil {
			t.Fatal(err)
		}
		if err := credentials.RecordUsage(ctx, session.AccessKeyID, "sqs", region); err != nil {
			t.Fatal(err)
		}
		out, err := client.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: role.Role.RoleName})
		if err != nil || out.Role.RoleLastUsed.LastUsedDate == nil || !out.Role.RoleLastUsed.LastUsedDate.Equal(manual.Now()) || aws.ToString(out.Role.RoleLastUsed.Region) != region {
			t.Fatalf("role request usage was coalesced: %+v %v", out, err)
		}
	}
}
