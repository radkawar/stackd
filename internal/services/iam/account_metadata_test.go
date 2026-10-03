package iam_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/clock"
	"stackd/internal/services/iam"
	"stackd/internal/services/organizations"
)

type unavailableAccountIdentity struct{ fail atomic.Bool }

func (s *unavailableAccountIdentity) AccountIdentity(context.Context, string, string) (organizations.AccountRecord, error) {
	if s.fail.Load() {
		return organizations.AccountRecord{}, errors.New("account registry unavailable")
	}
	return organizations.AccountRecord{Name: "AccountName1", Email: "account@example.test"}, nil
}

func TestAccountIdentityFailureBlocksPasswordChecks(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: clock.NewManual(time.Unix(3600, 0).UTC())})
	source := &unavailableAccountIdentity{}
	source.fail.Store(true)
	service.SetAccountIdentitySource(source)
	client := clientFor(t, service, "123456789012", "us-east-1")
	// Bootstrap creation metadata belongs to IAM and needs no registry read.
	if _, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("first")}); err != nil {
		t.Fatal(err)
	}
	// Persisted dates remain available without the registry. A password still
	// needs the current account name/email and must not bypass a lookup failure.
	out, err := client.GetUser(t.Context(), &sdkiam.GetUserInput{})
	if err != nil || !out.User.CreateDate.Equal(time.Unix(3600, 0)) {
		t.Fatalf("persisted creation date: %+v %v", out, err)
	}
	_, err = client.CreateLoginProfile(t.Context(), &sdkiam.CreateLoginProfileInput{UserName: aws.String("first"), Password: aws.String("OrdinaryPassword1")})
	requireCode(t, err, "ServiceFailure")
	_, err = client.GetLoginProfile(t.Context(), &sdkiam.GetLoginProfileInput{UserName: aws.String("first")})
	requireCode(t, err, "NoSuchEntity")
	source.fail.Store(false)
	_, err = client.CreateLoginProfile(t.Context(), &sdkiam.CreateLoginProfileInput{UserName: aws.String("first"), Password: aws.String("AccountName1")})
	requireCode(t, err, "PasswordPolicyViolation")
}
