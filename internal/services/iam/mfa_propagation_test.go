package iam_test

import (
	"encoding/base32"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"stackd/clock"
	"stackd/internal/awswire"
	"stackd/internal/services/iam"
	"stackd/internal/services/sts"
)

func TestMFAPendingRollbackReconstructionAndRetirement(t *testing.T) {
	source := clock.NewManual(iamClockEpoch.Truncate(time.Minute))
	repository := &mfaCommitRepository{Repository: iam.NewMemoryRepository(nil)}
	service := iam.NewWithConfig(iam.Config{Clock: source, Repository: repository})
	client := clientFor(t, service, "123456789012", "us-east-1")
	user, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("pending-owner")})
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateVirtualMFADevice(t.Context(), &sdkiam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("pending-device")})
	if err != nil {
		t.Fatal(err)
	}
	serial := created.VirtualMFADevice.SerialNumber
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(created.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	step := source.Now().Unix() / 30
	_, err = client.EnableMFADevice(t.Context(), &sdkiam.EnableMFADeviceInput{UserName: user.User.UserName, SerialNumber: serial, AuthenticationCode1: aws.String(testMFAOTP(seed, step-1)), AuthenticationCode2: aws.String(testMFAOTP(seed, step))})
	if err != nil {
		t.Fatal(err)
	}
	verify := func(offset int64) error {
		_, err := service.VerifyMFA(userContext(user.User, "aws"), *serial, testMFAOTP(seed, step+offset))
		return err
	}
	requireMFAVerificationDenied(t, verify(1))
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	repository.reject = true
	_, err = client.DeactivateMFADevice(t.Context(), &sdkiam.DeactivateMFADeviceInput{UserName: user.User.UserName, SerialNumber: serial})
	requireCode(t, err, "ServiceFailure")
	repository.reject = false
	// The enrollment deadline and the failed revocation both survive a new
	// provider using the same repository; no provider-local timer owns them.
	service = iam.NewWithConfig(iam.Config{Clock: source, Repository: repository})
	client = clientFor(t, service, "123456789012", "us-east-1")
	if err := source.Advance(9 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := verify(1); err != nil {
		t.Fatal("enrollment did not propagate", err)
	}
	_, err = client.DeactivateMFADevice(t.Context(), &sdkiam.DeactivateMFADeviceInput{UserName: user.User.UserName, SerialNumber: serial})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DeleteVirtualMFADevice(t.Context(), &sdkiam.DeleteVirtualMFADeviceInput{SerialNumber: serial})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListVirtualMFADevices(t.Context(), &sdkiam.ListVirtualMFADevicesInput{})
	if err != nil || len(listed.VirtualMFADevices) != 0 {
		t.Fatalf("IAM deletion: %v %v", listed, err)
	}
	if err := verify(2); err != nil {
		t.Fatal("deleted device lost preceding STS binding", err)
	}
	if err := source.Advance(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	readRetired := func() error {
		return repository.View(t.Context(), func(tx iam.ReadTx) error { _, err := tx.MFADevice(scope, *serial); return err })
	}
	_, err = client.ListVirtualMFADevices(t.Context(), &sdkiam.ListVirtualMFADevicesInput{})
	if err != nil {
		t.Fatal(err)
	}
	if err := readRetired(); err != nil {
		t.Fatal("revocation discarded the unexpired ARN verification budget", err)
	}
	if err := source.Advance(source.Now().Truncate(3 * time.Minute).Add(3 * time.Minute).Sub(source.Now())); err != nil {
		t.Fatal(err)
	}
	repository.reject = true
	_, err = client.ListVirtualMFADevices(t.Context(), &sdkiam.ListVirtualMFADevicesInput{})
	requireCode(t, err, "ServiceFailure")
	repository.reject = false
	if err := readRetired(); err != nil {
		t.Fatal("failed transaction reclaimed pending state", err)
	}
	_, err = client.ListVirtualMFADevices(t.Context(), &sdkiam.ListVirtualMFADevicesInput{})
	if err != nil {
		t.Fatal(err)
	}
	if err := readRetired(); !errors.Is(err, iam.ErrRecordNotFound) {
		t.Fatalf("expired MFA state not reclaimed: %v", err)
	}
}

func TestMFARapidReassignmentKeepsTransitionOrder(t *testing.T) {
	source := clock.NewManual(iamClockEpoch.Truncate(time.Minute))
	repository := iam.NewMemoryRepository(nil)
	service := iam.NewWithConfig(iam.Config{Clock: source, Repository: repository})
	client := clientFor(t, service, "123456789012", "us-east-1")
	owner, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("first")})
	if err != nil {
		t.Fatal(err)
	}
	other, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("second")})
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateVirtualMFADevice(t.Context(), &sdkiam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("ordered")})
	if err != nil {
		t.Fatal(err)
	}
	serial := created.VirtualMFADevice.SerialNumber
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(created.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	step := source.Now().Unix() / 30
	_, err = client.EnableMFADevice(t.Context(), &sdkiam.EnableMFADeviceInput{UserName: owner.User.UserName, SerialNumber: serial, AuthenticationCode1: aws.String(testMFAOTP(seed, step-1)), AuthenticationCode2: aws.String(testMFAOTP(seed, step))})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	_, err = client.DeactivateMFADevice(t.Context(), &sdkiam.DeactivateMFADeviceInput{UserName: owner.User.UserName, SerialNumber: serial})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	_, err = client.EnableMFADevice(t.Context(), &sdkiam.EnableMFADeviceInput{UserName: other.User.UserName, SerialNumber: serial, AuthenticationCode1: aws.String(testMFAOTP(seed, step+3)), AuthenticationCode2: aws.String(testMFAOTP(seed, step+4))})
	if err != nil {
		t.Fatal(err)
	}
	service = iam.NewWithConfig(iam.Config{Clock: source, Repository: repository})
	if err := source.Advance(8 * time.Second); err != nil {
		t.Fatal(err)
	}
	_, err = service.VerifyMFA(userContext(owner.User, "aws"), *serial, testMFAOTP(seed, step+1))
	if err != nil {
		t.Fatal("first enrollment was skipped", err)
	}
	_, err = service.VerifyMFA(userContext(other.User, "aws"), *serial, testMFAOTP(seed, step+5))
	requireMFAVerificationDenied(t, err)
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	_, err = service.VerifyMFA(userContext(owner.User, "aws"), *serial, testMFAOTP(seed, step+2))
	requireMFAVerificationDenied(t, err)
	_, err = service.VerifyMFA(userContext(other.User, "aws"), *serial, testMFAOTP(seed, step+5))
	requireMFAVerificationDenied(t, err)
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	_, err = service.VerifyMFA(userContext(other.User, "aws"), *serial, testMFAOTP(seed, step+5))
	if err != nil {
		t.Fatal("new enrollment did not propagate", err)
	}
}

func requireMFAVerificationDenied(t *testing.T, err error) {
	t.Helper()
	var apiErr *awswire.Error
	if !errors.Is(err, sts.ErrMFAUnavailable) && (!errors.As(err, &apiErr) || apiErr.Code != "InvalidAuthenticationCode") {
		t.Fatalf("expected invalid MFA code, got %v", err)
	}
}
