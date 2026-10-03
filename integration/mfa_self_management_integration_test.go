package stackd_test

import (
	"encoding/base32"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"stackd"
	"stackd/clock"
)

func TestMFASelfManagementAgainstAWS(t *testing.T) {
	check := mfaCapturedOutcomes(t, "mfa_self_management.json")
	source := clock.NewManual(time.Date(2035, 2, 3, 4, 5, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Clock: source})
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "self")
	c.user(t, "test", "other")
	putUserPolicy(t, root, "self", allow(`["iam:EnableMFADevice","iam:DeactivateMFADevice","iam:ResyncMFADevice"]`, "*"))
	caller := c.iam(key, secret, "")
	type device struct {
		serial *string
		seed   []byte
	}
	devices := make(map[string]device)
	for _, name := range []string{"first", "second", "other"} {
		created, err := root.CreateVirtualMFADevice(t.Context(), &iam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String(name)})
		check(t, "create_"+name, err)
		seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(created.VirtualMFADevice.Base32StringSeed))
		if err != nil {
			t.Fatal(err)
		}
		devices[name] = device{serial: created.VirtualMFADevice.SerialNumber, seed: seed}
	}
	pair := func(client *iam.Client, operation, name, owner string, offset int64) error {
		device := devices[name]
		step := source.Now().Unix()/30 + offset
		first, second := aws.String(otpForTest(device.seed, step-1)), aws.String(otpForTest(device.seed, step))
		if operation == "enable" {
			_, err := client.EnableMFADevice(t.Context(), &iam.EnableMFADeviceInput{UserName: aws.String(owner), SerialNumber: device.serial, AuthenticationCode1: first, AuthenticationCode2: second})
			return err
		}
		_, err := client.ResyncMFADevice(t.Context(), &iam.ResyncMFADeviceInput{UserName: aws.String(owner), SerialNumber: device.serial, AuthenticationCode1: first, AuthenticationCode2: second})
		return err
	}
	deactivate := func(client *iam.Client, serial *string) error {
		_, err := client.DeactivateMFADevice(t.Context(), &iam.DeactivateMFADeviceInput{UserName: aws.String("self"), SerialNumber: serial})
		return err
	}
	checkDenied := func(name string, err error) {
		t.Helper()
		check(t, name, err)
		if !strings.Contains(err.Error(), "authenticated with an MFA device") {
			t.Fatalf("wrong denial reason: %v", err)
		}
	}
	check(t, "self_enable_first_key", pair(caller, "enable", "first", "self", 0))
	advanceClock(t, source, 15*time.Second)
	checkDenied("self_enable_second_key", pair(caller, "enable", "second", "self", 0))
	checkDenied("self_enable_duplicate_key", pair(caller, "enable", "first", "self", 4))
	checkDenied("self_deactivate_key", deactivate(caller, devices["first"].serial))
	checkDenied("self_deactivate_missing_key", deactivate(caller, aws.String("arn:aws:iam::123456789012:mfa/missing")))
	check(t, "self_resync_key", pair(caller, "resync", "first", "self", 4))
	check(t, "other_enable_key", pair(caller, "enable", "other", "other", 0))
	advanceClock(t, source, 15*time.Second)
	issued, err := c.sts(key, secret, "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{SerialNumber: devices["first"].serial, TokenCode: aws.String(otpForTest(devices["first"].seed, source.Now().Unix()/30+5)), DurationSeconds: aws.Int32(900)})
	check(t, "issue_mfa_session", err)
	token := issued.Credentials
	session := c.iam(aws.ToString(token.AccessKeyId), aws.ToString(token.SecretAccessKey), aws.ToString(token.SessionToken))
	check(t, "self_enable_second_session", pair(session, "enable", "second", "self", 4))
	check(t, "self_deactivate_first_session", deactivate(session, devices["first"].serial))
	check(t, "self_deactivate_last_session", deactivate(session, devices["second"].serial))
	advanceClock(t, source, 15*time.Second)
	check(t, "self_reenroll_key", pair(caller, "enable", "first", "self", 8))
}

func TestMFAConcurrentSelfEnrollmentRequiresExistingMFA(t *testing.T) {
	source := clock.NewManual(time.Date(2035, 2, 3, 4, 5, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Clock: source})
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "self")
	putUserPolicy(t, root, "self", allow(`"iam:EnableMFADevice"`, "*"))
	caller := c.iam(key, secret, "")
	inputs := make([]*iam.EnableMFADeviceInput, 0, 2)
	for _, name := range []string{"one", "two"} {
		created, err := root.CreateVirtualMFADevice(t.Context(), &iam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String(name)})
		if err != nil {
			t.Fatal(err)
		}
		seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(created.VirtualMFADevice.Base32StringSeed))
		if err != nil {
			t.Fatal(err)
		}
		step := source.Now().Unix() / 30
		inputs = append(inputs, &iam.EnableMFADeviceInput{UserName: aws.String("self"), SerialNumber: created.VirtualMFADevice.SerialNumber, AuthenticationCode1: aws.String(otpForTest(seed, step-1)), AuthenticationCode2: aws.String(otpForTest(seed, step))})
	}
	var group sync.WaitGroup
	results := make(chan error, len(inputs))
	for _, input := range inputs {
		group.Go(func() { _, err := caller.EnableMFADevice(t.Context(), input); results <- err })
	}
	group.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			assertAPIError(t, err, "AccessDenied")
		}
	}
	if successes != 1 {
		t.Fatalf("long-term key enrolled %d devices without an existing MFA session", successes)
	}
}
