package stackd_test

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"stackd"
	"stackd/clock"
	"stackd/storage"
	iamstore "stackd/storage/iam"
)

func TestMFAAuthenticationAgainstAWS(t *testing.T) {
	for _, filename := range []string{
		"mfa_rejection.json", "mfa_rejection_threshold.json", "mfa_rejection_no_baseline.json",
		"mfa_rejection_success_count.json", "mfa_rejection_recovery.json", "mfa_rejection_aligned.json",
		"mfa_rejection_aligned_second.json", "mfa_rejection_odd_boundary.json", "mfa_recreation_limited.json",
		"mfa_recreation_limited_delayed.json",
		"mfa_synchronization_codes.json",
		"mfa_synchronization_reuse.json",
		"mfa_authentication_drift.json",
	} {
		t.Run(filename, func(t *testing.T) {
			data, err := os.ReadFile("../testdata/aws/iam/" + filename)
			if err != nil {
				t.Fatal(err)
			}
			var capture struct {
				Observations []struct {
					Case, Operation, Code, Message string
					RequestedAt                    time.Time `json:"requested_at"`
					SecondStep                     int64     `json:"second_step"`
					CodeStep                       int64     `json:"code_step"`
					Input                          struct{ UserName, VirtualMFADeviceName, SerialNumber string }
					Output                         struct{ VirtualMFADevice struct{ SerialNumber string } }
				}
			}
			if err := json.Unmarshal(data, &capture); err != nil {
				t.Fatal(err)
			}
			source := clock.NewManual(capture.Observations[0].RequestedAt)
			c := clockCloud(t, stackd.Config{Clock: source})
			root := c.iam("test", "test", "")
			clients := make(map[string]*sts.Client)
			owners := make(map[string]string)
			seeds := make(map[string][]byte)
			oldSeeds := make(map[string][]byte)
			serials := make(map[string]*string)
			for _, row := range capture.Observations {
				if row.Operation == "EnableMFADevice" && clients[row.Input.UserName] == nil {
					_, key, secret := c.user(t, "test", row.Input.UserName)
					clients[row.Input.UserName] = c.sts(key, secret, "")
				}
			}
			for _, row := range capture.Observations {
				advanceClock(t, source, row.RequestedAt.Sub(source.Now()))
				switch row.Operation {
				case "CreateVirtualMFADevice":
					if row.Case == "create_replacement" {
						// A normal IAM request can reclaim retired records. It must
						// retain a deleted ARN's unexpired verification budget.
						listed, listErr := root.ListVirtualMFADevices(t.Context(), &iam.ListVirtualMFADevicesInput{})
						if listErr != nil || len(listed.VirtualMFADevices) != 0 {
							t.Fatalf("deleted device remained listed: %v %v", listed, listErr)
						}
					}
					created, createErr := root.CreateVirtualMFADevice(t.Context(), &iam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String(row.Input.VirtualMFADeviceName)})
					err = createErr
					if err == nil {
						oldSeeds[row.Output.VirtualMFADevice.SerialNumber] = seeds[row.Output.VirtualMFADevice.SerialNumber]
						serials[row.Output.VirtualMFADevice.SerialNumber] = created.VirtualMFADevice.SerialNumber
						seeds[row.Output.VirtualMFADevice.SerialNumber], err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(created.VirtualMFADevice.Base32StringSeed))
					}
				case "EnableMFADevice":
					serial := row.Input.SerialNumber
					seed := seeds[serial]
					_, err = root.EnableMFADevice(t.Context(), &iam.EnableMFADeviceInput{UserName: aws.String(row.Input.UserName), SerialNumber: serials[serial], AuthenticationCode1: aws.String(otpForTest(seed, row.SecondStep-1)), AuthenticationCode2: aws.String(otpForTest(seed, row.SecondStep))})
					owners[serial] = row.Input.UserName
				case "ResyncMFADevice":
					serial := row.Input.SerialNumber
					seed := seeds[serial]
					_, err = root.ResyncMFADevice(t.Context(), &iam.ResyncMFADeviceInput{UserName: aws.String(row.Input.UserName), SerialNumber: serials[serial], AuthenticationCode1: aws.String(otpForTest(seed, row.SecondStep-1)), AuthenticationCode2: aws.String(otpForTest(seed, row.SecondStep))})
				case "DeactivateMFADevice":
					_, err = root.DeactivateMFADevice(t.Context(), &iam.DeactivateMFADeviceInput{UserName: aws.String(row.Input.UserName), SerialNumber: serials[row.Input.SerialNumber]})
				case "DeleteVirtualMFADevice":
					_, err = root.DeleteVirtualMFADevice(t.Context(), &iam.DeleteVirtualMFADeviceInput{SerialNumber: serials[row.Input.SerialNumber]})
				case "GetSessionToken":
					serial := row.Input.SerialNumber
					seed := seeds[serial]
					if strings.HasPrefix(row.Case, "old_") {
						seed = oldSeeds[serial]
					}
					_, err = clients[owners[serial]].GetSessionToken(t.Context(), &sts.GetSessionTokenInput{SerialNumber: serials[serial], TokenCode: aws.String(otpForTest(seed, row.CodeStep)), DurationSeconds: aws.Int32(900)})
				default:
					t.Fatalf("unexpected captured operation %s", row.Operation)
				}
				if row.Code == "Success" {
					if err != nil {
						t.Fatalf("%s: AWS succeeded: %v", row.Case, err)
					}
				} else {
					var apiErr smithy.APIError
					if !errors.As(err, &apiErr) || apiErr.ErrorCode() != row.Code || strings.TrimSpace(apiErr.ErrorMessage()) != strings.TrimSpace(row.Message) {
						t.Fatalf("%s: local=%v; AWS=%s: %s", row.Case, err, row.Code, row.Message)
					}
				}
			}
		})
	}
}

func TestMFAAttemptTransactionFailures(t *testing.T) {
	for _, action := range []string{"AssumeRole", "GetSessionToken"} {
		for _, failure := range []string{"write", "commit", "cancellation"} {
			t.Run(action+"/"+failure, func(t *testing.T) {
				f := newSignedAuthorityFixture(t, storage.NewMemory())
				signedMFADevice(t, f)
				var seed []byte
				err := f.repository.View(t.Context(), func(tx iamstore.ReadTx) error {
					device, err := tx.MFADevice(iamstore.Scope{Partition: "aws", AccountID: strings.Split(f.userARN, ":")[4]}, *f.session.SerialNumber)
					seed = []byte(device.Binding.Value.Seed)
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				good := f.session.TokenCode
				bad := aws.String(invalidMFAOTPForTest(seed, f.clock.Now().Unix()/30))
				f.session.TokenCode, f.assume.TokenCode = bad, bad
				for range 7 {
					_, err := f.issue(t.Context(), action)
					assertMFAAttemptError(t, err, false)
				}
				plan := &signedAuthorityPlan{key: f.key, failMFA: failure == "write", failCommit: failure == "commit", cancelCommit: failure == "cancellation"}
				f.repository.arm(plan)
				ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
				defer cancel()
				out, err := f.issue(ctx, action)
				plan.wait(t, ctx)
				assertAPIError(t, err, "InternalFailure")
				if out != nil || len(plan.issued) != 0 || f.sessionCount(t) != 0 {
					t.Fatal("failed authentication published a credential")
				}
				// The failed transaction did not spend an attempt. Both remaining
				// verifications still reach code validation before the limit applies.
				for range 2 {
					_, err := f.issue(t.Context(), action)
					assertMFAAttemptError(t, err, false)
				}
				f.session.TokenCode, f.assume.TokenCode = good, good
				_, err = f.issue(t.Context(), action)
				assertMFAAttemptError(t, err, true)
				advanceClock(t, f.clock, 3*time.Minute)
				good = aws.String(otpForTest(seed, f.clock.Now().Unix()/30+1))
				f.session.TokenCode, f.assume.TokenCode = good, good
				if _, err := f.issue(t.Context(), action); err != nil {
					t.Fatal("device did not recover", err)
				}
			})
		}
	}
}

func TestMFAConcurrentAttemptBudget(t *testing.T) {
	source, _, client, serial, seed := newMFAConformanceFixture(t)
	input := &sts.GetSessionTokenInput{SerialNumber: serial, TokenCode: aws.String(invalidMFAOTPForTest(seed, source.Now().Unix()/30))}
	var group sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		group.Go(func() { _, err := client.GetSessionToken(t.Context(), input); results <- err })
	}
	group.Wait()
	close(results)
	verified := 0
	for err := range results {
		assertAPIError(t, err, "AccessDenied")
		if strings.Contains(err.Error(), "invalid MFA one time pass code") {
			verified++
		} else {
			assertMFAAttemptError(t, err, true)
		}
	}
	if verified != 9 {
		t.Fatalf("%d concurrent requests reached MFA verification; want 9", verified)
	}
}

func assertMFAAttemptError(t *testing.T, err error, limited bool) {
	t.Helper()
	assertAPIError(t, err, "AccessDenied")
	message := "invalid MFA one time pass code"
	if limited {
		message = "unable to validate MFA code"
	}
	if !strings.Contains(err.Error(), message) {
		t.Fatalf("MFA denial = %v; want %s", err, message)
	}
}

// Choose an invalid code without depending on a random seed's decimal output.
func invalidMFAOTPForTest(seed []byte, step int64) string {
	for value := 0; ; value++ {
		code := fmt.Sprintf("%06d", value)
		matches := false
		for offset := int64(-2); offset <= 2; offset++ {
			matches = matches || code == otpForTest(seed, step+offset)
		}
		if !matches {
			return code
		}
	}
}
