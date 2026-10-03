package iam_test

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"stackd/clock"
	"stackd/internal/services/iam"
)

func TestMFAPairWindowAndClockAdjustmentAgainstAWS(t *testing.T) {
	for _, filename := range []string{"mfa_pair_window.json", "mfa_resync_anchor.json"} {
		t.Run(filename, func(t *testing.T) {
			data, err := os.ReadFile("../../../testdata/aws/iam/" + filename)
			if err != nil {
				t.Fatal(err)
			}
			var capture struct {
				Observations []struct {
					Case, Operation string
					Offset          int64 `json:"second_step_offset"`
				}
			}
			if err := json.Unmarshal(data, &capture); err != nil {
				t.Fatal(err)
			}
			check := mfaAWSResults(t, filename)
			source := clock.NewManual(iamClockEpoch)
			c := clientFor(t, iam.NewWithConfig(iam.Config{Clock: source}), "123456789012", "us-east-1")
			name := aws.String("window-owner")
			if _, err := c.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: name}); err != nil {
				t.Fatal(err)
			}
			var serial *string
			var seed []byte
			for i, row := range capture.Observations {
				var err error
				switch row.Operation {
				case "CreateVirtualMFADevice":
					created, createErr := c.CreateVirtualMFADevice(t.Context(), &sdkiam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("window-" + strconv.Itoa(i))})
					if createErr != nil {
						t.Fatal(createErr)
					}
					serial = created.VirtualMFADevice.SerialNumber
					seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(created.VirtualMFADevice.Base32StringSeed))
				case "EnableMFADevice", "ResyncMFADevice":
					step := source.Now().Unix()/30 + row.Offset
					first, second := aws.String(testMFAOTP(seed, step-1)), aws.String(testMFAOTP(seed, step))
					if row.Operation == "EnableMFADevice" {
						_, err = c.EnableMFADevice(t.Context(), &sdkiam.EnableMFADeviceInput{UserName: name, SerialNumber: serial, AuthenticationCode1: first, AuthenticationCode2: second})
					} else {
						_, err = c.ResyncMFADevice(t.Context(), &sdkiam.ResyncMFADeviceInput{UserName: name, SerialNumber: serial, AuthenticationCode1: first, AuthenticationCode2: second})
					}
				case "DeactivateMFADevice":
					_, err = c.DeactivateMFADevice(t.Context(), &sdkiam.DeactivateMFADeviceInput{UserName: name, SerialNumber: serial})
				case "DeleteVirtualMFADevice":
					_, err = c.DeleteVirtualMFADevice(t.Context(), &sdkiam.DeleteVirtualMFADeviceInput{SerialNumber: serial})
				default:
					t.Fatalf("unexpected captured operation %s", row.Operation)
				}
				check(row.Case, err)
			}
		})
	}
}

type mfaCommitRepository struct {
	iam.Repository
	reject bool
}

func (r *mfaCommitRepository) Update(ctx context.Context, fn func(iam.WriteTx) error) error {
	return r.Repository.Update(ctx, func(tx iam.WriteTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if r.reject {
			return errors.New("MFA commit failed")
		}
		return nil
	})
}

func TestMFACodePairHistoryAndRollback(t *testing.T) {
	check := mfaAWSResults(t, "mfa_time.json")
	source := clock.NewManual(iamClockEpoch)
	repository := &mfaCommitRepository{Repository: iam.NewMemoryRepository(nil)}
	s := iam.NewWithConfig(iam.Config{Clock: source, Repository: repository})
	c := clientFor(t, s, "123456789012", "us-east-1")
	name := aws.String("pair-owner")
	if _, err := c.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: name}); err != nil {
		t.Fatal(err)
	}
	created, err := c.CreateVirtualMFADevice(t.Context(), &sdkiam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("pair-device")})
	if err != nil {
		t.Fatal(err)
	}
	serial := created.VirtualMFADevice.SerialNumber
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(created.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	pair := func(second int64, enable bool) error {
		t.Helper()
		firstCode, secondCode := aws.String(testMFAOTP(seed, second-1)), aws.String(testMFAOTP(seed, second))
		if enable {
			_, err := c.EnableMFADevice(t.Context(), &sdkiam.EnableMFADeviceInput{UserName: name, SerialNumber: serial, AuthenticationCode1: firstCode, AuthenticationCode2: secondCode})
			return err
		}
		_, err := c.ResyncMFADevice(t.Context(), &sdkiam.ResyncMFADeviceInput{UserName: name, SerialNumber: serial, AuthenticationCode1: firstCode, AuthenticationCode2: secondCode})
		return err
	}
	step := source.Now().Unix() / 30
	check("enable", pair(step, true))
	check("resync_enrollment_pair", pair(step, false))
	future := step + 10
	repository.reject = true
	requireCode(t, pair(future, false), "ServiceFailure")
	repository.reject = false
	check("resync_future", pair(future, false))
	// Reconstructing a provider retains the accepted pair counter in storage.
	c = clientFor(t, iam.NewWithConfig(iam.Config{Clock: source, Repository: repository}), "123456789012", "us-east-1")
	check("resync_same_pair", pair(future, false))
	check("resync_overlap_pair", pair(future+1, false))
	check("resync_next_pair", pair(future+2, false))
	check("resync_backwards", pair(step, false))
	_, err = c.DeactivateMFADevice(t.Context(), &sdkiam.DeactivateMFADeviceInput{UserName: name, SerialNumber: serial})
	check("deactivate", err)
	check("reenroll_same_pair", pair(future+2, true))
	check("reenroll_overlap_pair", pair(future+3, true))
	check("reenroll_next_pair", pair(future+4, true))
}

func mfaAWSResults(t *testing.T, filename string) func(string, error) {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/iam/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Code string
			Status     int `json:"http_status"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return func(name string, err error) {
		t.Helper()
		for _, row := range fixture.Observations {
			if row.Case != name {
				continue
			}
			if row.Code == "Success" {
				if err != nil {
					t.Fatalf("%s: AWS succeeded: %v", name, err)
				}
				return
			}
			requireCode(t, err, row.Code)
			var response interface{ HTTPStatusCode() int }
			if !errors.As(err, &response) || response.HTTPStatusCode() != row.Status {
				t.Fatalf("%s: AWS status %d: %v", name, row.Status, err)
			}
			return
		}
		t.Fatalf("missing AWS observation %s", name)
	}
}

func TestMFAVirtualAWSLifecycle(t *testing.T) {
	check := mfaAWSResults(t, "mfa.json")
	source := clock.NewManual(iamClockEpoch)
	c := clientFor(t, iam.NewWithConfig(iam.Config{Clock: source}), "123456789012", "us-east-1")
	for _, name := range []string{"owner", "other"} {
		if _, err := c.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	create := &sdkiam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("phone"), Path: aws.String("/devices/"), Tags: []types.Tag{{Key: aws.String("owner"), Value: aws.String("probe")}}}
	created, err := c.CreateVirtualMFADevice(t.Context(), create)
	check("create", err)
	serial := created.VirtualMFADevice.SerialNumber
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(created.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateVirtualMFADevice(t.Context(), create)
	check("duplicate_create", err)
	deactivate := &sdkiam.DeactivateMFADeviceInput{UserName: aws.String("owner"), SerialNumber: serial}
	_, err = c.DeactivateMFADevice(t.Context(), deactivate)
	check("deactivate_unassigned", err)
	step := source.Now().Unix() / 30
	enable := &sdkiam.EnableMFADeviceInput{UserName: aws.String("owner"), SerialNumber: serial, AuthenticationCode1: aws.String(testMFAOTP(seed, step-1)), AuthenticationCode2: aws.String(testMFAOTP(seed, step))}
	resync := &sdkiam.ResyncMFADeviceInput{UserName: enable.UserName, SerialNumber: serial, AuthenticationCode1: enable.AuthenticationCode1, AuthenticationCode2: enable.AuthenticationCode2}
	_, err = c.ResyncMFADevice(t.Context(), resync)
	check("resync_unassigned", err)
	_, err = c.EnableMFADevice(t.Context(), enable)
	check("enable", err)
	_, err = c.EnableMFADevice(t.Context(), enable)
	check("enable_duplicate", err)
	enable.UserName = aws.String("other")
	_, err = c.EnableMFADevice(t.Context(), enable)
	check("enable_other", err)
	_, err = c.DeleteVirtualMFADevice(t.Context(), &sdkiam.DeleteVirtualMFADeviceInput{SerialNumber: serial})
	check("delete_assigned", err)
	_, err = c.DeleteUser(t.Context(), &sdkiam.DeleteUserInput{UserName: aws.String("owner")})
	check("delete_assigned_user", err)
	deactivate.UserName, resync.UserName = aws.String("other"), aws.String("other")
	_, err = c.DeactivateMFADevice(t.Context(), deactivate)
	check("deactivate_other", err)
	_, err = c.ResyncMFADevice(t.Context(), resync)
	check("resync_other", err)
	listed, err := c.ListVirtualMFADevices(t.Context(), &sdkiam.ListVirtualMFADevicesInput{AssignmentStatus: types.AssignmentStatusTypeAssigned})
	check("list_assigned", err)
	if len(listed.VirtualMFADevices) != 1 {
		t.Fatal("missing assigned device")
	}
	device := listed.VirtualMFADevices[0]
	if len(device.Tags) != 0 || len(device.Base32StringSeed) != 0 || len(device.QRCodePNG) != 0 || device.User == nil || aws.ToString(device.User.UserName) != "owner" || device.EnableDate == nil {
		t.Fatal("assigned MFA response differs from AWS fields")
	}
	deactivate.UserName = aws.String("owner")
	_, err = c.DeactivateMFADevice(t.Context(), deactivate)
	check("deactivate", err)
	_, err = c.DeactivateMFADevice(t.Context(), deactivate)
	check("deactivate_again", err)
	listed, err = c.ListVirtualMFADevices(t.Context(), &sdkiam.ListVirtualMFADevicesInput{AssignmentStatus: types.AssignmentStatusTypeUnassigned})
	check("list_after_deactivate", err)
	if len(listed.VirtualMFADevices) != 1 || listed.VirtualMFADevices[0].User != nil || listed.VirtualMFADevices[0].EnableDate != nil || len(listed.VirtualMFADevices[0].Tags) != 0 {
		t.Fatal("unassigned MFA response differs from AWS fields")
	}
}
