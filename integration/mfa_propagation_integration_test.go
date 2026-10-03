package stackd_test

import (
	"encoding/base32"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestMFARecreationAgainstAWS(t *testing.T) {
	check := mfaCapturedOutcomes(t, "mfa_recreation_fresh.json")
	source, root, client, serial, oldSeed := newMFAConformanceFixture(t)
	auth := func(seed []byte, offset int64) error {
		_, err := client.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{SerialNumber: serial, TokenCode: aws.String(otpForTest(seed, source.Now().Unix()/30+offset))})
		return err
	}
	check(t, "before_recreate", auth(oldSeed, 1))
	_, err := root.DeactivateMFADevice(t.Context(), &iam.DeactivateMFADeviceInput{UserName: aws.String("mfa-window"), SerialNumber: serial})
	check(t, "deactivate_original", err)
	_, err = root.DeleteVirtualMFADevice(t.Context(), &iam.DeleteVirtualMFADeviceInput{SerialNumber: serial})
	check(t, "delete_original", err)
	replacement, err := root.CreateVirtualMFADevice(t.Context(), &iam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("window")})
	check(t, "create_replacement", err)
	if *replacement.VirtualMFADevice.SerialNumber != *serial {
		t.Fatal("replacement changed the resource ARN")
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(replacement.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	step := source.Now().Unix() / 30
	_, err = root.EnableMFADevice(t.Context(), &iam.EnableMFADeviceInput{UserName: aws.String("mfa-window"), SerialNumber: serial, AuthenticationCode1: aws.String(otpForTest(seed, step-1)), AuthenticationCode2: aws.String(otpForTest(seed, step))})
	check(t, "enable_replacement", err)
	check(t, "old_immediate", auth(oldSeed, 2))
	advanceClock(t, source, 12*time.Second)
	check(t, "old_later", auth(oldSeed, 2))
	// This counter was consumed against the original key before recreation.
	// A replacement's independent seed can authenticate at the same counter.
	check(t, "new_later", auth(seed, 1))
	advanceClock(t, source, 30*time.Second)
	check(t, "new_recovered", auth(seed, 1))
}

func mfaCapturedOutcomes(t *testing.T, filename string) func(*testing.T, string, error) {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/iam/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	var capture struct{ Observations []struct{ Case, Code string } }
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	codes := make(map[string]string)
	for _, row := range capture.Observations {
		codes[row.Case] = row.Code
	}
	return func(t *testing.T, name string, err error) {
		t.Helper()
		want, ok := codes[name]
		if !ok {
			t.Fatalf("missing AWS observation %s", name)
		}
		if want == "Success" {
			if err != nil {
				t.Fatalf("%s: AWS succeeded: %v", name, err)
			}
		} else {
			assertAPIError(t, err, want)
		}
	}
}

func TestMFAPropagationAgainstAWS(t *testing.T) {
	checkAWS := mfaCapturedOutcomes(t, "mfa_propagation.json")
	for _, transition := range []string{"deactivate", "delete", "resync", "reassign"} {
		for _, delay := range []int{0, 12} {
			label := transition + "_" + strconv.Itoa(delay)
			t.Run(label, func(t *testing.T) {
				check := func(name string, err error) {
					t.Helper()
					checkAWS(t, name+"_"+label, err)
				}
				source, root, client, serial, seed := newMFAConformanceFixture(t)
				auth := func(c *sts.Client, offset int64) (*sts.GetSessionTokenOutput, error) {
					return c.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{SerialNumber: serial, TokenCode: aws.String(otpForTest(seed, source.Now().Unix()/30+offset)), DurationSeconds: aws.Int32(900)})
				}
				other := client
				if transition == "reassign" {
					_, err := root.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("destination")})
					if err != nil {
						t.Fatal(err)
					}
					key, err := root.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: aws.String("destination")})
					if err != nil {
						t.Fatal(err)
					}
					other = sts.New(client.Options(), func(o *sts.Options) {
						o.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey), "")
					})
				}
				issued, err := auth(client, 1)
				check("before", err)
				if transition == "resync" {
					step := source.Now().Unix()/30 + 10
					_, err = root.ResyncMFADevice(t.Context(), &iam.ResyncMFADeviceInput{UserName: aws.String("mfa-window"), SerialNumber: serial, AuthenticationCode1: aws.String(otpForTest(seed, step-1)), AuthenticationCode2: aws.String(otpForTest(seed, step))})
				} else {
					_, err = root.DeactivateMFADevice(t.Context(), &iam.DeactivateMFADeviceInput{UserName: aws.String("mfa-window"), SerialNumber: serial})
				}
				check("transition", err)
				if transition == "delete" {
					_, err = root.DeleteVirtualMFADevice(t.Context(), &iam.DeleteVirtualMFADeviceInput{SerialNumber: serial})
					check("delete", err)
					listed, err := root.ListVirtualMFADevices(t.Context(), &iam.ListVirtualMFADevicesInput{})
					if err != nil || len(listed.VirtualMFADevices) != 0 {
						t.Fatalf("deleted device remained in IAM: %v %v", listed, err)
					}
				}
				if transition == "reassign" {
					step := source.Now().Unix()/30 + 4
					_, err = root.EnableMFADevice(t.Context(), &iam.EnableMFADeviceInput{UserName: aws.String("destination"), SerialNumber: serial, AuthenticationCode1: aws.String(otpForTest(seed, step-1)), AuthenticationCode2: aws.String(otpForTest(seed, step))})
					check("reassign", err)
				}
				listed, err := root.ListMFADevices(t.Context(), &iam.ListMFADevicesInput{UserName: aws.String("mfa-window")})
				check("list", err)
				wantCount := 0
				if transition == "resync" {
					wantCount = 1
				}
				if len(listed.MFADevices) != wantCount {
					t.Fatalf("IAM still reports preceding association: %v", listed)
				}
				// Local regression: changing IAM state cannot release a code
				// already consumed against the still-visible STS binding.
				_, err = auth(client, 1)
				assertAPIError(t, err, "AccessDenied")
				advanceClock(t, source, time.Duration(delay)*time.Second)
				_, err = auth(client, 2)
				check("old", err)
				if transition == "resync" {
					_, err = auth(client, 11)
					check("new", err)
				}
				if transition == "reassign" {
					_, err = auth(other, 5)
					check("new", err)
				}
				session := sts.New(client.Options(), func(o *sts.Options) {
					o.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(issued.Credentials.AccessKeyId), aws.ToString(issued.Credentials.SecretAccessKey), aws.ToString(issued.Credentials.SessionToken))
				})
				_, err = session.GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
				check("issued_session", err)
			})
		}
	}
}
