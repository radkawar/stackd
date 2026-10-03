package stackd_test

import (
	"encoding/base32"
	"encoding/json"
	"os"
	"strconv"
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

func TestMFASTSInterleavedReuseAndConcurrency(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/mfa_reuse.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case, Code string
			Step       int64 `json:"code_step"`
			SecondStep int64 `json:"second_step"`
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	source, root, client, serial, seed := newMFAConformanceFixture(t)
	var first int64
	observed := 0
	for _, row := range capture.Observations {
		if !strings.HasPrefix(row.Case, "reuse_") {
			continue
		}
		if first == 0 {
			first = row.Step
		}
		observed++
		code := otpForTest(seed, source.Now().Unix()/30+row.Step-first)
		out, err := client.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{SerialNumber: serial, TokenCode: aws.String(code)})
		if row.Code == "Success" {
			if err != nil || out.Credentials == nil {
				t.Fatalf("%s: AWS succeeded: %v", row.Case, err)
			}
		} else {
			assertAPIError(t, err, row.Code)
		}
	}
	if observed != 6 {
		t.Fatalf("expected six interleaved AWS authentication observations, got %d", observed)
	}
	for _, row := range capture.Observations {
		if !strings.HasPrefix(row.Case, "resync_after_use_") {
			continue
		}
		second := source.Now().Unix()/30 + row.SecondStep - first
		_, err := root.ResyncMFADevice(t.Context(), &iam.ResyncMFADeviceInput{UserName: aws.String("mfa-window"), SerialNumber: serial, AuthenticationCode1: aws.String(otpForTest(seed, second-1)), AuthenticationCode2: aws.String(otpForTest(seed, second))})
		if row.Code == "Success" {
			if err != nil {
				t.Fatalf("%s: AWS resynchronized: %v", row.Case, err)
			}
		} else {
			assertAPIError(t, err, row.Code)
		}
	}
	advanceClock(t, source, 3*time.Minute)
	// The last successful resynchronization selected the third future step.
	in := &sts.GetSessionTokenInput{SerialNumber: serial, TokenCode: aws.String(otpForTest(seed, source.Now().Unix()/30+3))}
	var group sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		group.Go(func() {
			_, err := client.GetSessionToken(t.Context(), in)
			results <- err
		})
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
		t.Fatalf("one MFA code issued %d concurrent sessions", successes)
	}
}

func TestMFASTSWindowAndReuseAgainstAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/mfa_verification.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Code string
			Step       int64 `json:"code_step"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for delta := int64(-3); delta <= 3; delta++ {
		t.Run(strconv.FormatInt(delta, 10), func(t *testing.T) {
			source, _, client, serial, seed := newMFAConformanceFixture(t)
			var previousStep int64
			for attempt := 0; attempt < 2; attempt++ {
				name := "use_offset_" + strconv.FormatInt(delta, 10) + "_" + strconv.Itoa(attempt)
				found := false
				for _, row := range fixture.Observations {
					if row.Case != name {
						continue
					}
					found = true
					if attempt > 0 && row.Step != previousStep {
						advanceClock(t, source, time.Duration(row.Step-previousStep)*30*time.Second)
					}
					previousStep = row.Step
					out, err := client.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{SerialNumber: serial, TokenCode: aws.String(otpForTest(seed, source.Now().Unix()/30+delta))})
					if row.Code == "Success" {
						if err != nil || out.Credentials == nil {
							t.Fatalf("%s: AWS issued credentials: %v", name, err)
						}
					} else {
						assertAPIError(t, err, row.Code)
					}
				}
				if !found {
					t.Fatalf("missing AWS observation %s", name)
				}
			}
		})
	}
}

func TestMFAUnusedCodesCanArriveOutOfOrderAgainstAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/mfa_code_order.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case, Code string
			Step       int64 `json:"code_step"`
			Offset     int64 `json:"code_step_offset"`
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []string{"future", "current", "past"} {
		t.Run(sequence, func(t *testing.T) {
			source, _, client, serial, seed := newMFAConformanceFixture(t)
			var origin int64
			for _, row := range capture.Observations {
				if !strings.HasPrefix(row.Case, sequence+"_") {
					continue
				}
				if origin == 0 {
					origin = row.Step - row.Offset
				}
				_, err := client.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{SerialNumber: serial, TokenCode: aws.String(otpForTest(seed, source.Now().Unix()/30+row.Step-origin))})
				if row.Code != "Success" || err != nil {
					t.Fatalf("%s: AWS=%s, local=%v", row.Case, row.Code, err)
				}
			}
			if origin == 0 {
				t.Fatal("missing AWS code-order observations")
			}
		})
	}
}

func newMFAConformanceFixture(t *testing.T) (*clock.Manual, *iam.Client, *sts.Client, *string, []byte) {
	t.Helper()
	source := clock.NewManual(time.Date(2035, 2, 3, 4, 5, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Clock: source})
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "mfa-window")
	created, err := root.CreateVirtualMFADevice(t.Context(), &iam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("window")})
	if err != nil {
		t.Fatal(err)
	}
	serial := created.VirtualMFADevice.SerialNumber
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(created.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	step := source.Now().Unix() / 30
	_, err = root.EnableMFADevice(t.Context(), &iam.EnableMFADeviceInput{UserName: aws.String("mfa-window"), SerialNumber: serial, AuthenticationCode1: aws.String(otpForTest(seed, step-1)), AuthenticationCode2: aws.String(otpForTest(seed, step))})
	if err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 2*time.Minute)
	return source, root, c.sts(key, secret, ""), serial, seed
}
