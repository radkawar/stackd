package stackd_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type stepFunctionsQuotaObservation struct {
	awsNativeObservation
	WireResponse struct {
		Body json.RawMessage
	} `json:"wire_response"`
}

func TestStepFunctionsNativeAPIThrottling(t *testing.T) {
	var fixture struct {
		Account, Region string
		Started         time.Time `json:"started_at"`
		Documentation   struct {
			Validation struct {
				Capacity int     `json:"bucket_size"`
				Refill   float64 `json:"refill_per_second"`
			} `json:"ValidateStateMachineDefinition_default"`
		}
		Observations []stepFunctionsQuotaObservation
	}
	awsReadFixture(t, "stepfunctions/api_throttling.json", &fixture)
	observation := func(label string) stepFunctionsQuotaObservation {
		t.Helper()
		for _, row := range fixture.Observations {
			if row.Label == label {
				return row
			}
		}
		t.Fatalf("missing native quota observation %q", label)
		return stepFunctionsQuotaObservation{}
	}
	valid := observation("baseline-valid")
	invalid := observation("baseline-invalid-definition")
	throttled := observation("mixed-after-burst-1")
	invalidThrottled := observation("mixed-after-burst-2")
	recovered := observation("natural-idle-recovery-1")
	quota := fixture.Documentation.Validation
	if quota.Capacity <= 0 || quota.Refill <= 0 {
		t.Fatal("native fixture does not identify the nominal validation quota")
	}
	interval := time.Duration(float64(time.Second) / quota.Refill)

	// AWS's concurrent burst success count is not a fleet bucket measurement.
	// Exercise the captured nominal 100/1 quota locally at frozen service time,
	// while retaining the native SDK success, diagnostic and throttle outcomes.
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Started)
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			client := func(account, region string) *sfn.Client {
				return sfn.New(sfn.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL),
					Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""),
					HTTPClient:  clients.server.Client(), RetryMaxAttempts: 1})
			}
			call := func(api *sfn.Client, row stepFunctionsQuotaObservation) {
				t.Helper()
				var input sfn.ValidateStateMachineDefinitionInput
				if err := awstest.DecodeSDK(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				output, err := api.ValidateStateMachineDefinition(t.Context(), &input)
				awsNativeResult(t, row.awsNativeObservation, err)
				if err != nil {
					var nativeBody struct{ Message string }
					awsDecodeJSON(t, row.WireResponse.Body, &nativeBody)
					var modeled interface{ ErrorMessage() string }
					if !errors.As(err, &modeled) || modeled.ErrorMessage() != nativeBody.Message {
						t.Fatalf("%s: native throttle message %q, local %v", row.Label, nativeBody.Message, err)
					}
					return
				}
				var expected sfn.ValidateStateMachineDefinitionOutput
				if err := awstest.DecodeSDK(row.Result.Output, &expected); err != nil {
					t.Fatal(err)
				}
				if output.Result != expected.Result {
					t.Fatalf("%s: native validation result %s, local %s", row.Label, expected.Result, output.Result)
				}
			}
			api := client(fixture.Account, fixture.Region)
			// A semantic diagnostic is an admitted API call and spends a token.
			call(api, invalid)
			for range quota.Capacity - 1 {
				call(api, valid)
			}
			call(api, throttled)
			call(api, invalidThrottled)

			// A new SDK client cannot replenish its account/Region bucket.
			call(client(fixture.Account, fixture.Region), throttled)
			otherRegion := "eu-west-1"
			if otherRegion == fixture.Region {
				otherRegion = "us-east-1"
			}
			call(client(fixture.Account, otherRegion), valid)
			otherAccount := "111111111111"
			if otherAccount == fixture.Account {
				otherAccount = "222222222222"
			}
			call(client(otherAccount, fixture.Region), valid)
			call(api, throttled)

			// Fractional refill cannot admit a whole request, and denied calls
			// cannot create debt that postpones the next available token.
			advanceClock(t, source, interval/2)
			call(api, throttled)
			advanceClock(t, source, interval-interval/2)
			call(api, invalid)
			call(api, throttled)
			advanceClock(t, source, interval)
			call(api, recovered)
			call(api, throttled)
		})
	}
}

func TestStepFunctionsNativeStartExecutionQuotas(t *testing.T) {
	var fixture struct {
		Account      string
		Started      time.Time `json:"started_at"`
		Observations []awsNativeObservation
	}
	awsReadFixture(t, "stepfunctions/api_throttling.json", &fixture)
	const region = "us-west-1"
	var capacity, refill int
	for _, row := range fixture.Observations {
		if row.Service != "service-quotas" || row.Region != region || stepFunctionsOperation(row.Operation) != "listawsdefaultservicequotas" {
			continue
		}
		var output struct {
			Quotas []struct {
				QuotaName string
				Value     float64
			}
		}
		awsDecodeJSON(t, row.Result.Output, &output)
		for _, quota := range output.Quotas {
			switch quota.QuotaName {
			case "StartExecution throttle token bucket size":
				capacity = int(quota.Value)
			case "StartExecution throttle token refill rate per second":
				refill = int(quota.Value)
			}
		}
	}
	if capacity <= 0 || refill <= 0 {
		t.Fatal("native fixture does not identify the regional StartExecution quota")
	}
	source := clock.NewManual(fixture.Started)
	clients, _ := retainedCloud(t, "memory", stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return startPublicCloud(t, config)
	})
	api := sfn.New(sfn.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1,
		Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")})
	role, err := clients.iam(fixture.Account, "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("quota-worker"),
		AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	machines := map[sfntypes.StateMachineType]*string{}
	for _, typ := range []sfntypes.StateMachineType{sfntypes.StateMachineTypeStandard, sfntypes.StateMachineTypeExpress} {
		machine, err := api.CreateStateMachine(t.Context(), &sfn.CreateStateMachineInput{Name: aws.String("quota-" + string(typ)), RoleArn: role.Role.Arn, Type: typ,
			Definition: aws.String(`{"StartAt":"Hold","States":{"Hold":{"Type":"Wait","Seconds":30,"End":true}}}`)})
		if err != nil {
			t.Fatal(err)
		}
		machines[typ] = machine.StateMachineArn
	}
	standard := &sfn.StartExecutionInput{StateMachineArn: machines[sfntypes.StateMachineTypeStandard], Name: aws.String("same-execution"), Input: aws.String("{}")}
	first, err := api.StartExecution(t.Context(), standard)
	if err != nil {
		t.Fatal(err)
	}
	// Idempotency avoids hundreds of retained executions, but does not bypass
	// admission: every public StartExecution request spends an API token.
	for range capacity - 1 {
		repeated, err := api.StartExecution(t.Context(), standard)
		if err != nil {
			t.Fatal(err)
		}
		if aws.ToString(repeated.ExecutionArn) != aws.ToString(first.ExecutionArn) || !aws.ToTime(repeated.StartDate).Equal(aws.ToTime(first.StartDate)) {
			t.Fatal("idempotent StartExecution changed the retained execution")
		}
	}
	_, err = api.StartExecution(t.Context(), standard)
	assertAPIError(t, err, "ThrottlingException")
	_, err = api.StartExecution(t.Context(), &sfn.StartExecutionInput{StateMachineArn: machines[sfntypes.StateMachineTypeStandard], Name: aws.String("blocked-execution"), Input: aws.String("{}")})
	assertAPIError(t, err, "ThrottlingException")

	// Async Express has a separate StartExecution bucket even in the same
	// account and Region; exhausting Standard must not block its admission.
	if _, err := api.StartExecution(t.Context(), &sfn.StartExecutionInput{StateMachineArn: machines[sfntypes.StateMachineTypeExpress], Name: aws.String("express-execution"), Input: aws.String("{}")}); err != nil {
		t.Fatalf("Express shared exhausted Standard admission: %v", err)
	}
	_, err = api.StartExecution(t.Context(), standard)
	assertAPIError(t, err, "ThrottlingException")

	interval := (time.Second + time.Duration(refill) - 1) / time.Duration(refill)
	advanceClock(t, source, interval)
	recovered, err := api.StartExecution(t.Context(), standard)
	if err != nil {
		t.Fatalf("Standard did not recover after service-time refill: %v", err)
	}
	if aws.ToString(recovered.ExecutionArn) != aws.ToString(first.ExecutionArn) {
		t.Fatal("refilled StartExecution changed the retained execution")
	}
	_, err = api.StartExecution(t.Context(), standard)
	assertAPIError(t, err, "ThrottlingException")
	executions, err := api.ListExecutions(t.Context(), &sfn.ListExecutionsInput{StateMachineArn: machines[sfntypes.StateMachineTypeStandard]})
	if err != nil {
		t.Fatal(err)
	}
	if len(executions.Executions) != 1 || aws.ToString(executions.Executions[0].ExecutionArn) != aws.ToString(first.ExecutionArn) || executions.NextToken != nil {
		t.Fatalf("idempotent or rejected starts created additional executions: %+v", executions)
	}
}
