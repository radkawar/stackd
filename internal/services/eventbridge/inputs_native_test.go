package eventbridge_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
)

type nativeTargetInput struct {
	Case        string          `json:"case"`
	TargetInput json.RawMessage `json:"target_input"`
	ListedInput map[string]any  `json:"listed_input"`
	Admission   struct {
		Code   string         `json:"code"`
		Output map[string]any `json:"output"`
	} `json:"admission"`
}

type nativeTargetInputFixture struct {
	Observations []nativeTargetInput `json:"observations"`
	Updates      []nativeTargetInput `json:"updates"`
	Cleanup      bool                `json:"cleanup"`
}

func loadNativeTargetInputs(t *testing.T) nativeTargetInputFixture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/eventbridge/inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture nativeTargetInputFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.Cleanup {
		t.Fatal("native input probe cleanup is incomplete")
	}
	return fixture
}

func nativeInputTarget(t *testing.T, input json.RawMessage, id string) types.Target {
	t.Helper()
	var target types.Target
	if err := json.Unmarshal(input, &target); err != nil {
		t.Fatal(err)
	}
	target.Id = aws.String(id)
	target.Arn = aws.String("arn:aws:sqs:us-east-1:123456789012:input-fixture")
	return target
}

func putNativeInputTargets(t *testing.T, client *sdk.Client, rule string, targets []types.Target, expected string) *sdk.PutTargetsOutput {
	t.Helper()
	input := &sdk.PutTargetsInput{EventBusName: aws.String("input-fixtures"), Rule: aws.String(rule), Targets: targets}
	output, err := awstest.CallSDK(t.Context(), client, "PutTargets", json.RawMessage(mustJSON(t, input)))
	code := "Success"
	if err != nil {
		var apiError smithy.APIError
		if !errors.As(err, &apiError) {
			t.Fatal(err)
		}
		code = apiError.ErrorCode()
	}
	// The CLI enforces the model's minimum template length before sending.
	// The Go SDK sends this value to the generated frontend's same constraint.
	if expected == "ParamValidation" {
		expected = "ValidationException"
	}
	if code != expected {
		t.Fatalf("PutTargets: native=%s local=%s error=%v", expected, code, err)
	}
	if err != nil {
		return nil
	}
	return output.(*sdk.PutTargetsOutput)
}

func listNativeInputTargets(t *testing.T, client *sdk.Client, rule string) []types.Target {
	t.Helper()
	output, err := client.ListTargetsByRule(t.Context(), &sdk.ListTargetsByRuleInput{
		EventBusName: aws.String("input-fixtures"), Rule: aws.String(rule)})
	if err != nil {
		t.Fatal(err)
	}
	return output.Targets
}

func assertNativeInputStored(t *testing.T, target types.Target, expected map[string]any) {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(mustJSON(t, target)), &fields); err != nil {
		t.Fatal(err)
	}
	input := map[string]any{}
	for _, name := range []string{"Input", "InputPath", "InputTransformer"} {
		if fields[name] != nil {
			input[name] = fields[name]
		}
	}
	if !reflect.DeepEqual(normalized(input), normalized(expected)) {
		t.Fatalf("stored input: native=%s local=%s", mustJSON(t, normalized(expected)), mustJSON(t, normalized(input)))
	}
}

func createNativeInputRule(t *testing.T, client *sdk.Client, name string) {
	t.Helper()
	if _, err := client.PutRule(t.Context(), &sdk.PutRuleInput{Name: aws.String(name), EventBusName: aws.String("input-fixtures"),
		EventPattern: aws.String(`{"source":["input-fixtures"]}`)}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeTargetInputAdmissionSDK(t *testing.T) {
	fixture := loadNativeTargetInputs(t)
	backends(t, func(t *testing.T, b *backend) {
		service := newService(t, b, clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)), &sender{})
		client := sdkClient(t, service)
		if _, err := client.CreateEventBus(t.Context(), &sdk.CreateEventBusInput{Name: aws.String("input-fixtures")}); err != nil {
			t.Fatal(err)
		}
		for _, row := range fixture.Observations {
			t.Run(row.Case, func(t *testing.T) {
				createNativeInputRule(t, client, row.Case)
				target := nativeInputTarget(t, row.TargetInput, "target")
				output := putNativeInputTargets(t, client, row.Case, []types.Target{target}, row.Admission.Code)
				listed := listNativeInputTargets(t, client, row.Case)
				if output == nil {
					if len(listed) != 0 {
						t.Fatalf("rejected input persisted targets: %s", mustJSON(t, listed))
					}
					return
				}
				var actual map[string]any
				if err := json.Unmarshal([]byte(mustJSON(t, output)), &actual); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(normalized(actual), normalized(row.Admission.Output)) {
					t.Fatalf("admission: native=%s local=%s", mustJSON(t, normalized(row.Admission.Output)), mustJSON(t, normalized(actual)))
				}
				if len(listed) != 1 || aws.ToString(listed[0].Id) != "target" || aws.ToString(listed[0].Arn) != aws.ToString(target.Arn) {
					t.Fatalf("stored target identity changed: %s", mustJSON(t, listed))
				}
				assertNativeInputStored(t, listed[0], row.ListedInput)
			})
		}
	})
}

func TestNativeTargetInputUpdatesSDK(t *testing.T) {
	fixture := loadNativeTargetInputs(t)
	backends(t, func(t *testing.T, b *backend) {
		c := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
		service := newService(t, b, c, &sender{})
		client := sdkClient(t, service)
		if _, err := client.CreateEventBus(t.Context(), &sdk.CreateEventBusInput{Name: aws.String("input-fixtures")}); err != nil {
			t.Fatal(err)
		}
		createNativeInputRule(t, client, "updates")
		for _, row := range fixture.Updates {
			target := nativeInputTarget(t, row.TargetInput, "target")
			output := putNativeInputTargets(t, client, "updates", []types.Target{target}, row.Admission.Code)
			if output == nil || output.FailedEntryCount != 0 {
				t.Fatalf("replacement failed: %s", mustJSON(t, output))
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			b.reopen()
			service = newService(t, b, c, &sender{})
			client = sdkClient(t, service)
			listed := listNativeInputTargets(t, client, "updates")
			if len(listed) != 1 || aws.ToString(listed[0].Id) != "target" {
				t.Fatalf("replacement changed target count or ID: %s", mustJSON(t, listed))
			}
			assertNativeInputStored(t, listed[0], row.ListedInput)
		}
	})
}

func TestTargetInputValidationAtomicitySDK(t *testing.T) {
	fixture := loadNativeTargetInputs(t)
	rows := map[string]nativeTargetInput{}
	for _, row := range fixture.Observations {
		rows[row.Case] = row
	}
	backends(t, func(t *testing.T, b *backend) {
		service := newService(t, b, clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)), &sender{})
		client := sdkClient(t, service)
		if _, err := client.CreateEventBus(t.Context(), &sdk.CreateEventBusInput{Name: aws.String("input-fixtures")}); err != nil {
			t.Fatal(err)
		}
		createNativeInputRule(t, client, "atomic")
		initial := []types.Target{nativeInputTarget(t, rows["input-object"].TargetInput, "update"),
			nativeInputTarget(t, rows["typed-values"].TargetInput, "keep")}
		if output := putNativeInputTargets(t, client, "atomic", initial, "Success"); output.FailedEntryCount != 0 {
			t.Fatalf("initial targets failed: %s", mustJSON(t, output))
		}
		before := mustJSON(t, listNativeInputTargets(t, client, "atomic"))
		mixed := []types.Target{nativeInputTarget(t, rows["path-object"].TargetInput, "update"),
			nativeInputTarget(t, rows["input-array"].TargetInput, "new"),
			nativeInputTarget(t, rows["input-and-path"].TargetInput, "invalid")}
		putNativeInputTargets(t, client, "atomic", mixed, rows["input-and-path"].Admission.Code)
		if after := mustJSON(t, listNativeInputTargets(t, client, "atomic")); after != before {
			t.Fatalf("invalid target partially updated the rule:\nbefore=%s\nafter=%s", before, after)
		}
	})
}
