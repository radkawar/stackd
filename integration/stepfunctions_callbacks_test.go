package stackd_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sfn"

	"stackd/internal/awstest"
)

func TestStepFunctionsNativeCallbacksRecovery(t *testing.T) {
	stepFunctionsNativeRun(t, "callback_lifecycle", true, nil)
}

// Identical consecutive worker polls can lease concurrent branches in either
// order. Match each captured payload once, then bind its token so subsequent
// callbacks still exercise the captured branch, not whichever worker ran first.
func (r *stepFunctionsNativeReplay) activityLease(t *testing.T, row stepFunctionsNativeObservation, native, actual *sfn.GetActivityTaskOutput) *sfn.GetActivityTaskOutput {
	t.Helper()
	if actual.Input == nil {
		return native
	}
	rows := r.fixture.Observations
	index := slices.IndexFunc(rows, func(candidate stepFunctionsNativeObservation) bool { return candidate.Label == row.Label })
	if index < 0 {
		return native
	}
	samePoll := func(candidate stepFunctionsNativeObservation) bool {
		return candidate.Operation == row.Operation && candidate.Service == row.Service && candidate.Region == row.Region && candidate.Actor == row.Actor && string(candidate.Input) == string(row.Input) && candidate.Result.Code == "Success"
	}
	first, end := index, index+1
	for first > 0 && samePoll(rows[first-1]) {
		first--
	}
	for end < len(rows) && samePoll(rows[end]) {
		end++
	}
	var actualInput any
	awsDecodeJSON(t, json.RawMessage(*actual.Input), &actualInput)
	for _, candidate := range rows[first:end] {
		var expected sfn.GetActivityTaskOutput
		if err := awstest.DecodeSDK(candidate.Result.Output, &expected); err != nil {
			t.Fatal(err)
		}
		if expected.Input == nil || expected.TaskToken == nil {
			continue
		}
		if _, used := r.bindings[*expected.TaskToken]; used {
			continue
		}
		var expectedInput any
		awsDecodeJSON(t, r.input(t, json.RawMessage(*expected.Input)), &expectedInput)
		if reflect.DeepEqual(expectedInput, actualInput) {
			return &expected
		}
	}
	t.Fatalf("activity lease payload does not match any unconsumed capture in %s through %s: %s", rows[first].Label, rows[end-1].Label, *actual.Input)
	return nil
}
