package sqs

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func TestRedriveNativeStartingCountAndCompletion(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/sqs/redrive.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case   string
			Output struct {
				Results []types.ListMessageMoveTasksResultEntry
			}
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	f := retainedRedrive(t, NewMemoryRepository(nil), 12, 1)
	var moved int64
	for _, observation := range capture.Observations {
		if observation.Case != "progress" {
			continue
		}
		want := observation.Output.Results[0]
		// Compare at matching progress, not native polling timestamps: AWS
		// publishes approximate counters in bursts, and has variable startup.
		advance(t, f.clock, time.Duration(want.ApproximateNumberOfMessagesMoved-moved)*time.Second)
		if _, err := f.s.jobs.RunDue(t.Context(), 100); err != nil {
			t.Fatal(err)
		}
		got := f.status(t)
		if got.ApproximateNumberOfMessagesMoved != want.ApproximateNumberOfMessagesMoved || aws.ToInt64(got.ApproximateNumberOfMessagesToMove) != aws.ToInt64(want.ApproximateNumberOfMessagesToMove) || aws.ToString(got.Status) != aws.ToString(want.Status) || (got.TaskHandle == nil) != (want.TaskHandle == nil) {
			t.Fatalf("local task %v differs from native %v", got, want)
		}
		moved = want.ApproximateNumberOfMessagesMoved
	}
	if moved != 12 {
		t.Fatalf("incomplete native completion comparison: %d", moved)
	}
}
