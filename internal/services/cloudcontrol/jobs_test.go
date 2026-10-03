package cloudcontrol

import (
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/scheduler"
)

// A retained request can outlive its registered owner. That is a downstream
// service failure, not an attempt to update a create-only property:
// https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/resource-type-test-contract-errors.html
func TestRecoveredCreationWithoutHandlerReportsServiceFailure(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	repository := NewMemoryRepository(nil)
	request := RequestRecord{
		Scope: Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"},
		Token: "retained-request", TypeName: "Custom::RemovedOwner", Desired: "{}",
		Operation: "CREATE", Status: "IN_PROGRESS", Phase: "APPLY",
		Created: now, EventTime: now, Due: now, Revision: 1,
	}
	if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutRequest(request) }); err != nil {
		t.Fatal(err)
	}
	service := New(Config{Repository: repository, Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = service.Close() })
	if err := service.run(t.Context(), scheduler.Job{Key: request.Token, Version: request.Revision, Due: request.Due}); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(t.Context(), func(r Reader) error {
		completed, err := r.Request(request.Token)
		if err != nil {
			return err
		}
		output := progress(completed)
		if text(output.Operation) != "CREATE" || text(output.OperationStatus) != "FAILED" || text(output.ErrorCode) != "GeneralServiceException" {
			t.Fatalf("missing handler misclassified the recovered request: %+v", output)
		}
		_, pending, err := r.NextRequest()
		if err == nil && pending {
			t.Fatal("terminal unsupported owner remained retryable")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
