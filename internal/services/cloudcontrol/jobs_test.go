package cloudcontrol

import (
	"context"
	"fmt"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/internal/services/cloudformation"
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

type pendingAdmissionOwner struct {
	t               *testing.T
	attempts        int
	admitted        bool
	stabilizations  int
	operationTokens []string
	live            bool
}

func (*pendingAdmissionOwner) Validate(cloudformation.Properties) error { return nil }
func (*pendingAdmissionOwner) Replacement(cloudformation.Properties, cloudformation.Properties) (bool, error) {
	return false, nil
}
func (h *pendingAdmissionOwner) admit(r cloudformation.ResourceRequest) error {
	h.operationTokens = append(h.operationTokens, r.OperationToken)
	h.attempts++
	if h.attempts == 1 {
		return &awswire.Error{Code: "OperationInProgressException", Cause: fmt.Errorf("native transition: %w", &cloudformation.ResourcePendingError{Reason: "previous native operation remains busy"})}
	}
	h.admitted = true
	return nil
}
func (h *pendingAdmissionOwner) Create(_ context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.admit(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	h.live = true
	return cloudformation.ResourceResult{PhysicalID: "native-queue", Ref: "native-queue"}, nil
}
func (h *pendingAdmissionOwner) Update(_ context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.admit(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}, nil
}
func (h *pendingAdmissionOwner) Delete(_ context.Context, r cloudformation.ResourceRequest) error {
	return h.admit(r)
}
func (h *pendingAdmissionOwner) Read(context.Context, cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if !h.live {
		return nil, &awswire.Error{Code: "ResourceNotFoundException"}
	}
	return cloudformation.Properties{"QueueName": "owned-queue", "QueueUrl": "native-queue"}, nil
}
func (*pendingAdmissionOwner) List(context.Context, cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return nil, nil
}
func (h *pendingAdmissionOwner) Stabilize(context.Context, cloudformation.ResourceRequest) (bool, error) {
	if !h.admitted {
		h.t.Fatal("Cloud Control stabilized a command the owner never admitted")
	}
	h.stabilizations++
	return h.stabilizations > 1, nil
}
func (h *pendingAdmissionOwner) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ready, err := h.Stabilize(ctx, r)
	if ready {
		h.live = false
	}
	return ready, err
}

func TestPendingNativeAdmissionRetriesRetainedCloudControlCommand(t *testing.T) {
	for _, operation := range []string{"CREATE", "UPDATE", "DELETE"} {
		t.Run(operation, func(t *testing.T) {
			now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
			repository := NewMemoryRepository(nil)
			owner := &pendingAdmissionOwner{t: t, live: operation != "CREATE"}
			phase := "APPLY"
			if operation == "DELETE" {
				phase = "MUTATE"
			}
			request := RequestRecord{Scope: Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Token: "retained-request", TypeName: "AWS::SQS::Queue", Identifier: "native-queue", Desired: `{"QueueName":"owned-queue"}`, Before: `{"QueueName":"owned-queue"}`, Operation: operation, Status: "IN_PROGRESS", Phase: phase, Created: now, EventTime: now, Due: now, Revision: 1}
			if operation == "CREATE" {
				request.Identifier = ""
			}
			if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutRequest(request) }); err != nil {
				t.Fatal(err)
			}
			service := New(Config{Repository: repository, Clock: clock.NewManual(now), Handlers: map[string]cloudformation.ResourceHandler{request.TypeName: owner}})
			t.Cleanup(func() { _ = service.Close() })
			run := func() {
				t.Helper()
				if err := service.run(t.Context(), scheduler.Job{Key: request.Token, Version: request.Revision, Due: request.Due}); err != nil {
					t.Fatal(err)
				}
				if err := repository.View(t.Context(), func(r Reader) error { var err error; request, err = r.Request(request.Token); return err }); err != nil {
					t.Fatal(err)
				}
			}
			run()
			if request.Status != "IN_PROGRESS" || request.Phase != phase || request.ErrorCode != "" || !request.Due.After(now) || owner.admitted || owner.stabilizations != 0 {
				t.Fatalf("busy native transition lost unadmitted intent: %+v owner=%+v", request, owner)
			}
			run()
			if request.Status != "IN_PROGRESS" || request.Phase != "STABILIZE" || !owner.admitted || owner.attempts != 2 {
				t.Fatalf("retry bypassed native admission: %+v owner=%+v", request, owner)
			}
			run()
			if request.Status != "SUCCESS" || request.Phase != "DONE" || owner.attempts != 2 {
				t.Fatalf("admitted native command did not stabilize normally: %+v owner=%+v", request, owner)
			}
			for _, token := range owner.operationTokens {
				if token != request.Token {
					t.Fatalf("native operation identity changed across retry: %q", token)
				}
			}
			if operation == "DELETE" && owner.live {
				t.Fatal("successful deletion left the native owner live")
			}
		})
	}
}
