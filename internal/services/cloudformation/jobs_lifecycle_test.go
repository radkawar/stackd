package cloudformation

import (
	"context"
	"fmt"
	"maps"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type lifecycleRepository struct {
	Repository
	inside bool
}

func (r *lifecycleRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.Repository.Update(ctx, func(tx Transaction) error {
		r.inside = true
		defer func() { r.inside = false }()
		return fn(tx)
	})
}

// The owner retains an exclusive slot and asynchronous native transitions.
// It rejects creating into an occupied slot, rather than echoing controller
// inputs, so wrong deletion/restoration ordering cannot pass these regressions.
type lifecycleOwner struct {
	t                  *testing.T
	repository         *lifecycleRepository
	live               map[string]Properties
	tokens             map[string]string
	deleting           map[string]int
	creating           map[string]int
	calls              []string
	requests           []ResourceRequest
	pendingAction      string
	pending            int
	readError          error
	resultError        error
	failCreate         bool
	admitBeforeFailure bool
	next               int
}

func (h *lifecycleOwner) Validate(Properties) error { return nil }
func (h *lifecycleOwner) Replacement(a, b Properties) (bool, error) {
	return a["RouteTableId"] != b["RouteTableId"], nil
}
func (h *lifecycleOwner) command(action string, r ResourceRequest) error {
	h.t.Helper()
	if h.repository.inside {
		h.t.Fatal("native owner effect ran inside a repository transaction")
	}
	if r.OperationToken == "" {
		h.t.Fatal("native command lacked a retained operation identity")
	}
	h.calls = append(h.calls, action)
	h.requests = append(h.requests, r)
	if h.pendingAction == action && h.pending > 0 {
		h.pending--
		return &awswire.Error{Code: "OperationInProgressException", Cause: fmt.Errorf("native busy: %w", &ResourcePendingError{Reason: "prior native transition is active"})}
	}
	return nil
}
func (h *lifecycleOwner) Create(_ context.Context, r ResourceRequest) (ResourceResult, error) {
	if err := h.command("CREATE", r); err != nil {
		return ResourceResult{}, err
	}
	if id := h.tokens[r.Token]; id != "" {
		if _, exists := h.live[id]; exists {
			return ResourceResult{PhysicalID: id, Ref: id}, nil
		}
		return ResourceResult{}, fmt.Errorf("deleted token cannot resurrect its old physical incarnation")
	}
	for _, properties := range h.live {
		if properties["SubnetId"] == r.Properties["SubnetId"] {
			return ResourceResult{}, fmt.Errorf("exclusive native slot is occupied")
		}
	}
	if h.failCreate && !h.admitBeforeFailure {
		h.failCreate = false
		return ResourceResult{}, &awswire.Error{Code: "AccessDenied", Message: "native create rejected before admission"}
	}
	h.next++
	id := fmt.Sprintf("assoc-%d", h.next)
	h.live[id] = maps.Clone(r.Properties)
	h.tokens[r.Token] = id
	h.creating[id] = 1
	if h.failCreate {
		h.failCreate = false
		return ResourceResult{}, &awswire.Error{Code: "AccessDenied", Message: "post-admission step failed before the result could be retained"}
	}
	return ResourceResult{PhysicalID: id, Ref: "unsettled-" + id}, nil
}
func (h *lifecycleOwner) RecoverCreation(_ context.Context, r ResourceRequest) (ResourceResult, error) {
	if err := h.command("RECOVER_CREATE", r); err != nil {
		return ResourceResult{}, err
	}
	id := h.tokens[r.Token]
	if _, exists := h.live[id]; id != "" && exists {
		return ResourceResult{PhysicalID: id, Ref: id}, nil
	}
	return ResourceResult{}, &awswire.Error{Code: "Resource.NotFound", Message: "this exact native incarnation was not admitted"}
}
func (h *lifecycleOwner) Update(_ context.Context, r ResourceRequest) (ResourceResult, error) {
	if err := h.command("UPDATE", r); err != nil {
		return ResourceResult{}, err
	}
	if _, exists := h.live[r.PhysicalID]; !exists {
		return ResourceResult{}, &awswire.Error{Code: "Resource.NotFound"}
	}
	h.live[r.PhysicalID] = maps.Clone(r.Properties)
	return ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}, nil
}
func (h *lifecycleOwner) Delete(_ context.Context, r ResourceRequest) error {
	if err := h.command("DELETE", r); err != nil {
		return err
	}
	if _, exists := h.live[r.PhysicalID]; exists {
		if _, admitted := h.deleting[r.PhysicalID]; !admitted {
			h.deleting[r.PhysicalID] = 1
		}
	}
	return nil
}
func (h *lifecycleOwner) Read(_ context.Context, r ResourceRequest) (Properties, error) {
	if err := h.command("READ", r); err != nil {
		return nil, err
	}
	if h.readError != nil {
		return nil, h.readError
	}
	if properties, exists := h.live[r.PhysicalID]; exists {
		return maps.Clone(properties), nil
	}
	return nil, &awswire.Error{Code: "Resource.NotFound", Message: "native association is absent"}
}
func (h *lifecycleOwner) List(context.Context, ResourceRequest) ([]ResourceDescription, error) {
	return nil, nil
}
func (h *lifecycleOwner) Stabilize(_ context.Context, r ResourceRequest) (bool, error) {
	if err := h.command("STABILIZE", r); err != nil {
		return false, err
	}
	if _, deleting := h.deleting[r.PhysicalID]; deleting {
		return false, nil
	}
	if h.creating[r.PhysicalID] > 0 {
		h.creating[r.PhysicalID]--
		return false, nil
	}
	_, exists := h.live[r.PhysicalID]
	return exists, nil
}
func (h *lifecycleOwner) StabilizeDeletion(_ context.Context, r ResourceRequest) (bool, error) {
	if err := h.command("STABILIZE_DELETE", r); err != nil {
		return false, err
	}
	if h.deleting[r.PhysicalID] > 0 {
		h.deleting[r.PhysicalID]--
		return false, nil
	}
	delete(h.live, r.PhysicalID)
	delete(h.deleting, r.PhysicalID)
	return true, nil
}
func (h *lifecycleOwner) Result(_ context.Context, r ResourceRequest) (ResourceResult, error) {
	if err := h.command("RESULT", r); err != nil {
		return ResourceResult{}, err
	}
	if h.resultError != nil {
		return ResourceResult{}, h.resultError
	}
	if _, exists := h.live[r.PhysicalID]; !exists {
		return ResourceResult{}, &awswire.Error{Code: "Resource.NotFound"}
	}
	return ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{"Id": r.PhysicalID}}, nil
}

func lifecycleFixture(t *testing.T, action, phase string) (*Service, *lifecycleRepository, *lifecycleOwner, OperationRecord) {
	t.Helper()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	r := &lifecycleRepository{Repository: NewMemoryRepository(nil)}
	h := &lifecycleOwner{t: t, repository: r, live: map[string]Properties{}, tokens: map[string]string{}, deleting: map[string]int{}, creating: map[string]int{}}
	before := ResourceRecord{StackID: "stack", LogicalID: "Association", Type: "AWS::EC2::SubnetRouteTableAssociation", PhysicalID: "assoc-original", Ref: "assoc-original", Generation: 1, Token: "original-incarnation", Current: true, Properties: Properties{"SubnetId": "subnet", "RouteTableId": "original"}, Status: "CREATE_COMPLETE"}
	after := before
	after.Generation, after.Token = 2, "replacement-incarnation"
	after.PhysicalID, after.Ref = "", ""
	after.Properties = Properties{"SubnetId": "subnet", "RouteTableId": "desired"}
	if action == "UPDATE" {
		after.PhysicalID, after.Ref, after.Generation, after.Token = before.PhysicalID, before.Ref, before.Generation, before.Token
	}
	if action == "CREATE" {
		before = ResourceRecord{}
	}
	step := StepRecord{LogicalID: "Association", Action: action, State: "PENDING", Before: before, After: after}
	if phase == "ROLLBACK" {
		step.State = "SUCCEEDED"
		if action == "CREATE" {
			step.After.PhysicalID, step.After.Ref = "assoc-created", "assoc-created"
		}
	}
	body := `{"Resources":{"Association":{"Type":"AWS::EC2::SubnetRouteTableAssociation","Properties":{"SubnetId":"subnet","RouteTableId":"original"}}},"Outputs":{"Association":{"Value":{"Ref":"Association"}}}}`
	op := OperationRecord{ID: "retained-operation", StackID: "stack", Kind: "UPDATE", Phase: phase, Template: body, Steps: []StepRecord{step}, Revision: 1, Due: now, Caller: awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"}}
	if action == "DELETE" {
		op.Kind = "DELETE"
	}
	stack := StackRecord{ID: "stack", Name: "test", Template: body, OperationID: op.ID, Scope: Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Outputs: map[string]OutputValue{"Association": {Value: "assoc-original"}}}
	if before.PhysicalID != "" {
		h.live[before.PhysicalID] = maps.Clone(before.Properties)
		h.tokens[before.Token] = before.PhysicalID
	}
	if phase == "ROLLBACK" && action == "CREATE" {
		h.live[step.After.PhysicalID] = maps.Clone(after.Properties)
		h.tokens[after.Token] = step.After.PhysicalID
	}
	if err := r.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutStack(stack); err != nil {
			return err
		}
		if before.PhysicalID != "" {
			if err := tx.PutResource(before); err != nil {
				return err
			}
		}
		return tx.PutOperation(op)
	}); err != nil {
		t.Fatal(err)
	}
	s := New(Config{Repository: r, Clock: clock.NewManual(now), Handlers: map[string]ResourceHandler{after.Type: h}})
	t.Cleanup(func() { _ = s.Close() })
	return s, r, h, op
}

func lifecycleRun(t *testing.T, s *Service, r Repository, id string) OperationRecord {
	t.Helper()
	var op OperationRecord
	if err := r.View(t.Context(), func(reader Reader) error { var err error; op, err = reader.Operation(id); return err }); err != nil {
		t.Fatal(err)
	}
	if err := s.runDeployment(t.Context(), scheduler.Job{Key: id, Version: op.Revision, Due: op.Due}); err != nil {
		t.Fatal(err)
	}
	if err := r.View(t.Context(), func(reader Reader) error { var err error; op, err = reader.Operation(id); return err }); err != nil {
		t.Fatal(err)
	}
	return op
}

func TestPendingAdmissionRetainsDeploymentAndUndoIntent(t *testing.T) {
	for _, tc := range []struct{ action, phase, pending string }{{"CREATE", "APPLY", "CREATE"}, {"UPDATE", "APPLY", "UPDATE"}, {"DELETE", "APPLY", "DELETE"}, {"CREATE", "ROLLBACK", "DELETE"}, {"UPDATE", "ROLLBACK", "UPDATE"}} {
		t.Run(tc.phase+"/"+tc.action, func(t *testing.T) {
			s, r, h, initial := lifecycleFixture(t, tc.action, tc.phase)
			h.pendingAction, h.pending = tc.pending, 1
			op := lifecycleRun(t, s, r, initial.ID)
			want := "RUNNING"
			if tc.phase == "ROLLBACK" {
				want = "SUCCEEDED"
			}
			if op.Phase != tc.phase || op.Cursor != initial.Cursor || op.Steps[0].State != want || !op.Steps[0].AdmissionPending || !op.Due.After(initial.Due) {
				t.Fatalf("unadmitted native command lost its retained intent: %+v", op)
			}
			op = lifecycleRun(t, s, r, initial.ID)
			if op.Steps[0].AdmissionPending || op.Phase == "DONE" || op.Steps[0].State != map[string]string{"APPLY": "STABILIZING", "ROLLBACK": "UNDO_STABILIZING"}[tc.phase] {
				t.Fatalf("retry did not admit the original retained command: %+v", op)
			}
			for _, request := range h.requests {
				if request.OperationToken != initial.ID {
					t.Fatalf("unstable deployment identity: %+v", request)
				}
			}
		})
	}
}

func TestDeleteFirstRollbackWaitsForNativeRestorationAndRefreshesOutputs(t *testing.T) {
	s, r, h, initial := lifecycleFixture(t, "REPLACE", "APPLY")
	op := initial
	for i := 0; i < 12 && op.Cursor == 0; i++ {
		op = lifecycleRun(t, s, r, initial.ID)
	}
	if op.Cursor != 1 || !op.Steps[0].BeforeDeleted || len(op.Steps) != 1 {
		t.Fatalf("replacement did not delete its exclusive old owner exactly once: %+v", op)
	}
	if _, exists := h.live["assoc-original"]; exists {
		t.Fatal("old native association still exists after replacement")
	}
	if err := r.Update(t.Context(), func(tx Transaction) error { op.Phase, op.Cursor = "ROLLBACK", 0; return tx.PutOperation(op) }); err != nil {
		t.Fatal(err)
	}
	h.pendingAction, h.pending = "CREATE", 1
	for i := 0; i < 16 && op.Phase != "DONE"; i++ {
		op = lifecycleRun(t, s, r, initial.ID)
	}
	if op.Phase != "DONE" || op.Steps[0].Restore.PhysicalID == "" || op.Steps[0].Restore.PhysicalID == "assoc-original" || op.Steps[0].Restore.Token == "original-incarnation" {
		t.Fatalf("old properties were not recreated as a native incarnation: %+v", op)
	}
	restored := op.Steps[0].Restore
	if len(h.live) != 1 || h.live[restored.PhysicalID]["RouteTableId"] != "original" {
		t.Fatalf("rollback did not restore the actual exclusive native slot: %+v", h.live)
	}
	if err := r.View(t.Context(), func(reader Reader) error {
		stack, err := reader.Stack("stack")
		if err != nil {
			return err
		}
		if stack.Status != "UPDATE_ROLLBACK_COMPLETE" || stack.Outputs["Association"].Value != restored.PhysicalID || restored.Ref != restored.PhysicalID {
			t.Fatalf("rollback retained a deleted or unstabilized output: %+v restore=%+v", stack, restored)
		}
		resources, err := reader.Resources("stack")
		if err != nil {
			return err
		}
		for _, resource := range resources {
			if resource.PhysicalID == "assoc-original" && (resource.Current || resource.Status != "DELETE_COMPLETE") {
				t.Fatalf("rollback resurrected the deleted history row: %+v", resource)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteFirstRollbackRejectsRestorationResultReadFailure(t *testing.T) {
	s, r, h, op := lifecycleFixture(t, "REPLACE", "APPLY")
	for i := 0; i < 12 && op.Cursor == 0; i++ {
		op = lifecycleRun(t, s, r, op.ID)
	}
	if op.Cursor != 1 || !op.Steps[0].BeforeDeleted {
		t.Fatalf("replacement did not complete native deletion: %+v", op)
	}
	op.Phase, op.Cursor = "ROLLBACK", 0
	if err := r.Update(t.Context(), func(tx Transaction) error { return tx.PutOperation(op) }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12 && op.Steps[0].State != "RESTORE_STABILIZING"; i++ {
		op = lifecycleRun(t, s, r, op.ID)
	}
	if op.Steps[0].State != "RESTORE_STABILIZING" {
		t.Fatalf("rollback did not retain pending native restoration: %+v", op)
	}
	restoredID := op.Steps[0].Restore.PhysicalID
	h.resultError = &awswire.Error{Code: "AccessDenied", Message: "current caller lost restored-owner read authority"}
	for i := 0; i < 12 && op.Phase != "DONE"; i++ {
		op = lifecycleRun(t, s, r, op.ID)
	}
	if op.Phase != "DONE" || h.live[restoredID]["RouteTableId"] != "original" {
		t.Fatalf("result-read rejection lost the admitted restoration: %+v live=%v", op, h.live)
	}
	if err := r.View(t.Context(), func(reader Reader) error {
		stack, err := reader.Stack("stack")
		if err == nil && stack.Status != "UPDATE_ROLLBACK_FAILED" {
			t.Fatalf("unreadable restoration reported successful rollback: %+v", stack)
		}
		if err != nil {
			return err
		}
		resources, err := reader.Resources("stack")
		for _, resource := range resources {
			if resource.PhysicalID == restoredID && resource.Status == "UPDATE_COMPLETE" {
				t.Fatalf("unreadable restored owner was published as complete: %+v", resource)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

type lifecyclePlanner struct {
	*lifecycleOwner
	cancel      bool
	expectedARN string
}

func (h *lifecyclePlanner) ReplacementForResource(ctx context.Context, r ResourceRequest) (bool, error) {
	if err := h.command("PLAN", r); err != nil {
		return false, err
	}
	if r.PhysicalID != "assoc-original" || r.Token != "original-incarnation" || r.Previous["RouteTableId"] != "original" {
		h.t.Fatalf("planner did not receive resolved old owner state: %+v", r)
	}
	if awsctx.FromContext(ctx).PrincipalARN != h.expectedARN {
		h.t.Fatal("planner lost current caller or service-role authority")
	}
	if h.cancel {
		if err := h.repository.Update(ctx, func(tx Transaction) error {
			op, err := tx.Operation(r.OperationToken)
			if err != nil {
				return err
			}
			op.Cancel = true
			return tx.PutOperation(op)
		}); err != nil {
			return false, err
		}
	}
	return true, nil
}

type lifecycleExecutionRoles struct {
	t          *testing.T
	repository *lifecycleRepository
}

func (lifecycleExecutionRoles) Validate(context.Context, string, string) error { return nil }
func (r lifecycleExecutionRoles) Context(ctx context.Context, _ string, role string) (context.Context, error) {
	if r.repository.inside {
		r.t.Fatal("execution role was resolved inside a shared transaction")
	}
	caller := awsctx.FromContext(ctx)
	caller.PrincipalARN = role
	return awsctx.WithMetadata(ctx, caller), nil
}

func TestContextualReplacementPlanningPrecedesEqualitySkipAndFencesCancellation(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		for _, role := range []string{"", "arn:aws:iam::123456789012:role/service-role"} {
			t.Run(fmt.Sprint(cancel)+"/"+role, func(t *testing.T) {
				s, r, owner, initial := lifecycleFixture(t, "UPSERT", "APPLY")
				expected := "arn:aws:iam::123456789012:root"
				if role != "" {
					initial.RoleARN = role
					expected = role
					s.roles = lifecycleExecutionRoles{t: t, repository: r}
					if err := r.Update(t.Context(), func(tx Transaction) error { return tx.PutOperation(initial) }); err != nil {
						t.Fatal(err)
					}
				}
				planner := &lifecyclePlanner{lifecycleOwner: owner, cancel: cancel, expectedARN: expected}
				s.handlers[initial.Steps[0].After.Type] = planner
				op := lifecycleRun(t, s, r, initial.ID)
				if len(owner.calls) != 1 || owner.calls[0] != "PLAN" {
					t.Fatalf("planning performed a mutation or skipped native observation: %v", owner.calls)
				}
				if cancel {
					if op.Phase != "ROLLBACK" || op.Steps[0].State != "PLANNING" {
						t.Fatalf("cancelled native plan crossed its admission fence: %+v", op)
					}
				} else if op.Steps[0].Action != "REPLACE" || op.Steps[0].State != "PENDING" {
					t.Fatalf("equal desired/tag state bypassed contextual replacement: %+v", op)
				}
			})
		}
	}
}

func TestInterruptedDeleteFirstRollbackObservesExactNativeOwnerAndFailsClosed(t *testing.T) {
	for _, readError := range []error{nil, &awswire.Error{Code: "AccessDenied", Message: "current caller lost native read authority"}} {
		t.Run(fmt.Sprint(readError), func(t *testing.T) {
			s, r, h, op := lifecycleFixture(t, "REPLACE", "ROLLBACK")
			op.Steps[0].State = "BEFORE_DELETE_RUNNING"
			op.Steps[0].BeforeDeleteStarted = true
			// The actual deletion happened, but the BeforeDeleted commit was
			// lost. The previous intent still names the exact original ID.
			delete(h.live, "assoc-original")
			h.readError = readError
			if err := r.Update(t.Context(), func(tx Transaction) error { return tx.PutOperation(op) }); err != nil {
				t.Fatal(err)
			}
			op = lifecycleRun(t, s, r, op.ID)
			if len(h.requests) != 1 || h.requests[0].PhysicalID != "assoc-original" || h.calls[0] != "READ" {
				t.Fatalf("recovery did not inspect the exact old native identity: %+v", h.requests)
			}
			if readError != nil {
				if op.Phase != "DONE" || op.Steps[0].BeforeDeleted || len(h.live) != 0 {
					t.Fatalf("native read failure was converted into fake restoration: %+v live=%v", op, h.live)
				}
				if err := r.View(t.Context(), func(reader Reader) error {
					stack, err := reader.Stack("stack")
					if err == nil && stack.Status != "UPDATE_ROLLBACK_FAILED" {
						t.Fatalf("unobservable native owner reported successful rollback: %+v", stack)
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				return
			}
			if !op.Steps[0].BeforeDeleted || op.Steps[0].State != "UNDO_REPLACEMENT" {
				t.Fatalf("modeled native absence was not retained before restoration: %+v", op)
			}
			for i := 0; i < 12 && op.Phase != "DONE"; i++ {
				op = lifecycleRun(t, s, r, op.ID)
			}
			if op.Steps[0].Restore.PhysicalID == "" || h.live[op.Steps[0].Restore.PhysicalID]["RouteTableId"] != "original" {
				t.Fatalf("interrupted deletion did not restore actual old native properties: %+v live=%v", op, h.live)
			}
		})
	}
}

func TestDeleteFirstReplacementRejectsRetainedExclusiveOldIncarnation(t *testing.T) {
	s, r, h, op := lifecycleFixture(t, "UPSERT", "APPLY")
	op.Steps[0].Before.UpdateReplacePolicy = "Retain"
	op.Template = `{"Resources":{"Association":{"Type":"AWS::EC2::SubnetRouteTableAssociation","Properties":{"SubnetId":"subnet","RouteTableId":"desired"}}}}`
	if err := r.Update(t.Context(), func(tx Transaction) error { return tx.PutOperation(op) }); err != nil {
		t.Fatal(err)
	}
	op = lifecycleRun(t, s, r, op.ID)
	if op.Phase != "ROLLBACK" || len(h.calls) != 0 || len(h.live) != 1 {
		t.Fatalf("Retain silently destroyed or overwrote an exclusive old native association: %+v calls=%v live=%v", op, h.calls, h.live)
	}
}

func TestFailedDeleteFirstCreationRecoversExactAdmissionBeforeRestoringOldOwner(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		t.Run(fmt.Sprint(admitted), func(t *testing.T) {
			s, r, h, op := lifecycleFixture(t, "REPLACE", "APPLY")
			h.failCreate, h.admitBeforeFailure = true, admitted
			for i := 0; i < 12 && op.Phase != "ROLLBACK"; i++ {
				op = lifecycleRun(t, s, r, op.ID)
			}
			if op.Phase != "ROLLBACK" || op.Steps[0].State != "FAILED_CREATE_RECOVERING" || !op.Steps[0].BeforeDeleted {
				t.Fatalf("modeled creation failure discarded possible native admission: %+v", op)
			}
			for i := 0; i < 18 && op.Phase != "DONE"; i++ {
				op = lifecycleRun(t, s, r, op.ID)
			}
			restore := op.Steps[0].Restore
			if op.Phase != "DONE" || len(h.live) != 1 || h.live[restore.PhysicalID]["RouteTableId"] != "original" {
				t.Fatalf("failed desired creation prevented actual restoration: %+v live=%v", op, h.live)
			}
			recovered := false
			for i, request := range h.requests {
				if h.calls[i] == "RECOVER_CREATE" && request.Token == "replacement-incarnation" && request.PhysicalID == "" {
					recovered = true
				}
			}
			if !recovered {
				t.Fatal("rollback never observed the exact failed creation incarnation")
			}
			if admitted && (op.Steps[0].After.PhysicalID == "" || op.Steps[0].After.PhysicalID == restore.PhysicalID) {
				t.Fatalf("partially admitted desired owner was not recovered before replacement cleanup: %+v", op)
			}
			if err := r.View(t.Context(), func(reader Reader) error {
				stack, err := reader.Stack("stack")
				if err == nil && (stack.Status != "UPDATE_ROLLBACK_COMPLETE" || stack.Outputs["Association"].Value != restore.PhysicalID) {
					t.Fatalf("failed creation restoration reported stale native outputs: %+v", stack)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type lifecycleUpdateOwner struct {
	*lifecycleOwner
	updateValidated bool
}

func (h *lifecycleUpdateOwner) Validate(p Properties) error {
	if p["Code"] == nil {
		return fmt.Errorf("creation requires the write-only Code property")
	}
	return nil
}
func (h *lifecycleUpdateOwner) ValidateUpdate(previous, desired Properties) error {
	if previous["Code"] != "write-only-code" {
		return fmt.Errorf("update validator lost the old state")
	}
	h.updateValidated = true
	return nil
}
func (h *lifecycleUpdateOwner) Update(_ context.Context, r ResourceRequest) (ResourceResult, error) {
	if err := h.command("UPDATE", r); err != nil {
		return ResourceResult{}, err
	}
	code := h.live[r.PhysicalID]["Code"]
	h.live[r.PhysicalID] = maps.Clone(r.Properties)
	h.live[r.PhysicalID]["Code"] = code
	return ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}, nil
}

func TestUpdateValidationCanOmitWriteOnlyCreateRequirementButReplacementCannot(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			s, r, original, op := lifecycleFixture(t, "UPSERT", "APPLY")
			h := &lifecycleUpdateOwner{lifecycleOwner: original}
			s.handlers[op.Steps[0].After.Type] = h
			op.Steps[0].Before.Properties["Code"] = "write-only-code"
			h.live["assoc-original"]["Code"] = "write-only-code"
			if replace {
				op.Template = `{"Resources":{"Association":{"Type":"AWS::EC2::SubnetRouteTableAssociation","Properties":{"SubnetId":"subnet","RouteTableId":"desired"}}}}`
			}
			if err := r.Update(t.Context(), func(tx Transaction) error { return tx.PutOperation(op) }); err != nil {
				t.Fatal(err)
			}
			op = lifecycleRun(t, s, r, op.ID)
			if !h.updateValidated {
				t.Fatal("existing resource used creation validation for an update")
			}
			if replace {
				if op.Phase != "ROLLBACK" || len(h.calls) != 0 {
					t.Fatalf("replacement bypassed write-only create admission: %+v calls=%v", op, h.calls)
				}
			} else if op.Steps[0].Action != "UPDATE" || op.Steps[0].State != "STABILIZING" || h.live["assoc-original"]["Code"] != "write-only-code" {
				t.Fatalf("configuration-only update lost the actual write-only owner content: %+v live=%v", op, h.live)
			}
		})
	}
}

func TestCancellationDoesNotAdmitAPendingCreationForRollback(t *testing.T) {
	s, r, h, op := lifecycleFixture(t, "CREATE", "APPLY")
	h.pendingAction, h.pending = "CREATE", 1
	op = lifecycleRun(t, s, r, op.ID)
	if err := r.Update(t.Context(), func(tx Transaction) error { op.Cancel = true; return tx.PutOperation(op) }); err != nil {
		t.Fatal(err)
	}
	op = lifecycleRun(t, s, r, op.ID)
	if op.Phase != "ROLLBACK" || op.Steps[0].State != "ROLLED_BACK" || len(h.live) != 0 || len(h.calls) != 1 || h.calls[0] != "CREATE" {
		t.Fatalf("rollback created a native resource whose forward admission was explicitly pending: %+v calls=%v live=%v", op, h.calls, h.live)
	}
	if err := r.View(t.Context(), func(reader Reader) error {
		resources, err := reader.Resources(op.StackID)
		if err != nil {
			return err
		}
		for _, resource := range resources {
			if resource.Current || resource.Status == "DELETE_COMPLETE" {
				t.Fatalf("unadmitted cancellation fabricated a current resource or native deletion: %+v", resource)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCancellationWaitsForExactOldDeletionBeforeFreshRestoration(t *testing.T) {
	s, r, h, op := lifecycleFixture(t, "REPLACE", "APPLY")
	op = lifecycleRun(t, s, r, op.ID)
	if op.Steps[0].State != "BEFORE_DELETE_STABILIZING" || op.Steps[0].BeforeDeleted {
		t.Fatalf("old deletion was not retained before creation: %+v", op)
	}
	if err := r.Update(t.Context(), func(tx Transaction) error { op.Cancel = true; return tx.PutOperation(op) }); err != nil {
		t.Fatal(err)
	}
	op = lifecycleRun(t, s, r, op.ID)
	if op.Phase != "ROLLBACK" || op.Steps[0].BeforeDeleted || len(h.live) != 1 || h.live["assoc-original"] == nil {
		t.Fatalf("cancellation skipped admitted native deletion stabilization: %+v live=%v", op, h.live)
	}
	for i := 0; i < 14 && op.Phase != "DONE"; i++ {
		op = lifecycleRun(t, s, r, op.ID)
	}
	restore := op.Steps[0].Restore
	if op.Phase != "DONE" || !op.Steps[0].BeforeDeleted || restore.PhysicalID == "" || len(h.live) != 1 || h.live[restore.PhysicalID]["RouteTableId"] != "original" {
		t.Fatalf("cancellation did not recreate the deleted native owner: %+v live=%v", op, h.live)
	}
	for _, request := range h.requests {
		if request.Token == "replacement-incarnation" && request.PhysicalID != "" {
			t.Fatalf("cancelled delete-first replacement admitted the desired owner: %+v", request)
		}
	}
}

func TestCrashAfterReplacementCreationRecoversExactTokenBeforeNativeUndo(t *testing.T) {
	s, r, h, op := lifecycleFixture(t, "REPLACE", "ROLLBACK")
	step := &op.Steps[0]
	step.State, step.BeforeDeleteStarted, step.BeforeDeleted = "RUNNING", true, true
	h.live = map[string]Properties{"assoc-admitted-without-result": maps.Clone(step.After.Properties)}
	h.tokens[step.After.Token] = "assoc-admitted-without-result"
	if err := r.Update(t.Context(), func(tx Transaction) error {
		before := step.Before
		before.Current, before.Status = false, "DELETE_COMPLETE"
		if err := tx.PutResource(before); err != nil {
			return err
		}
		return tx.PutOperation(op)
	}); err != nil {
		t.Fatal(err)
	}
	op = lifecycleRun(t, s, r, op.ID)
	if op.Steps[0].State != "RECOVERED" || op.Steps[0].After.PhysicalID != "assoc-admitted-without-result" || h.calls[0] != "RECOVER_CREATE" {
		t.Fatalf("crashed native creation was not recovered by its exact retained token: %+v calls=%v", op, h.calls)
	}
	for i := 0; i < 14 && op.Phase != "DONE"; i++ {
		op = lifecycleRun(t, s, r, op.ID)
	}
	restore := op.Steps[0].Restore
	if op.Phase != "DONE" || len(h.live) != 1 || h.live[restore.PhysicalID]["RouteTableId"] != "original" {
		t.Fatalf("crashed replacement was not deleted before actual restoration: %+v live=%v", op, h.live)
	}
}
