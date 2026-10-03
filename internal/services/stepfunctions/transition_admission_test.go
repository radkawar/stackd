package stepfunctions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"stackd/internal/services/cloudwatch"
	"stackd/storage/memory"
)

type transitionAdmissionHarness struct {
	s       *Service
	clock   *clock.Manual
	metrics *cloudwatch.MemoryRepository
	jobs    *scheduler.Driver
}

func newTransitionAdmissionHarness(t *testing.T) transitionAdmissionHarness {
	t.Helper()
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
	domain := memory.NewDomain()
	metrics := cloudwatch.NewMemoryRepository(domain)
	publisher := cloudwatch.New(cloudwatch.Config{Repository: metrics, Clock: source})
	s := New(Config{Repository: NewMemoryRepository(domain), Clock: source, Metrics: publisher})
	// Own explicit draining so automatic Wake cannot race quota setup or
	// consume the bounded job budget before the test observes it.
	s.jobs.Close()
	jobs := scheduler.New(source, workflowJobs{s})
	t.Cleanup(func() { jobs.Close(); _ = s.Close(); _ = publisher.Close() })
	if _, err := jobs.RunDue(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	return transitionAdmissionHarness{s, source, metrics, jobs}
}

func (h transitionAdmissionHarness) start(t *testing.T, scope Scope, name, typ, definition string) ExecutionKey {
	t.Helper()
	machine := MachineRecord{Key: MachineKey{Scope: scope, Name: name}, ID: name, RevisionID: name, Type: typ, Status: "ACTIVE", Created: h.clock.Now(), Version: 1}
	revision := RevisionRecord{Key: RevisionKey{Scope: scope, ID: name}, Machine: machine.Key, MachineID: name, Definition: definition, RoleARN: "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":role/workflow"}
	if err := h.s.repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutRevision(revision); err != nil {
			return err
		}
		return tx.PutMachine(machine)
	}); err != nil {
		t.Fatal(err)
	}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID})
	out, err := h.s.StartExecution(ctx, &api.StartExecutionInput{StateMachineArn: new(api.Arn(machine.Key.ARN())), Name: new(api.Name(name)), Input: new(api.SensitiveData(`{"retained":true}`))})
	if err != nil {
		t.Fatal(err)
	}
	return ExecutionKey{Scope: scope, ARN: string(*out.ExecutionArn)}
}

func (h transitionAdmissionHarness) exhaust(t *testing.T, scope Scope) time.Duration {
	t.Helper()
	quota, ok := workflowQuotaFor("StateTransition", scope.Region)
	if !ok {
		t.Fatal("missing state transition quota")
	}
	for range int(quota.capacity) {
		if delay := h.s.admission.admit(scope, "StateTransition", h.clock.Now(), quota); delay > 0 {
			t.Fatal("transition bucket exhausted before setup consumed its capacity")
		}
	}
	// Do not make an extra denied attempt: denial itself now assigns a retry
	// time, and setup must leave all deferred work to the actual scheduler.
	return time.Duration(math.Ceil(float64(time.Second) / quota.refill))
}

func (h transitionAdmissionHarness) drain(t *testing.T, limit int) {
	t.Helper()
	result, err := h.jobs.RunDue(t.Context(), limit)
	if err != nil || result.More {
		t.Fatalf("workflow drain: %+v, %v", result, err)
	}
}

func (h transitionAdmissionHarness) advance(t *testing.T, duration time.Duration) {
	t.Helper()
	if err := h.clock.Advance(duration); err != nil {
		t.Fatal(err)
	}
}

func (h transitionAdmissionHarness) execution(t *testing.T, key ExecutionKey) (ExecutionRecord, []HistoryRecord) {
	t.Helper()
	var execution ExecutionRecord
	var history []HistoryRecord
	if err := h.s.repository.View(t.Context(), func(r Reader) error {
		var err error
		execution, err = r.Execution(key)
		if err != nil {
			return err
		}
		history, err = r.History(key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return execution, history
}

func (h transitionAdmissionHarness) throttleCounts(t *testing.T, scope Scope) map[string]float64 {
	t.Helper()
	counts := map[string]float64{}
	if err := h.metrics.View(t.Context(), func(r cloudwatch.Reader) error {
		metrics, err := r.Metrics(cloudwatch.MetricQuery{Scope: cloudwatch.Scope(scope), Namespace: "AWS/States", Name: "ExecutionThrottled", Limit: 100})
		if err != nil {
			return err
		}
		for _, metric := range metrics {
			machine := ""
			for _, dimension := range metric.Dimensions {
				if dimension.Name == "StateMachineArn" {
					machine = dimension.Value
				}
			}
			if err := r.Points(cloudwatch.PointQuery{MetricID: metric.ID, Start: h.clock.Now().Add(-time.Hour).Unix(), End: h.clock.Now().Add(time.Hour).Unix()}, func(point cloudwatch.Point) error {
				counts[machine] += point.Sum
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return counts
}

func TestTransitionAdmissionWaitsAndIsolatesScopes(t *testing.T) {
	h := newTransitionAdmissionHarness(t)
	scope := Scope{Partition: "aws", AccountID: "111111111111", Region: "eu-north-1"}
	started := h.clock.Now()
	delay := h.exhaust(t, scope)
	definition := `{"StartAt":"Done","States":{"Done":{"Type":"Pass","End":true}}}`
	waiting := h.start(t, scope, "waiting", "STANDARD", definition)
	express := h.start(t, scope, "express", "EXPRESS", definition)
	otherAccount := scope
	otherAccount.AccountID = "222222222222"
	otherRegion := scope
	otherRegion.Region = "ap-south-1"
	isolated := []ExecutionKey{express, h.start(t, otherAccount, "account", "STANDARD", definition), h.start(t, otherRegion, "region", "STANDARD", definition)}
	h.drain(t, 20)
	active, history := h.execution(t, waiting)
	if active.Status != "RUNNING" || len(history) != 1 || value(history[0].Event.Type) != "ExecutionStarted" {
		t.Fatalf("throttling invented execution history or failed the execution: %+v, %+v", active, history)
	}
	for _, key := range isolated {
		execution, _ := h.execution(t, key)
		if execution.Status != "SUCCEEDED" || execution.Output != `{"retained":true}` {
			t.Fatalf("scope or Express inherited another workflow's quota: %+v", execution)
		}
	}
	counts := h.throttleCounts(t, scope)
	if counts[""] != 1 || counts[active.Machine.ARN()] != 1 || len(counts) != 2 {
		t.Fatal("throttle metric lost account/machine identity", counts)
	}
	if len(h.throttleCounts(t, otherAccount)) != 0 || len(h.throttleCounts(t, otherRegion)) != 0 {
		t.Fatal("throttle metric crossed account or Region")
	}
	h.advance(t, time.Second)
	h.drain(t, 20)
	completed, history := h.execution(t, waiting)
	admitted := started.Add(delay)
	if completed.Status != "SUCCEEDED" || completed.Stopped == nil || !completed.Stopped.Equal(admitted) || completed.Output != `{"retained":true}` {
		t.Fatalf("refilled workflow did not complete at scheduled service time: %+v", completed)
	}
	if len(history) != 4 || value(history[1].Event.Type) != "PassStateEntered" || !history[1].Event.Timestamp.Equal(admitted) {
		t.Fatalf("deferred state entry did not retain its scheduled timestamp: %+v", history)
	}
}

func TestTransitionAdmissionWaitCompletionAndRetry(t *testing.T) {
	scope := Scope{Partition: "aws", AccountID: "111111111111", Region: "eu-north-1"}
	t.Run("Wait completion does not consume a transition", func(t *testing.T) {
		h := newTransitionAdmissionHarness(t)
		key := h.start(t, scope, "wait", "STANDARD", `{"StartAt":"Wait","States":{"Wait":{"Type":"Wait","Seconds":1,"End":true}}}`)
		h.drain(t, 10)
		h.advance(t, time.Second)
		h.exhaust(t, scope)
		h.drain(t, 10)
		execution, _ := h.execution(t, key)
		if execution.Status != "SUCCEEDED" || len(h.throttleCounts(t, scope)) != 0 {
			t.Fatalf("Wait completion was treated as another entry: %+v", execution)
		}
	})
	t.Run("Retry consumes a transition without another StateEntered", func(t *testing.T) {
		h := newTransitionAdmissionHarness(t)
		key := h.start(t, scope, "retry", "STANDARD", `{"StartAt":"Parallel","States":{"Parallel":{"Type":"Parallel","Branches":[{"StartAt":"Fail","States":{"Fail":{"Type":"Fail","Error":"Expected"}}}],"Retry":[{"ErrorEquals":["Expected"],"IntervalSeconds":1,"MaxAttempts":1}],"End":true}}}`)
		h.drain(t, 20)
		_, before := h.execution(t, key)
		h.advance(t, time.Second)
		h.exhaust(t, scope)
		h.drain(t, 20)
		execution, history := h.execution(t, key)
		if execution.Status != "RUNNING" || len(history) != len(before) || h.throttleCounts(t, scope)[""] != 1 {
			t.Fatalf("retry was not deferred cleanly: %+v, history %d -> %d", execution, len(before), len(history))
		}
		h.advance(t, time.Second)
		h.drain(t, 30)
		execution, history = h.execution(t, key)
		entered, attempts := 0, 0
		for _, record := range history {
			switch value(record.Event.Type) {
			case "ParallelStateEntered":
				entered++
			case "ParallelStateStarted":
				attempts++
			}
		}
		if execution.Status != "FAILED" || execution.Error != "Expected" || entered != 1 || attempts != 2 {
			t.Fatalf("resumed retry changed attempts or entry history: %+v, entries=%d attempts=%d", execution, entered, attempts)
		}
	})
}

func TestTransitionAdmissionKeepsExecutionDeadline(t *testing.T) {
	h := newTransitionAdmissionHarness(t)
	scope := Scope{Partition: "aws", AccountID: "111111111111", Region: "eu-north-1"}
	key := h.start(t, scope, "deadline", "STANDARD", `{"TimeoutSeconds":1,"StartAt":"Loop","States":{"Loop":{"Type":"Pass","Next":"Again"},"Again":{"Type":"Choice","Choices":[{"Variable":"$.retained","BooleanEquals":true,"Next":"Loop"}],"Default":"Done"},"Done":{"Type":"Succeed"}}}`)
	h.exhaust(t, scope)
	h.drain(t, 10)
	h.advance(t, time.Second)
	h.drain(t, 5000)
	execution, history := h.execution(t, key)
	if execution.Status != "TIMED_OUT" || execution.Stopped == nil || !execution.Stopped.Equal(execution.Started.Add(time.Second)) || value(history[len(history)-1].Event.Type) != "ExecutionTimedOut" {
		t.Fatalf("transition deferral displaced the execution deadline: %+v", execution)
	}
	for _, record := range history {
		if value(record.Event.Type) == "PassStateEntered" && !record.Event.Timestamp.Before(execution.Deadline) {
			t.Fatal("entry won a tie against the execution timeout", record.Event)
		}
	}
}

type failTransitionCommit struct {
	Repository
	err error
}

func (r failTransitionCommit) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.Repository.Update(ctx, func(tx Transaction) error {
		if err := fn(tx); err != nil {
			return err
		}
		return r.err
	})
}

func TestTransitionAdmissionMetricRollsBackWithDeferral(t *testing.T) {
	h := newTransitionAdmissionHarness(t)
	scope := Scope{Partition: "aws", AccountID: "111111111111", Region: "eu-north-1"}
	key := h.start(t, scope, "rollback", "STANDARD", `{"StartAt":"Done","States":{"Done":{"Type":"Pass","End":true}}}`)
	h.exhaust(t, scope)
	source := workflowJobs{h.s}
	selected, found, err := source.Next(t.Context())
	if err != nil || !found {
		t.Fatal("missing entry", selected, found, err)
	}
	repository := h.s.repository
	rejected := errors.New("injected commit failure")
	h.s.repository = failTransitionCommit{repository, rejected}
	if err := source.Run(t.Context(), selected); !errors.Is(err, rejected) {
		t.Fatal("expected transaction failure", err)
	}
	h.s.repository = repository
	next, found, err := source.Next(t.Context())
	if err != nil || !found || next != selected || len(h.throttleCounts(t, scope)) != 0 {
		t.Fatal("failed transition retained reschedule or metric", selected, next, found, err)
	}
	h.drain(t, 10)
	execution, history := h.execution(t, key)
	if execution.Status != "RUNNING" || len(history) != 1 || h.throttleCounts(t, scope)[""] != 1 {
		t.Fatalf("committed retry did not retain exactly one throttle: %+v, %+v", execution, history)
	}
}

func TestTransitionAdmissionBoundsConcurrentBranchRetries(t *testing.T) {
	h := newTransitionAdmissionHarness(t)
	scope := Scope{Partition: "aws", AccountID: "111111111111", Region: "eu-north-1"}
	const branchCount = 32
	branches := make([]string, branchCount)
	for i := range branches {
		branches[i] = fmt.Sprintf(`{"StartAt":"Done%d","States":{"Done%d":{"Type":"Pass","End":true}}}`, i, i)
	}
	definition := `{"StartAt":"Fanout","States":{"Fanout":{"Type":"Parallel","Branches":[` + strings.Join(branches, ",") + `],"End":true}}}`
	key := h.start(t, scope, "fanout", "STANDARD", definition)
	h.exhaust(t, scope)
	h.drain(t, 10)
	h.advance(t, time.Second)
	// Each branch needs entry and parent-join work plus one initial denial,
	// not another denial for every other branch's single-token refill.
	result, err := h.jobs.RunDue(t.Context(), 4*branchCount)
	if err != nil || result.More {
		t.Fatalf("concurrent transitions exceeded a linear drain budget: %+v, %v", result, err)
	}
	execution, _ := h.execution(t, key)
	var output []struct {
		Retained bool `json:"retained"`
	}
	if err := json.Unmarshal([]byte(execution.Output), &output); err != nil {
		t.Fatal("concurrent execution did not produce its branch results", execution.Status, err)
	}
	if execution.Status != "SUCCEEDED" || len(output) != branchCount {
		t.Fatalf("bounded retries lost concurrent branches: %+v, output=%+v", execution, output)
	}
	for i, branch := range output {
		if !branch.Retained {
			t.Fatal("branch input was lost", i)
		}
	}
	if throttled := h.throttleCounts(t, scope)[""]; throttled != branchCount+1 {
		t.Fatal("an isolated burst repeatedly retried denied branches", throttled)
	}
}
