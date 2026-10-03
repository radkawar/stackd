package stepfunctions

import (
	"cmp"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/stepfunctions"
)

func mapRunKeyFor(r Reader, raw string) (MapRunKey, error) {
	parts := strings.SplitN(raw, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "states" || parts[3] == "" || !accountPattern.MatchString(parts[4]) {
		return MapRunKey{}, failure("InvalidArn", "Invalid Arn: '"+raw+"'", 400)
	}
	resource := strings.Split(parts[5], ":")
	if len(resource) != 3 || resource[0] != "mapRun" || !validResourceName(resource[2]) {
		return MapRunKey{}, failure("InvalidArn", "Invalid Arn: '"+raw+"'", 400)
	}
	machine := strings.Split(resource[1], "/")
	if len(machine) != 2 || !validResourceName(machine[0]) || !validResourceName(machine[1]) {
		return MapRunKey{}, failure("InvalidArn", "Invalid Arn: '"+raw+"'", 400)
	}
	key := MapRunKey{Scope: Scope{Partition: parts[1], Region: parts[3], AccountID: parts[4]}, ARN: raw}
	if key.Scope != scopeFor(r.Context()) {
		return key, resourceMissing(raw)
	}
	return key, nil
}

func (s *Service) mapRunFor(r Reader, raw, action string) (MapRunRecord, ExecutionRecord, error) {
	key, keyErr := mapRunKeyFor(r, raw)
	if key.ARN == "" {
		return MapRunRecord{}, ExecutionRecord{}, keyErr
	}
	var run MapRunRecord
	var execution ExecutionRecord
	var machine MachineRecord
	err := keyErr
	if err == nil {
		run, err = r.MapRun(key)
		if errors.Is(err, ErrNotFound) {
			err = resourceMissing(raw)
		}
		if err == nil {
			execution, machine, err = s.retainedExecution(r, run.Frame.Execution)
			if rejected := wireError(err); rejected != nil && rejected.Code == "ExecutionDoesNotExist" {
				err = resourceMissing(raw)
			}
		}
	}
	if denied := s.authorize(r, action, raw, machine.Tags, nil); denied != nil {
		return MapRunRecord{}, ExecutionRecord{}, denied
	}
	return run, execution, err
}

func (s *Service) listMapRuns(tx Transaction, in *api.ListMapRunsInput) (*api.ListMapRunsOutput, error) {
	execution, err := s.publicExecutionFor(tx, value(in.ExecutionArn), "ListMapRuns")
	if err != nil {
		return nil, err
	}
	filters, _ := json.Marshal([]any{execution.Key.ARN, in.MaxResults})
	collection := controlCollection(tx, "ListMapRuns", string(filters), executionIncarnation(execution))
	now := s.clock.Now()
	limit, after, err := controlPage(in.NextToken, in.MaxResults, collection, now)
	if err != nil {
		return nil, err
	}
	rows, err := tx.MapRuns(execution.Key)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rows, func(a, b MapRunRecord) int {
		if order := b.Started.Compare(a.Started); order != 0 {
			return order
		}
		return cmp.Compare(a.Key.ARN, b.Key.ARN)
	})
	out := &api.ListMapRunsOutput{MapRuns: api.MapRunList{}}
	for _, run := range rows {
		position := queryPosition(run.Started, run.Key.ARN)
		if position <= after {
			continue
		}
		if len(out.MapRuns) == limit {
			out.NextToken = controlNext(collection, after, now)
			break
		}
		item := api.MapRunListItem{ExecutionArn: new(api.Arn(execution.Key.ARN)), MapRunArn: new(api.LongArn(run.Key.ARN)), StateMachineArn: new(api.Arn(mapRunMachineARN(run.Key.ARN))), StartDate: controlTimestamp(run.Started)}
		if run.Stopped != nil {
			item.StopDate = controlTimestamp(*run.Stopped)
		}
		out.MapRuns = append(out.MapRuns, item)
		after = position
	}
	return out, nil
}

// A retained Map Run ARN names its synthetic processor state machine before
// the final run identifier: ...:mapRun:machine/label:run-id.
func mapRunMachineARN(raw string) string {
	return strings.Replace(raw[:strings.LastIndexByte(raw, ':')], ":mapRun:", ":stateMachine:", 1)
}

func (s *Service) describeMapRun(tx Transaction, in *api.DescribeMapRunInput) (*api.DescribeMapRunOutput, error) {
	run, parent, err := s.mapRunFor(tx, value(in.MapRunArn), "DescribeMapRun")
	if err != nil {
		return nil, err
	}
	children, err := tx.Executions(ExecutionSelection{Scope: run.Key.Scope, MapRunARN: run.Key.ARN})
	if err != nil {
		return nil, err
	}
	items := mapRunCounts{total: run.TotalItems, pending: run.TotalItems, written: run.ResultsWrittenItems}
	executions := mapRunCounts{total: int64(len(children)), written: run.ResultsWrittenExecutions}
	now := s.clock.Now()
	remaining := run.TotalItems
	for _, child := range children {
		// MapItemCount records the original item membership of an admitted
		// batch, independently of its transformed input or final output.
		if child.MapItemCount <= 0 || child.MapItemCount > remaining {
			return nil, internalFailure()
		}
		remaining -= child.MapItemCount
		items.pending -= child.MapItemCount
		redriveStatus, _ := executionRedrive(child, now)
		if !items.add(child.Status, child.MapItemCount, redriveStatus == "NOT_REDRIVABLE") || !executions.add(child.Status, 1, redriveStatus == "NOT_REDRIVABLE") {
			return nil, internalFailure()
		}
	}
	if items.pending < 0 || items.written < 0 || items.written > items.total || executions.written < 0 || executions.written > executions.total {
		return nil, internalFailure()
	}
	out := &api.DescribeMapRunOutput{
		MapRunArn: new(api.LongArn(run.Key.ARN)), ExecutionArn: new(api.Arn(parent.Key.ARN)),
		StartDate: controlTimestamp(run.Started), Status: new(api.MapRunStatus(run.Status)),
		MaxConcurrency: new(api.MaxConcurrency(run.MaxConcurrency)), RedriveCount: new(api.RedriveCount(run.RedriveCount)),
		ToleratedFailureCount: new(api.ToleratedFailureCount(run.ToleratedFailureCount)), ToleratedFailurePercentage: new(api.ToleratedFailurePercentage(run.ToleratedFailurePercentage)),
		ExecutionCounts: &api.MapRunExecutionCounts{
			Aborted: new(api.UnsignedLong(executions.aborted)), Failed: new(api.UnsignedLong(executions.failed)), Pending: new(api.UnsignedLong(executions.pending)),
			Running: new(api.UnsignedLong(executions.running)), Succeeded: new(api.UnsignedLong(executions.succeeded)), TimedOut: new(api.UnsignedLong(executions.timedOut)),
			Total: new(api.UnsignedLong(executions.total)), ResultsWritten: new(api.UnsignedLong(executions.written)),
			PendingRedrive: new(api.LongObject(executions.pendingRedrive)), FailuresNotRedrivable: new(api.LongObject(executions.notRedrivable)),
		},
		ItemCounts: &api.MapRunItemCounts{
			Aborted: new(api.UnsignedLong(items.aborted)), Failed: new(api.UnsignedLong(items.failed)), Pending: new(api.UnsignedLong(items.pending)),
			Running: new(api.UnsignedLong(items.running)), Succeeded: new(api.UnsignedLong(items.succeeded)), TimedOut: new(api.UnsignedLong(items.timedOut)),
			Total: new(api.UnsignedLong(items.total)), ResultsWritten: new(api.UnsignedLong(items.written)),
			PendingRedrive: new(api.LongObject(items.pendingRedrive)), FailuresNotRedrivable: new(api.LongObject(items.notRedrivable)),
		},
	}
	if run.Stopped != nil {
		out.StopDate = controlTimestamp(*run.Stopped)
	}
	if run.Redriven != nil {
		out.RedriveDate = controlTimestamp(*run.Redriven)
	}
	return out, nil
}

type mapRunCounts struct {
	total, pending, running, succeeded, failed, timedOut, aborted int64
	written, pendingRedrive, notRedrivable                        int64
}

func (counts *mapRunCounts) add(status string, size int64, notRedrivable bool) bool {
	switch status {
	case "PENDING":
		counts.pending += size
	case "RUNNING":
		counts.running += size
	case "SUCCEEDED":
		counts.succeeded += size
	case "FAILED":
		counts.failed += size
	case "TIMED_OUT":
		counts.timedOut += size
	case "ABORTED":
		counts.aborted += size
	case "PENDING_REDRIVE":
		counts.pendingRedrive += size
	default:
		return false
	}
	if notRedrivable && (status == "FAILED" || status == "TIMED_OUT" || status == "ABORTED") {
		counts.notRedrivable += size
	}
	return true
}
