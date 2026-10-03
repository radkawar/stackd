package stepfunctions

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	domain "stackd/internal/services/stepfunctions"
	"stackd/storage/sqlite/stepfunctions/internal/sqlcgen"
)

func executionRecord(row sqlcgen.StepfunctionsExecution) domain.ExecutionRecord {
	scope := domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}
	return domain.ExecutionRecord{
		Key: domain.ExecutionKey{Scope: scope, ARN: row.Arn}, Machine: domain.MachineKey{Scope: scope, Name: row.MachineName},
		MachineID: row.MachineID, RevisionID: row.RevisionID, Name: row.Name, Type: row.Type, VersionARN: row.VersionArn,
		AliasARN: row.AliasArn, MapRunARN: row.MapRunArn, ParentEventID: row.ParentEventID, TraceHeader: row.TraceHeader,
		TraceSegmentID: row.TraceSegmentID,
		MapItemCount:   row.MapItemCount,
		MapGeneration:  row.MapGeneration,
		Status:         row.Status, Input: row.Input, Output: row.Output, Error: row.Error, Cause: row.Cause, Started: row.Started,
		Stopped: timePointer(row.Stopped), Deadline: row.Deadline, Expires: timePointer(row.Expires), Version: row.Version,
		NextFrameID: row.NextFrameID, NextHistoryID: row.NextHistoryID,
		DeliveredHistoryID: row.DeliveredHistoryID,
		PeakMemoryBytes:    row.PeakMemoryBytes,
		RedriveCount:       row.RedriveCount, Redriven: timePointer(row.Redriven),
		Encrypted: encryptedPayload(row.EncryptedDataKey, row.EncryptedContent),
	}
}

func (r reader) Execution(k domain.ExecutionKey) (domain.ExecutionRecord, error) {
	row, err := r.q.GetExecution(r.ctx, sqlcgen.GetExecutionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN})
	if err != nil {
		return domain.ExecutionRecord{}, missing(err)
	}
	return executionRecord(row), nil
}

func (r reader) Executions(k domain.ExecutionSelection) ([]domain.ExecutionRecord, error) {
	rows, err := r.q.ListExecutions(r.ctx, sqlcgen.ListExecutionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MachineID: k.MachineID, VersionArn: k.VersionARN, AliasArn: k.AliasARN, MapRunArn: k.MapRunARN, Status: k.Status})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ExecutionRecord, len(rows))
	for i, row := range rows {
		out[i] = executionRecord(row)
	}
	return out, nil
}

func (r reader) OpenExecutionCount(k domain.Scope) (int64, error) {
	return r.q.CountOpenExecutions(r.ctx, sqlcgen.CountOpenExecutionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
}

func (w writer) PutExecution(v domain.ExecutionRecord) error {
	k := v.Key
	old, err := w.q.GetExecution(w.ctx, sqlcgen.GetExecutionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	hadOld := err == nil
	dataKey, content := encryptedColumns(v.Encrypted)
	if err := w.q.PutExecution(w.ctx, sqlcgen.PutExecutionParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN, MachineName: v.Machine.Name,
		MachineID: v.MachineID, RevisionID: v.RevisionID, Name: v.Name, Type: v.Type, VersionArn: v.VersionARN,
		AliasArn: v.AliasARN, MapRunArn: v.MapRunARN, ParentEventID: v.ParentEventID, TraceHeader: v.TraceHeader,
		TraceSegmentID: v.TraceSegmentID,
		MapItemCount:   v.MapItemCount,
		MapGeneration:  v.MapGeneration,
		Status:         v.Status, Input: v.Input, Output: v.Output, Error: v.Error, Cause: v.Cause, Started: v.Started.UTC(),
		Stopped: nullableTime(v.Stopped), Deadline: v.Deadline.UTC(), Expires: nullableTime(v.Expires), Version: v.Version,
		NextFrameID: v.NextFrameID, NextHistoryID: v.NextHistoryID,
		DeliveredHistoryID: v.DeliveredHistoryID,
		PeakMemoryBytes:    v.PeakMemoryBytes,
		RedriveCount:       v.RedriveCount, Redriven: nullableTime(v.Redriven),
		EncryptedDataKey: dataKey, EncryptedContent: content,
	}); err != nil {
		return err
	}
	if hadOld && old.RevisionID != v.RevisionID {
		return w.reclaim(k.Scope, old.RevisionID)
	}
	return nil
}

func (w writer) DeleteExecution(k domain.ExecutionKey) error {
	// Capture the ownership tree before cascading its frames and map runs. A child
	// execution's immutable revision stays pinned until every affected row is gone.
	rows, err := w.q.ListOwnedExecutions(w.ctx, sqlcgen.ListOwnedExecutionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return domain.ErrNotFound
	}
	for _, row := range rows {
		if err := deleted(w.q.DeleteExecution(w.ctx, sqlcgen.DeleteExecutionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: row.Arn})); err != nil {
			return err
		}
	}
	for _, row := range rows {
		if err := w.reclaim(k.Scope, row.RevisionID); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) RedriveRequests(k domain.ExecutionKey) ([]domain.RedriveRequest, error) {
	rows, err := r.q.ListRedriveRequests(r.ctx, sqlcgen.ListRedriveRequestsParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.RedriveRequest, len(rows))
	for i, row := range rows {
		out[i] = domain.RedriveRequest{Token: row.Token, Count: row.Count, Date: row.Date}
	}
	return out, nil
}

func (w writer) PutRedriveRequests(k domain.ExecutionKey, requests []domain.RedriveRequest) error {
	if err := w.q.DeleteRedriveRequests(w.ctx, sqlcgen.DeleteRedriveRequestsParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN,
	}); err != nil {
		return err
	}
	for _, request := range requests {
		if err := w.q.PutRedriveRequest(w.ctx, sqlcgen.PutRedriveRequestParams{
			Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN,
			Token: request.Token, Count: request.Count, Date: request.Date.UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}

func frameRecord(row sqlcgen.StepfunctionsFrame) domain.FrameRecord {
	return domain.FrameRecord{
		Key:      domain.FrameKey{Execution: domain.ExecutionKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ARN: row.ExecutionArn}, ID: row.ID},
		ParentID: row.ParentID, BranchIndex: row.BranchIndex, ScopePath: row.ScopePath, StateName: row.StateName,
		ParentStateID: row.ParentStateID, ParentAttempt: row.ParentAttempt,
		ChildGeneration:  row.ChildGeneration,
		StartedHistoryID: row.StartedHistoryID,
		Phase:            domain.FramePhase(row.Phase), Input: row.Input, Variables: row.Variables, Arguments: row.Arguments,
		Output: row.Output, Error: row.Error, Cause: row.Cause, Entered: row.Entered, EnteredHistoryID: row.EnteredHistoryID,
		PreviousHistoryID: row.PreviousHistoryID, TaskID: row.TaskID, RetryCounts: map[int]int64{}, RetryCount: row.RetryCount,
		NextItem: row.NextItem, ItemCount: row.ItemCount, MaxConcurrency: row.MaxConcurrency, MapRunARN: row.MapRunArn,
		Due: timePointer(row.Due), Version: row.Version,
		Encrypted: encryptedPayload(row.EncryptedDataKey, row.EncryptedContent),
	}
}

func (r reader) frame(row sqlcgen.StepfunctionsFrame) (domain.FrameRecord, error) {
	v := frameRecord(row)
	rows, err := r.q.ListFrameRetries(r.ctx, sqlcgen.ListFrameRetriesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ExecutionArn: row.ExecutionArn, FrameID: row.ID})
	if err != nil {
		return domain.FrameRecord{}, err
	}
	for _, retry := range rows {
		v.RetryCounts[int(retry.Retrier)] = retry.Count
	}
	return v, nil
}

func (r reader) Frame(k domain.FrameKey) (domain.FrameRecord, error) {
	e := k.Execution
	row, err := r.q.GetFrame(r.ctx, sqlcgen.GetFrameParams{Partition: e.Partition, AccountID: e.AccountID, Region: e.Region, ExecutionArn: e.ARN, ID: k.ID})
	if err != nil {
		return domain.FrameRecord{}, missing(err)
	}
	return r.frame(row)
}

func (r reader) Frames(k domain.ExecutionKey) ([]domain.FrameRecord, error) {
	rows, err := r.q.ListFrames(r.ctx, sqlcgen.ListFramesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN})
	if err != nil {
		return nil, err
	}
	out := make([]domain.FrameRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.frame(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (w writer) PutFrame(v domain.FrameRecord) error {
	k := v.Key.Execution
	dataKey, content := encryptedColumns(v.Encrypted)
	if err := w.q.PutFrame(w.ctx, sqlcgen.PutFrameParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN, ID: v.Key.ID,
		ParentID: v.ParentID, BranchIndex: v.BranchIndex, ScopePath: v.ScopePath, StateName: v.StateName,
		Phase: string(v.Phase), Input: v.Input, Variables: v.Variables, Arguments: v.Arguments, Output: v.Output,
		Error: v.Error, Cause: v.Cause, Entered: v.Entered.UTC(), EnteredHistoryID: v.EnteredHistoryID,
		ParentStateID: v.ParentStateID, ParentAttempt: v.ParentAttempt,
		ChildGeneration:   v.ChildGeneration,
		StartedHistoryID:  v.StartedHistoryID,
		PreviousHistoryID: v.PreviousHistoryID, TaskID: v.TaskID, RetryCount: v.RetryCount, NextItem: v.NextItem,
		ItemCount: v.ItemCount, MaxConcurrency: v.MaxConcurrency, MapRunArn: v.MapRunARN, Due: nullableTime(v.Due), Version: v.Version,
		EncryptedDataKey: dataKey, EncryptedContent: content,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteFrameRetries(w.ctx, sqlcgen.DeleteFrameRetriesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN, FrameID: v.Key.ID}); err != nil {
		return err
	}
	for retrier, count := range v.RetryCounts {
		if err := w.q.PutFrameRetry(w.ctx, sqlcgen.PutFrameRetryParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN, FrameID: v.Key.ID, Retrier: int64(retrier), Count: count}); err != nil {
			return err
		}
	}
	return nil
}

func taskRecord(row sqlcgen.StepfunctionsTask) domain.TaskRecord {
	scope := domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}
	return domain.TaskRecord{
		Key: domain.TaskKey{Scope: scope, ID: row.ID}, Frame: domain.FrameKey{Execution: domain.ExecutionKey{Scope: scope, ARN: row.ExecutionArn}, ID: row.FrameID},
		Attempt: row.Attempt, Token: row.Token, Kind: row.Kind, Resource: row.Resource, Parameters: row.Parameters,
		RoleARN: row.RoleArn, Activity: row.Activity, Status: domain.TaskStatus(row.Status), Scheduled: row.Scheduled,
		Started: timePointer(row.Started), TimeoutSeconds: row.TimeoutSeconds, HeartbeatSeconds: row.HeartbeatSeconds,
		Deadline: timePointer(row.Deadline), HeartbeatDeadline: timePointer(row.HeartbeatDeadline), WorkerName: row.WorkerName,
		Output: row.Output, Error: row.Error, Cause: row.Cause, HistoryID: row.HistoryID, Version: row.Version,
		Encrypted:      encryptedPayload(row.EncryptedDataKey, row.EncryptedContent),
		EncryptedInput: encryptedPayload(row.InputDataKey, row.InputContent),
	}
}

func (r reader) Task(k domain.TaskKey) (domain.TaskRecord, error) {
	row, err := r.q.GetTask(r.ctx, sqlcgen.GetTaskParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID})
	if err != nil {
		return domain.TaskRecord{}, missing(err)
	}
	return taskRecord(row), nil
}

func (r reader) TaskByToken(k domain.Scope, token string) (domain.TaskRecord, error) {
	row, err := r.q.GetTaskByToken(r.ctx, sqlcgen.GetTaskByTokenParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Token: token})
	if err != nil {
		return domain.TaskRecord{}, missing(err)
	}
	return taskRecord(row), nil
}

func (r reader) ActivityTasks(k domain.ActivityKey) ([]domain.TaskRecord, error) {
	rows, err := r.q.ListActivityTasks(r.ctx, sqlcgen.ListActivityTasksParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Activity: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.TaskRecord, len(rows))
	for i, row := range rows {
		out[i] = taskRecord(row)
	}
	return out, nil
}

func (r reader) RecoverableTasks() ([]domain.TaskRecord, error) {
	rows, err := r.q.ListRecoverableTasks(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.TaskRecord, len(rows))
	for i, row := range rows {
		out[i] = taskRecord(row)
	}
	return out, nil
}

func (w writer) PutTask(v domain.TaskRecord) error {
	k := v.Key
	dataKey, content := encryptedColumns(v.Encrypted)
	inputDataKey, inputContent := encryptedColumns(v.EncryptedInput)
	return w.q.PutTask(w.ctx, sqlcgen.PutTaskParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID, ExecutionArn: v.Frame.Execution.ARN, FrameID: v.Frame.ID,
		Attempt: v.Attempt, Token: v.Token, Kind: v.Kind, Resource: v.Resource, Parameters: v.Parameters,
		RoleArn: v.RoleARN, Activity: v.Activity, Status: string(v.Status), Scheduled: v.Scheduled.UTC(),
		Started: nullableTime(v.Started), TimeoutSeconds: v.TimeoutSeconds, HeartbeatSeconds: v.HeartbeatSeconds,
		Deadline: nullableTime(v.Deadline), HeartbeatDeadline: nullableTime(v.HeartbeatDeadline), WorkerName: v.WorkerName,
		Output: v.Output, Error: v.Error, Cause: v.Cause, HistoryID: v.HistoryID, Version: v.Version,
		EncryptedDataKey: dataKey, EncryptedContent: content,
		InputDataKey: inputDataKey, InputContent: inputContent,
	})
}

func (r reader) History(k domain.ExecutionKey) ([]domain.HistoryRecord, error) {
	rows, err := r.q.ListHistory(r.ctx, sqlcgen.ListHistoryParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN})
	if err != nil {
		return nil, err
	}
	out := make([]domain.HistoryRecord, len(rows))
	for i, row := range rows {
		out[i] = domain.HistoryRecord{Execution: k, FrameID: row.FrameID, StateID: row.StateID, RedriveCount: row.RedriveCount, Error: row.Error, Cause: row.Cause, Encrypted: encryptedPayload(row.EncryptedDataKey, row.EncryptedContent)}
		if err := json.Unmarshal([]byte(row.Event), &out[i].Event); err != nil {
			return nil, fmt.Errorf("decode Step Functions history: %w", err)
		}
	}
	return out, nil
}

func (r reader) HistoryEvent(k domain.ExecutionKey, id int64) (domain.HistoryRecord, error) {
	row, err := r.q.GetHistoryEvent(r.ctx, sqlcgen.GetHistoryEventParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN, EventID: id})
	if err != nil {
		return domain.HistoryRecord{}, missing(err)
	}
	v := domain.HistoryRecord{Execution: k, FrameID: row.FrameID, StateID: row.StateID, RedriveCount: row.RedriveCount, Error: row.Error, Cause: row.Cause, Encrypted: encryptedPayload(row.EncryptedDataKey, row.EncryptedContent)}
	if err := json.Unmarshal([]byte(row.Event), &v.Event); err != nil {
		return domain.HistoryRecord{}, fmt.Errorf("decode Step Functions history: %w", err)
	}
	return v, nil
}

func (w writer) AppendHistory(v domain.HistoryRecord) error {
	if v.Event.Id == nil {
		return errors.New("step functions history event has no ID")
	}
	document, err := json.Marshal(v.Event)
	if err != nil {
		return err
	}
	k := v.Execution
	dataKey, content := encryptedColumns(v.Encrypted)
	return w.q.AppendHistory(w.ctx, sqlcgen.AppendHistoryParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN,
		EventID: int64(*v.Event.Id), At: nullableTime(v.Event.Timestamp), Event: string(document),
		FrameID: v.FrameID, StateID: v.StateID, RedriveCount: v.RedriveCount, Error: v.Error, Cause: v.Cause,
		EncryptedDataKey: dataKey, EncryptedContent: content,
	})
}

func mapRunRecord(row sqlcgen.StepfunctionsMapRun) domain.MapRunRecord {
	scope := domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}
	return domain.MapRunRecord{
		Key: domain.MapRunKey{Scope: scope, ARN: row.Arn}, Frame: domain.FrameKey{Execution: domain.ExecutionKey{Scope: scope, ARN: row.ExecutionArn}, ID: row.FrameID},
		Label: row.Label, Status: row.Status, Started: row.Started, Stopped: timePointer(row.Stopped), MaxConcurrency: row.MaxConcurrency,
		ToleratedFailureCount: row.ToleratedFailureCount, ToleratedFailurePercentage: row.ToleratedFailurePercentage, TotalItems: row.TotalItems,
		ResultsWrittenItems: row.ResultsWrittenItems, ResultsWrittenExecutions: row.ResultsWrittenExecutions,
		RedriveCount: row.RedriveCount, Redriven: timePointer(row.Redriven),
	}
}

func (r reader) MapRun(k domain.MapRunKey) (domain.MapRunRecord, error) {
	row, err := r.q.GetMapRun(r.ctx, sqlcgen.GetMapRunParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN})
	if err != nil {
		return domain.MapRunRecord{}, missing(err)
	}
	return mapRunRecord(row), nil
}

func (r reader) MapRuns(k domain.ExecutionKey) ([]domain.MapRunRecord, error) {
	rows, err := r.q.ListMapRuns(r.ctx, sqlcgen.ListMapRunsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ExecutionArn: k.ARN})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MapRunRecord, len(rows))
	for i, row := range rows {
		out[i] = mapRunRecord(row)
	}
	return out, nil
}

func (w writer) PutMapRun(v domain.MapRunRecord) error {
	k := v.Key
	return w.q.PutMapRun(w.ctx, sqlcgen.PutMapRunParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN, ExecutionArn: v.Frame.Execution.ARN, FrameID: v.Frame.ID,
		Label: v.Label, Status: v.Status, Started: v.Started.UTC(), Stopped: nullableTime(v.Stopped), MaxConcurrency: v.MaxConcurrency,
		ToleratedFailureCount: v.ToleratedFailureCount, ToleratedFailurePercentage: v.ToleratedFailurePercentage, TotalItems: v.TotalItems,
		ResultsWrittenItems: v.ResultsWrittenItems, ResultsWrittenExecutions: v.ResultsWrittenExecutions,
		RedriveCount: v.RedriveCount, Redriven: nullableTime(v.Redriven),
	})
}

func (r reader) MapResultFiles(k domain.MapRunKey) ([]domain.MapResultFile, error) {
	rows, err := r.q.ListMapResultFiles(r.ctx, sqlcgen.ListMapResultFilesParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MapRunArn: k.ARN,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MapResultFile, len(rows))
	for i, row := range rows {
		out[i] = domain.MapResultFile{
			Generation: row.Generation, Status: row.Status, Index: row.FileIndex, Key: row.Key, Size: row.Size,
			FirstExecution: row.FirstExecution, LastExecution: row.LastExecution,
		}
	}
	return out, nil
}

func (w writer) PutMapResultFile(k domain.MapRunKey, v domain.MapResultFile) error {
	return w.q.PutMapResultFile(w.ctx, sqlcgen.PutMapResultFileParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, MapRunArn: k.ARN,
		Generation: v.Generation, Status: v.Status, FileIndex: v.Index, Key: v.Key, Size: v.Size,
		FirstExecution: v.FirstExecution, LastExecution: v.LastExecution,
	})
}
