package stepfunctions

import (
	"cmp"
	"fmt"
	"maps"
	"slices"

	api "stackd/internal/awsapi/stepfunctions"
)

func cloneExecution(v ExecutionRecord) ExecutionRecord {
	v.Encrypted = cloneEncryptedPayload(v.Encrypted)
	if v.Stopped != nil {
		v.Stopped = new(*v.Stopped)
	}
	if v.Expires != nil {
		v.Expires = new(*v.Expires)
	}
	if v.Redriven != nil {
		v.Redriven = new(*v.Redriven)
	}
	return v
}

func cloneFrame(v FrameRecord) FrameRecord {
	v.Encrypted = cloneEncryptedPayload(v.Encrypted)
	v.RetryCounts = maps.Clone(v.RetryCounts)
	if v.Due != nil {
		v.Due = new(*v.Due)
	}
	return v
}

func cloneTask(v TaskRecord) TaskRecord {
	v.Encrypted = cloneEncryptedPayload(v.Encrypted)
	v.EncryptedInput = cloneEncryptedPayload(v.EncryptedInput)
	if v.Started != nil {
		v.Started = new(*v.Started)
	}
	if v.Deadline != nil {
		v.Deadline = new(*v.Deadline)
	}
	if v.HeartbeatDeadline != nil {
		v.HeartbeatDeadline = new(*v.HeartbeatDeadline)
	}
	return v
}

func cloneMapRun(v MapRunRecord) MapRunRecord {
	if v.Stopped != nil {
		v.Stopped = new(*v.Stopped)
	}
	if v.Redriven != nil {
		v.Redriven = new(*v.Redriven)
	}
	return v
}

func (r memoryReader) Execution(key ExecutionKey) (ExecutionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ExecutionRecord{}, err
	}
	row, ok := r.s.executions[key]
	if !ok {
		return ExecutionRecord{}, ErrNotFound
	}
	return cloneExecution(row), nil
}

func (r memoryReader) Executions(selection ExecutionSelection) ([]ExecutionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]ExecutionRecord, 0)
	for key, row := range r.s.executions {
		if key.Scope != selection.Scope ||
			(selection.MachineID != "" && row.MachineID != selection.MachineID) ||
			(selection.VersionARN != "" && row.VersionARN != selection.VersionARN) ||
			(selection.AliasARN != "" && row.AliasARN != selection.AliasARN) ||
			(selection.MapRunARN != "" && row.MapRunARN != selection.MapRunARN) ||
			(selection.Status != "" && row.Status != selection.Status) {
			continue
		}
		rows = append(rows, cloneExecution(row))
	}
	slices.SortFunc(rows, func(a, b ExecutionRecord) int {
		if order := b.Started.Compare(a.Started); order != 0 {
			return order
		}
		return cmp.Compare(a.Key.ARN, b.Key.ARN)
	})
	return rows, nil
}

func (r memoryReader) OpenExecutionCount(scope Scope) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	var count int64
	for key := range r.s.executions {
		if key.Scope == scope && r.s.executions[key].Type == "STANDARD" && r.s.executions[key].Status == "RUNNING" {
			count++
		}
	}
	return count, nil
}

func (w memoryWriter) PutExecution(row ExecutionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	previous, existed := w.s.executions[row.Key]
	w.s.executions[row.Key] = cloneExecution(row)
	if existed && previous.RevisionID != row.RevisionID {
		w.reclaimRevision(RevisionKey{Scope: row.Key.Scope, ID: previous.RevisionID})
	}
	return nil
}

func (r memoryReader) RedriveRequests(key ExecutionKey) ([]RedriveRequest, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	return slices.Clone(r.s.redrives[key]), nil
}

func (w memoryWriter) PutRedriveRequests(key ExecutionKey, requests []RedriveRequest) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.redrives[key] = slices.Clone(requests)
	return nil
}

func (w memoryWriter) DeleteExecution(key ExecutionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	row, ok := w.s.executions[key]
	if !ok {
		return ErrNotFound
	}
	delete(w.s.executions, key)
	delete(w.s.redrives, key)
	for frameKey := range w.s.frames {
		if frameKey.Execution == key {
			delete(w.s.frames, frameKey)
		}
	}
	for taskKey, task := range w.s.tasks {
		if task.Frame.Execution == key {
			if task.Token != "" {
				delete(w.s.tokens, memoryTokenKey{Scope: taskKey.Scope, Token: task.Token})
			}
			delete(w.s.tasks, taskKey)
		}
	}
	for historyKey := range w.s.history {
		if historyKey.Execution == key {
			delete(w.s.history, historyKey)
		}
	}
	for mapRunKey, mapRun := range w.s.mapRuns {
		if mapRun.Frame.Execution == key {
			delete(w.s.mapRuns, mapRunKey)
			delete(w.s.mapFiles, mapRunKey)
			for childKey, child := range w.s.executions {
				if childKey.Scope == mapRunKey.Scope && child.MapRunARN == mapRunKey.ARN {
					if err := w.DeleteExecution(childKey); err != nil {
						return err
					}
				}
			}
		}
	}
	w.reclaimRevision(RevisionKey{Scope: key.Scope, ID: row.RevisionID})
	return nil
}

func (r memoryReader) Frame(key FrameKey) (FrameRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return FrameRecord{}, err
	}
	row, ok := r.s.frames[key]
	if !ok {
		return FrameRecord{}, ErrNotFound
	}
	return cloneFrame(row), nil
}

func (r memoryReader) Frames(execution ExecutionKey) ([]FrameRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]FrameRecord, 0)
	for key, row := range r.s.frames {
		if key.Execution == execution {
			rows = append(rows, cloneFrame(row))
		}
	}
	slices.SortFunc(rows, func(a, b FrameRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}

func (w memoryWriter) PutFrame(row FrameRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.frames[row.Key] = cloneFrame(row)
	return nil
}

func (r memoryReader) Task(key TaskKey) (TaskRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TaskRecord{}, err
	}
	row, ok := r.s.tasks[key]
	if !ok {
		return TaskRecord{}, ErrNotFound
	}
	return cloneTask(row), nil
}

func (r memoryReader) TaskByToken(scope Scope, token string) (TaskRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TaskRecord{}, err
	}
	if token == "" {
		return TaskRecord{}, ErrNotFound
	}
	key, ok := r.s.tokens[memoryTokenKey{Scope: scope, Token: token}]
	if !ok {
		return TaskRecord{}, ErrNotFound
	}
	return cloneTask(r.s.tasks[key]), nil
}

func (r memoryReader) ActivityTasks(activity ActivityKey) ([]TaskRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]TaskRecord, 0)
	for key, row := range r.s.tasks {
		if key.Scope == activity.Scope && row.Activity == activity.Name && row.Status == TaskScheduled &&
			r.s.executions[row.Frame.Execution].Status == "RUNNING" {
			rows = append(rows, cloneTask(row))
		}
	}
	slices.SortFunc(rows, func(a, b TaskRecord) int {
		if order := a.Scheduled.Compare(b.Scheduled); order != 0 {
			return order
		}
		return cmp.Compare(a.Key.ID, b.Key.ID)
	})
	return rows, nil
}

func (r memoryReader) RecoverableTasks() ([]TaskRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]TaskRecord, 0)
	for _, row := range r.s.tasks {
		if (row.Status == TaskRunning && row.Kind != "activity") || (row.Status == TaskSubmitted && row.Kind == "sync") {
			rows = append(rows, cloneTask(row))
		}
	}
	slices.SortFunc(rows, func(a, b TaskRecord) int {
		if order := cmp.Compare(a.Key.ID, b.Key.ID); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Key.Partition, b.Key.Partition); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Key.AccountID, b.Key.AccountID); order != 0 {
			return order
		}
		return cmp.Compare(a.Key.Region, b.Key.Region)
	})
	return rows, nil
}

func (w memoryWriter) PutTask(row TaskRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	tokenKey := memoryTokenKey{Scope: row.Key.Scope, Token: row.Token}
	if row.Token != "" {
		if key, exists := w.s.tokens[tokenKey]; exists && key != row.Key {
			return fmt.Errorf("step functions task token already belongs to another attempt")
		}
	}
	if previous, exists := w.s.tasks[row.Key]; exists && previous.Token != "" && previous.Token != row.Token {
		delete(w.s.tokens, memoryTokenKey{Scope: row.Key.Scope, Token: previous.Token})
	}
	w.s.tasks[row.Key] = cloneTask(row)
	if row.Token != "" {
		w.s.tokens[tokenKey] = row.Key
	}
	return nil
}

func (r memoryReader) HistoryEvent(execution ExecutionKey, id int64) (HistoryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return HistoryRecord{}, err
	}
	row, ok := r.s.history[memoryHistoryKey{Execution: execution, ID: id}]
	if !ok {
		return HistoryRecord{}, ErrNotFound
	}
	row.Event = api.CloneHistoryEvent(row.Event)
	row.Encrypted = cloneEncryptedPayload(row.Encrypted)
	return row, nil
}

func (r memoryReader) History(execution ExecutionKey) ([]HistoryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]HistoryRecord, 0)
	for key, row := range r.s.history {
		if key.Execution == execution {
			row.Event = api.CloneHistoryEvent(row.Event)
			row.Encrypted = cloneEncryptedPayload(row.Encrypted)
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b HistoryRecord) int { return cmp.Compare(*a.Event.Id, *b.Event.Id) })
	return rows, nil
}

func (w memoryWriter) AppendHistory(row HistoryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if row.Event.Id == nil {
		return fmt.Errorf("step functions history event ID is required")
	}
	key := memoryHistoryKey{Execution: row.Execution, ID: int64(*row.Event.Id)}
	if _, exists := w.s.history[key]; exists {
		return fmt.Errorf("step functions history event %d already exists", key.ID)
	}
	row.Event = api.CloneHistoryEvent(row.Event)
	row.Encrypted = cloneEncryptedPayload(row.Encrypted)
	w.s.history[key] = row
	return nil
}

func (r memoryReader) MapRun(key MapRunKey) (MapRunRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return MapRunRecord{}, err
	}
	row, ok := r.s.mapRuns[key]
	if !ok {
		return MapRunRecord{}, ErrNotFound
	}
	return cloneMapRun(row), nil
}

func (r memoryReader) MapRuns(execution ExecutionKey) ([]MapRunRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]MapRunRecord, 0)
	for _, row := range r.s.mapRuns {
		if row.Frame.Execution == execution {
			rows = append(rows, cloneMapRun(row))
		}
	}
	slices.SortFunc(rows, func(a, b MapRunRecord) int {
		if order := b.Started.Compare(a.Started); order != 0 {
			return order
		}
		return cmp.Compare(a.Key.ARN, b.Key.ARN)
	})
	return rows, nil
}

func (w memoryWriter) PutMapRun(row MapRunRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.mapRuns[row.Key] = cloneMapRun(row)
	return nil
}

func (r memoryReader) MapResultFiles(key MapRunKey) ([]MapResultFile, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	return slices.Clone(r.s.mapFiles[key]), nil
}

func (w memoryWriter) PutMapResultFile(key MapRunKey, file MapResultFile) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	files := slices.Clone(w.s.mapFiles[key])
	replaced := false
	for i, prior := range files {
		if prior.Generation == file.Generation && prior.Status == file.Status && prior.Index == file.Index {
			files[i], replaced = file, true
			break
		}
	}
	if !replaced {
		files = append(files, file)
	}
	slices.SortFunc(files, func(a, b MapResultFile) int {
		if order := cmp.Compare(a.Generation, b.Generation); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Status, b.Status); order != 0 {
			return order
		}
		return cmp.Compare(a.Index, b.Index)
	})
	w.s.mapFiles[key] = files
	return nil
}
