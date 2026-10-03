package stepfunctions

import (
	"errors"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/services/stepfunctions/asl"
)

type workflowTransaction struct {
	Transaction
	reader *workflowReader
}

func (s *Service) workflowTransaction(tx Transaction, revision RevisionRecord, role string) *workflowTransaction {
	return &workflowTransaction{Transaction: tx, reader: s.workflowReader(tx, revision, role)}
}

func (t *workflowTransaction) rebind(tx Transaction) *workflowTransaction {
	rebound := t.reader.service.workflowTransaction(tx, t.reader.revision, t.reader.role)
	rebound.reader.fixed = t.reader.fixed
	return rebound
}

func (t *workflowTransaction) Revision(k RevisionKey) (RevisionRecord, error) {
	return t.reader.Revision(k)
}
func (t *workflowTransaction) Execution(k ExecutionKey) (ExecutionRecord, error) {
	return t.reader.Execution(k)
}
func (t *workflowTransaction) Executions(k ExecutionSelection) ([]ExecutionRecord, error) {
	return t.reader.Executions(k)
}
func (t *workflowTransaction) Frame(k FrameKey) (FrameRecord, error) { return t.reader.Frame(k) }
func (t *workflowTransaction) Frames(k ExecutionKey) ([]FrameRecord, error) {
	return t.reader.Frames(k)
}
func (t *workflowTransaction) Task(k TaskKey) (TaskRecord, error) { return t.reader.Task(k) }
func (t *workflowTransaction) TaskByToken(scope Scope, token string) (TaskRecord, error) {
	return t.reader.TaskByToken(scope, token)
}
func (t *workflowTransaction) ActivityTasks(k ActivityKey) ([]TaskRecord, error) {
	return t.reader.ActivityTasks(k)
}
func (t *workflowTransaction) History(k ExecutionKey) ([]HistoryRecord, error) {
	return t.reader.History(k)
}
func (t *workflowTransaction) HistoryEvent(k ExecutionKey, id int64) (HistoryRecord, error) {
	return t.reader.HistoryEvent(k, id)
}

func (t *workflowTransaction) PutRevision(v RevisionRecord) error {
	sealed, err := t.reader.service.sealRevision(t.Context(), v, t.reader.role)
	if err != nil {
		return err
	}
	return t.Transaction.PutRevision(sealed)
}

func (t *workflowTransaction) PutExecution(v ExecutionRecord) error {
	if t.reader.revision.KMSKeyARN == "" {
		return t.Transaction.PutExecution(v)
	}
	data := executionPayload{v.Input, v.Output, v.Error, v.Cause}
	if _, opened := t.reader.executions[v.Key]; !opened && v.Encrypted != nil && data == (executionPayload{}) {
		return t.Transaction.PutExecution(v)
	}
	if previous, ok := t.reader.executions[v.Key]; ok && previous.value == data {
		v.Encrypted = previous.encrypted
	} else {
		var err error
		v.Encrypted, err = t.reader.seal(data)
		if err != nil {
			return err
		}
	}
	t.reader.executions[v.Key] = openedPayload[executionPayload]{data, v.Encrypted}
	v.Input, v.Output, v.Error, v.Cause = "", "", "", ""
	return t.Transaction.PutExecution(v)
}

func (t *workflowTransaction) PutFrame(v FrameRecord) error {
	if t.reader.revision.KMSKeyARN == "" {
		return t.Transaction.PutFrame(v)
	}
	data := framePayload{v.Input, v.Variables, v.Arguments, v.Output, v.Error, v.Cause}
	if _, opened := t.reader.frames[v.Key]; !opened && v.Encrypted != nil && data == (framePayload{}) {
		return t.Transaction.PutFrame(v)
	}
	if previous, ok := t.reader.frames[v.Key]; ok && previous.value == data {
		v.Encrypted = previous.encrypted
	} else {
		var err error
		v.Encrypted, err = t.reader.seal(data)
		if err != nil {
			return err
		}
	}
	t.reader.frames[v.Key] = openedPayload[framePayload]{data, v.Encrypted}
	v.Input, v.Variables, v.Arguments, v.Output, v.Error, v.Cause = "", "", "", "", "", ""
	return t.Transaction.PutFrame(v)
}

func (t *workflowTransaction) PutTask(v TaskRecord) error {
	if v.EncryptedInput != nil {
		v.Parameters = ""
	}
	if t.reader.revision.KMSKeyARN == "" {
		return t.Transaction.PutTask(v)
	}
	data := taskPayload{v.Output, v.Error, v.Cause}
	if data == (taskPayload{}) {
		v.Encrypted = nil
	} else if previous, ok := t.reader.tasks[v.Key]; ok && previous.value == data {
		v.Encrypted = previous.encrypted
	} else {
		var err error
		v.Encrypted, err = t.reader.seal(data)
		if err != nil {
			return err
		}
	}
	t.reader.tasks[v.Key] = openedPayload[taskPayload]{data, v.Encrypted}
	v.Output, v.Error, v.Cause = "", "", ""
	return t.Transaction.PutTask(v)
}

func (t *workflowTransaction) AppendHistory(v HistoryRecord) error {
	if t.reader.revision.KMSKeyARN == "" {
		return t.Transaction.AppendHistory(v)
	}
	encrypted, err := t.reader.seal(historyPayload{v.Error, v.Cause, v.Event})
	if err != nil {
		return err
	}
	v.Encrypted = encrypted
	v.Error, v.Cause = "", ""
	v.Event = api.HistoryEvent{Id: v.Event.Id, Timestamp: v.Event.Timestamp, Type: v.Event.Type, PreviousEventId: v.Event.PreviousEventId}
	return t.Transaction.AppendHistory(v)
}

// protectTaskInput admits immutable task input before scheduling history is
// emitted. A denied Activity key must not produce an ActivityScheduled event.
func (s *Service) protectTaskInput(r Reader, revision RevisionRecord, task *TaskRecord) error {
	config, resource := revision.EncryptionConfig, revision.Machine.ARN()
	var material *workflowDataKey
	if task.Kind == "activity" {
		scope, _, name, _, err := parseResourceARN(task.Resource)
		if err != nil {
			return err
		}
		activity, err := r.Activity(ActivityKey{Scope: scope, Name: name})
		if errors.Is(err, ErrNotFound) {
			return &asl.EvaluationError{Name: "States.Runtime", Cause: "The activity " + task.Resource + " does not exist."}
		}
		if err != nil {
			return err
		}
		config, resource = activity.EncryptionConfig, task.Resource
	} else {
		material = s.encryption.synchronousMaterial(task.Frame.Execution)
	}
	if config.KMSKeyARN == "" {
		return nil
	}
	if material == nil {
		generated, err := s.encryption.generate(r.Context(), revision, resource, revision.RoleARN, config)
		if err != nil {
			return err
		}
		material = &generated
	}
	task.EncryptedInput = sealWorkflowPayload(*material, []byte(task.Parameters))
	return nil
}
