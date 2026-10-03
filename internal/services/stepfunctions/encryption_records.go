package stepfunctions

import (
	"encoding/json"

	api "stackd/internal/awsapi/stepfunctions"
)

type executionPayload struct{ Input, Output, Error, Cause string }
type framePayload struct{ Input, Variables, Arguments, Output, Error, Cause string }
type taskPayload struct{ Output, Error, Cause string }
type historyPayload struct {
	Error, Cause string
	Event        api.HistoryEvent
}

type openedPayload[T comparable] struct {
	value     T
	encrypted *EncryptedPayload
}

// workflowReader projects a decrypted working set without changing the stored
// records. Metadata-only APIs continue to use the original repository reader.
type workflowReader struct {
	Reader
	payloadReader
	executions map[ExecutionKey]openedPayload[executionPayload]
	frames     map[FrameKey]openedPayload[framePayload]
	tasks      map[TaskKey]openedPayload[taskPayload]
}

func (s *Service) workflowReader(r Reader, revision RevisionRecord, role string) *workflowReader {
	return &workflowReader{Reader: r, payloadReader: payloadReader{service: s, reader: r, revision: revision, role: role},
		executions: make(map[ExecutionKey]openedPayload[executionPayload]),
		frames:     make(map[FrameKey]openedPayload[framePayload]), tasks: make(map[TaskKey]openedPayload[taskPayload])}
}

func (r *workflowReader) Revision(key RevisionKey) (RevisionRecord, error) {
	v, err := r.Reader.Revision(key)
	if err != nil || v.Encrypted == nil {
		return v, err
	}
	plain, err := r.open(v.Machine.ARN(), v.Encrypted)
	if err != nil {
		return RevisionRecord{}, err
	}
	v.Definition = string(plain)
	return v, nil
}

func (r *workflowReader) execution(v ExecutionRecord) (ExecutionRecord, error) {
	if r.role != "" && r.fixed == nil {
		r.fixed = r.service.encryption.synchronousMaterial(v.Key)
	}
	if v.Encrypted == nil {
		return v, nil
	}
	var data executionPayload
	if err := r.decode(r.revision.Machine.ARN(), v.Encrypted, &data); err != nil {
		return ExecutionRecord{}, err
	}
	r.executions[v.Key] = openedPayload[executionPayload]{data, v.Encrypted}
	v.Input, v.Output = data.Input, data.Output
	// A metadata-only terminal transition can add a service diagnostic while
	// retaining the inaccessible input envelope. That newer diagnostic wins
	// over the earlier payload, whose Error/Cause may still be empty.
	if v.Error == "" && v.Cause == "" {
		v.Error, v.Cause = data.Error, data.Cause
	}
	return v, nil
}

func (r *workflowReader) Execution(key ExecutionKey) (ExecutionRecord, error) {
	v, err := r.Reader.Execution(key)
	if err != nil {
		return v, err
	}
	return r.execution(v)
}

func (r *workflowReader) Executions(selection ExecutionSelection) ([]ExecutionRecord, error) {
	rows, err := r.Reader.Executions(selection)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i], err = r.execution(rows[i])
		if err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func (r *workflowReader) frame(v FrameRecord) (FrameRecord, error) {
	if v.Encrypted == nil {
		return v, nil
	}
	var data framePayload
	if err := r.decode(r.revision.Machine.ARN(), v.Encrypted, &data); err != nil {
		return FrameRecord{}, err
	}
	r.frames[v.Key] = openedPayload[framePayload]{data, v.Encrypted}
	v.Input, v.Variables, v.Arguments, v.Output = data.Input, data.Variables, data.Arguments, data.Output
	if v.Error == "" && v.Cause == "" {
		v.Error, v.Cause = data.Error, data.Cause
	}
	return v, nil
}

func (r *workflowReader) Frame(key FrameKey) (FrameRecord, error) {
	v, err := r.Reader.Frame(key)
	if err != nil {
		return v, err
	}
	return r.frame(v)
}

func (r *workflowReader) Frames(key ExecutionKey) ([]FrameRecord, error) {
	rows, err := r.Reader.Frames(key)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i], err = r.frame(rows[i])
		if err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func (r *workflowReader) task(v TaskRecord) (TaskRecord, error) {
	if v.Encrypted != nil {
		var data taskPayload
		if err := r.decode(r.revision.Machine.ARN(), v.Encrypted, &data); err != nil {
			return TaskRecord{}, err
		}
		r.tasks[v.Key] = openedPayload[taskPayload]{data, v.Encrypted}
		v.Output = data.Output
		if v.Error == "" && v.Cause == "" {
			v.Error, v.Cause = data.Error, data.Cause
		}
	}
	if v.EncryptedInput != nil && v.Kind != "activity" {
		plain, err := r.open(r.revision.Machine.ARN(), v.EncryptedInput)
		if err != nil {
			return TaskRecord{}, err
		}
		v.Parameters = string(plain)
	}
	return v, nil
}

func (r *workflowReader) Task(key TaskKey) (TaskRecord, error) {
	v, err := r.Reader.Task(key)
	if err != nil {
		return v, err
	}
	return r.task(v)
}

func (r *workflowReader) TaskByToken(scope Scope, token string) (TaskRecord, error) {
	v, err := r.Reader.TaskByToken(scope, token)
	if err != nil {
		return v, err
	}
	return r.task(v)
}

func (r *workflowReader) ActivityTasks(key ActivityKey) ([]TaskRecord, error) {
	rows, err := r.Reader.ActivityTasks(key)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i], err = r.task(rows[i])
		if err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func (r *workflowReader) history(v HistoryRecord) (HistoryRecord, error) {
	if v.Encrypted == nil {
		return v, nil
	}
	var data historyPayload
	if err := r.decode(r.revision.Machine.ARN(), v.Encrypted, &data); err != nil {
		return HistoryRecord{}, err
	}
	v.Error, v.Cause, v.Event = data.Error, data.Cause, data.Event
	return v, nil
}

func (r *workflowReader) History(key ExecutionKey) ([]HistoryRecord, error) {
	rows, err := r.Reader.History(key)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i], err = r.history(rows[i])
		if err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func (r *workflowReader) HistoryEvent(key ExecutionKey, id int64) (HistoryRecord, error) {
	v, err := r.Reader.HistoryEvent(key, id)
	if err != nil {
		return v, err
	}
	return r.history(v)
}

func (r *workflowReader) seal(value any) (*EncryptedPayload, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return r.sealBytes(plain)
}

func (r *workflowReader) sealBytes(plain []byte) (*EncryptedPayload, error) {
	var material workflowDataKey
	if r.fixed != nil {
		material = *r.fixed
	} else {
		var err error
		material, err = r.service.encryption.generate(r.Context(), r.revision, r.revision.Machine.ARN(), r.role, r.revision.EncryptionConfig)
		if err != nil {
			return nil, err
		}
	}
	return sealWorkflowPayload(material, plain), nil
}
