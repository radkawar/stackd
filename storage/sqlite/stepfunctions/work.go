package stepfunctions

import (
	"database/sql"
	"errors"

	domain "stackd/internal/services/stepfunctions"
)

func (r reader) NextWork() (domain.WorkRecord, error) {
	var next domain.WorkRecord
	found := false
	consider := func(candidate domain.WorkRecord, err error) error {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !found || domain.CompareWork(candidate, next) < 0 {
			next, found = candidate, true
		}
		return nil
	}
	machine, err := r.q.NextMachineDelete(r.ctx)
	if err := consider(domain.WorkRecord{
		Kind: domain.WorkMachineDelete, Due: machine.DeleteAt.Time, Version: machine.Version,
		Machine: domain.MachineKey{Scope: domain.Scope{Partition: machine.Partition, AccountID: machine.AccountID, Region: machine.Region}, Name: machine.Name},
	}, err); err != nil {
		return domain.WorkRecord{}, err
	}
	execution, err := r.q.NextExecutionTimeout(r.ctx)
	if err := consider(domain.WorkRecord{
		Kind: domain.WorkExecutionTimeout, Due: execution.Deadline, Version: execution.Version,
		Execution: domain.ExecutionKey{Scope: domain.Scope{Partition: execution.Partition, AccountID: execution.AccountID, Region: execution.Region}, ARN: execution.Arn},
	}, err); err != nil {
		return domain.WorkRecord{}, err
	}
	expiry, err := r.q.NextExecutionExpiry(r.ctx)
	if err := consider(domain.WorkRecord{
		Kind: domain.WorkExecutionExpiry, Due: expiry.Expires.Time, Version: expiry.Version,
		Execution: domain.ExecutionKey{Scope: domain.Scope{Partition: expiry.Partition, AccountID: expiry.AccountID, Region: expiry.Region}, ARN: expiry.Arn},
	}, err); err != nil {
		return domain.WorkRecord{}, err
	}
	frame, err := r.q.NextFrame(r.ctx)
	if err := consider(domain.WorkRecord{
		Kind: domain.WorkFrame, Due: frame.Due.Time, Version: frame.Version,
		Execution: domain.ExecutionKey{Scope: domain.Scope{Partition: frame.Partition, AccountID: frame.AccountID, Region: frame.Region}, ARN: frame.ExecutionArn}, FrameID: frame.ID,
	}, err); err != nil {
		return domain.WorkRecord{}, err
	}
	dispatch, err := r.q.NextTaskDispatch(r.ctx)
	if err := consider(domain.WorkRecord{
		Kind: domain.WorkTaskDispatch, Due: dispatch.Scheduled, Version: dispatch.Version,
		Execution: domain.ExecutionKey{Scope: domain.Scope{Partition: dispatch.Partition, AccountID: dispatch.AccountID, Region: dispatch.Region}, ARN: dispatch.ExecutionArn}, FrameID: dispatch.FrameID, TaskID: dispatch.ID,
	}, err); err != nil {
		return domain.WorkRecord{}, err
	}
	task, err := r.q.NextTaskTimeout(r.ctx)
	if err := consider(domain.WorkRecord{
		Kind: domain.WorkTaskTimeout, Due: task.Deadline.Time, Version: task.Version,
		Execution: domain.ExecutionKey{Scope: domain.Scope{Partition: task.Partition, AccountID: task.AccountID, Region: task.Region}, ARN: task.ExecutionArn}, FrameID: task.FrameID, TaskID: task.ID,
	}, err); err != nil {
		return domain.WorkRecord{}, err
	}
	heartbeat, err := r.q.NextHeartbeatTimeout(r.ctx)
	if err := consider(domain.WorkRecord{
		Kind: domain.WorkHeartbeatTimeout, Due: heartbeat.HeartbeatDeadline.Time, Version: heartbeat.Version,
		Execution: domain.ExecutionKey{Scope: domain.Scope{Partition: heartbeat.Partition, AccountID: heartbeat.AccountID, Region: heartbeat.Region}, ARN: heartbeat.ExecutionArn}, FrameID: heartbeat.FrameID, TaskID: heartbeat.ID,
	}, err); err != nil {
		return domain.WorkRecord{}, err
	}
	history, err := r.q.NextHistoryDelivery(r.ctx)
	if err := consider(domain.WorkRecord{
		Kind: domain.WorkHistoryDelivery, Due: history.At.Time, Version: history.Version,
		Execution: domain.ExecutionKey{Scope: domain.Scope{Partition: history.Partition, AccountID: history.AccountID, Region: history.Region}, ARN: history.Arn},
	}, err); err != nil {
		return domain.WorkRecord{}, err
	}
	if !found {
		return domain.WorkRecord{}, domain.ErrNotFound
	}
	return next, nil
}
