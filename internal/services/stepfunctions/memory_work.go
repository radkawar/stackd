package stepfunctions

func (r memoryReader) NextWork() (WorkRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return WorkRecord{}, err
	}
	var next WorkRecord
	found := false
	consider := func(work WorkRecord) {
		if !found || CompareWork(work, next) < 0 {
			next = work
			found = true
		}
	}
machines:
	for key, machine := range r.s.machines {
		if machine.DeleteAt == nil {
			continue
		}
		for _, execution := range r.s.executions {
			if execution.Machine == key && execution.MachineID == machine.ID && execution.Status == "RUNNING" {
				continue machines
			}
		}
		consider(WorkRecord{Kind: WorkMachineDelete, Due: *machine.DeleteAt, Version: machine.Version, Machine: key})
	}
	for key, execution := range r.s.executions {
		if execution.Status == "RUNNING" {
			consider(WorkRecord{Kind: WorkExecutionTimeout, Due: execution.Deadline, Version: execution.Version, Execution: key})
		} else if execution.Expires != nil {
			consider(WorkRecord{Kind: WorkExecutionExpiry, Due: *execution.Expires, Version: execution.Version, Execution: key})
		}
		if execution.DeliveredHistoryID < execution.NextHistoryID {
			revision := r.s.revisions[RevisionKey{Scope: key.Scope, ID: execution.RevisionID}]
			if revision.LogLevel != "" && revision.LogLevel != "OFF" || execution.TraceSegmentID != "" {
				history, exists := r.s.history[memoryHistoryKey{Execution: key, ID: execution.DeliveredHistoryID + 1}]
				if exists && history.Event.Timestamp != nil {
					consider(WorkRecord{Kind: WorkHistoryDelivery, Due: *history.Event.Timestamp, Version: execution.Version, Execution: key})
				}
			}
		}
	}
	for key, frame := range r.s.frames {
		if frame.Due != nil && r.s.executions[key.Execution].Status == "RUNNING" {
			consider(WorkRecord{Kind: WorkFrame, Due: *frame.Due, Version: frame.Version, Execution: key.Execution, FrameID: key.ID})
		}
	}
	for key, task := range r.s.tasks {
		if r.s.executions[task.Frame.Execution].Status != "RUNNING" {
			continue
		}
		work := WorkRecord{Version: task.Version, Execution: task.Frame.Execution, FrameID: task.Frame.ID, TaskID: key.ID}
		switch task.Status {
		case TaskScheduled:
			if task.Kind != "activity" {
				work.Kind, work.Due = WorkTaskDispatch, task.Scheduled
				consider(work)
			}
		case TaskRunning, TaskSubmitted:
			if task.Deadline != nil {
				work.Kind, work.Due = WorkTaskTimeout, *task.Deadline
				consider(work)
			}
			if task.HeartbeatDeadline != nil {
				work.Kind, work.Due = WorkHeartbeatTimeout, *task.HeartbeatDeadline
				consider(work)
			}
		}
	}
	if !found {
		return WorkRecord{}, ErrNotFound
	}
	return next, nil
}
