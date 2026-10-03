package lambda

import "stackd/internal/scheduler"

func (r memoryReader) NextCodeSourceCheck() (job scheduler.Job, found bool, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	for key, v := range *r.state {
		if key.Pending || !codeSourceCheckEligible(v) {
			continue
		}
		next := scheduler.Job{Key: (FunctionVersionKey{FunctionKey: v.Key, Version: v.Version}).ARN(), Version: v.Version, Due: v.CodeSourceCheckAt}
		if !found || scheduler.Compare(next, job) < 0 {
			job, found = next, true
		}
	}
	return
}

func (w memoryWriter) SetCodeSourceState(v FunctionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	key := deploymentKey{FunctionKey: v.Key, Version: v.Version}
	current, ok := (*w.state)[key]
	if !ok {
		return ErrNotFound
	}
	current.State, current.StateReason, current.StateReasonCode = v.State, v.StateReason, v.StateReasonCode
	current.Revision, current.CodeSourceCheckAt = v.Revision, v.CodeSourceCheckAt
	(*w.state)[key] = current
	return nil
}
