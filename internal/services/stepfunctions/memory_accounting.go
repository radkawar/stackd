package stepfunctions

// executionMemoryBase follows the documented Express sizing model. This is
// execution-data accounting, not the Go process's allocator or RSS.
// TODO: Comeback reconcile ExpressExecutionMemory with AWS's private per-value
// allocation accounting; native billing granularity is implemented separately.
func executionMemoryBase(revision RevisionRecord) int64 {
	return 50_000_000 + int64(len(revision.Definition))
}

func observeExecutionMemory(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame FrameRecord) error {
	if execution.Type != "EXPRESS" {
		return nil
	}
	parallelism := int64(1)
	if frame.ParentID != 0 {
		parent, err := tx.Frame(FrameKey{Execution: execution.Key, ID: frame.ParentID})
		if err != nil {
			return err
		}
		parallelism = max(parent.MaxConcurrency, 1)
	}
	data := int64(len(frame.Input) + len(frame.Arguments) + len(frame.Output) + len(frame.Variables))
	execution.PeakMemoryBytes = max(execution.PeakMemoryBytes, executionMemoryBase(revision)+data*parallelism)
	return nil
}
