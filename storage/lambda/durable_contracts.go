package lambda

import domain "stackd/internal/services/lambda"

type (
	DurableExecutionRecord  = domain.DurableExecutionRecord
	DurableOperationRecord  = domain.DurableOperationRecord
	DurableEventRecord      = domain.DurableEventRecord
	DurableCheckpointRecord = domain.DurableCheckpointRecord
	DurableReader           = domain.DurableReader
	DurableTransaction      = domain.DurableTransaction
)
