package journal

// EventBridgeAccepted identifies accepted event-bus work. Customer event detail
// and delivery state remain in EventBridge's typed repository.
type EventBridgeAccepted struct {
	// EventID identifies the retained admission used by causal descendants.
	EventID string `json:"event_id"`
	// WireEventID correlates native envelopes that can survive bus forwarding.
	WireEventID string `json:"wire_event_id"`
	EventBusARN string `json:"event_bus_arn"`
}

// LambdaInvocationAccepted identifies durable asynchronous work. The payload and
// retry state remain in Lambda's repository; acceptance is not execution success.
type LambdaInvocationAccepted struct {
	InvocationID string `json:"invocation_id"`
	FunctionARN  string `json:"function_arn"`
}

// SQSMessageAccepted records an accepted queue message without its customer body.
// ParentEventID in the envelope identifies its source event when delivered by a service.
type SQSMessageAccepted struct {
	MessageID string `json:"message_id"`
	QueueARN  string `json:"queue_arn"`
}

// LogsBatchAccepted identifies accepted log ingestion without customer messages.
// BatchID links downstream subscription delivery to this committed source fact.
type LogsBatchAccepted struct {
	BatchID       string `json:"batch_id"`
	LogGroupARN   string `json:"log_group_arn"`
	LogStreamName string `json:"log_stream_name"`
	EventCount    int64  `json:"event_count"`
}

// LambdaSourceBatchAccepted links an admitted Invoke to its source records.
// Payloads, receipts and retry ownership stay with their source domains.
type LambdaSourceBatchAccepted struct {
	InvocationEventID string   `json:"invocation_event_id"`
	MappingARN        string   `json:"mapping_arn"`
	SourceARN         string   `json:"source_arn"`
	RecordIDs         []string `json:"record_ids"`
}
