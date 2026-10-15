package ec2

// InternalFlowLogs is privileged scheduler discovery, never public discovery.
type FlowLogReader interface {
	FlowLog(ResourceKey) (FlowLogRecord, error)
	FlowLogs(Scope) ([]FlowLogRecord, error)
	InternalFlowLogs() ([]FlowLogRecord, error)
	FlowLogToken(FlowLogTokenKey) (FlowLogTokenRecord, error)
	FlowLogCaptureState() (FlowLogCaptureState, error)
	FlowLogAggregates(ResourceKey) ([]FlowLogAggregateRecord, error)
	FlowLogDeliveries() ([]FlowLogDeliveryRecord, error)
}
type FlowLogWriter interface {
	PutFlowLog(FlowLogRecord) error
	DeleteFlowLog(ResourceKey) error
	PutFlowLogToken(FlowLogTokenRecord) error
	PutFlowLogCaptureState(FlowLogCaptureState) error
	PutFlowLogAggregate(FlowLogAggregateRecord) error
	DeleteFlowLogAggregate(FlowLogAggregateKey) error
	PutFlowLogDelivery(FlowLogDeliveryRecord) error
	DeleteFlowLogDelivery(ResourceKey) error
}
