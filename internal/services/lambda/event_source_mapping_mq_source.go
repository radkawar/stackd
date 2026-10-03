package lambda

import (
	"context"
	"encoding/json"
)

// MQSource checks current broker, credential and execution-role authority without
// opening a queue. Open connects only when polling needs a native consumer.
type MQSource interface {
	Check(context.Context, FunctionKey, string, EventSourceMappingRecord) (MQIdentity, error)
	Open(context.Context, FunctionKey, string, EventSourceMappingRecord) (MQConsumer, error)
}

// MQConsumer retains native unacknowledged deliveries on one protocol session.
// Acknowledge commits the first count pending messages; Close returns unacknowledged
// messages to the broker. Neither Lambda nor its SQL store owns a message cursor.
type MQConsumer interface {
	Identity(context.Context) (MQIdentity, error)
	Fetch(context.Context, int) ([]MQMessage, error)
	Acknowledge(context.Context, int) error
	Close() error
}
type MQIdentity struct{ BrokerID, Engine string }
type MQMessage struct {
	ID     string
	Data   []byte
	Record json.RawMessage
}
type MQMappingSettings struct {
	Queue, VirtualHost, SecretARN string
	VirtualHostSet                bool
	Identity                      MQIdentity
}
