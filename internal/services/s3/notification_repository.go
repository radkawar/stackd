package s3

import "time"

// NotificationProtocol identifies a directly configured destination. EventBridge
// enablement is independent of these filtered notification rules.
type NotificationProtocol string

const (
	NotificationSNS    NotificationProtocol = "sns"
	NotificationSQS    NotificationProtocol = "sqs"
	NotificationLambda NotificationProtocol = "lambda"
)

// NotificationFilter retains the accepted spelling of a value. Name is the
// native canonical Prefix or Suffix; matching decodes the form-encoded value.
type NotificationFilter struct {
	Name, Value string
}

// NotificationRule contains admitted values, rather than optional wire members.
type NotificationRule struct {
	ID, DestinationARN string
	Protocol           NotificationProtocol
	Events             []string
	Filters            []NotificationFilter
}

type NotificationConfiguration struct {
	EventBridge bool
	Rules       []NotificationRule
}

// NotificationState separates immediately visible configuration from the
// asynchronously applied configuration used by object mutations.
type NotificationState struct {
	Bucket           BucketKey
	Desired, Applied NotificationConfiguration
	ApplyAt          *time.Time
	Version          uint64
}

// NotificationDelivery is an immutable accepted projection, not an object read
// deferred until publication. Bucket ownership and destination survive later
// configuration changes and bucket deletion. Recipient commands run outside the
// source transaction and own delivery after their durable acceptance.
type NotificationDelivery struct {
	ID                       string
	Bucket                   BucketKey
	AccountID, Region        string
	Protocol                 NotificationProtocol
	DestinationARN, Payload  string
	RequestID, ParentEventID string
	Due                      time.Time
	Attempts                 int
	Version                  uint64
}
