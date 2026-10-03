package guardduty

import (
	"context"
	"time"
)

// PublishingDestination retains regional destination intent and actual delivery
// health. Version fences work prepared before a destination replacement.
type PublishingDestination struct {
	Scope
	DetectorID, ID, ARN, Type, ClientToken string
	DestinationARN, KMSKeyARN, Status      string
	Version                                int64
	Created, Updated, FailureStarted       time.Time
	Tags                                   map[string]string
}

// FindingExport is a service-owned publication cursor and transactional outbox,
// not resource state. Payload contains the generated Finding wire document for
// the latest queued occurrence; completed cursors have no payload or deadline.
// ID and ObjectKey stay stable across retries of one publication.
type FindingExport struct {
	Scope
	ParentEventID                                       string
	DetectorID, DestinationID, FindingID, ID, ObjectKey string
	DestinationVersion, Version                         int64
	Created, Due, LastPublished                         time.Time
	Payload                                             []byte
}

// FindingExportDeadline selects work without reading retained payloads.
type FindingExportDeadline struct {
	FindingID, ID string
	Version       int64
	Due           time.Time
}

// PublishingDestinationSink owns current S3/KMS authorization and actual object
// writes. Neither method may run inside a GuardDuty repository transaction.
// Validate writes the native encrypted zero-byte permission marker. Export
// writes gzip-compressed JSONL bytes under the supplied retained object key.
type PublishingDestinationSink interface {
	Validate(context.Context, PublishingDestination) error
	Export(context.Context, PublishingDestination, string, []byte) error
}
