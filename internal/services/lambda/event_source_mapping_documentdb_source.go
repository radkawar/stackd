package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// DocumentDBSource opens a native change stream using the current function role.
// The source owner, not Lambda, owns cluster lookup, credentials and networking.
type DocumentDBSource interface {
	// Check authorizes control admission without opening the engine. It returns
	// the current cluster incarnation, which must match any retained checkpoint.
	Check(context.Context, FunctionKey, string, EventSourceMappingRecord, DocumentDBCheckpoint) (string, error)
	Open(context.Context, FunctionKey, string, EventSourceMappingRecord, DocumentDBCheckpoint) (DocumentDBConsumer, error)
}

// DocumentDBConsumer reauthorizes every read and delivery/commit check. Position
// is established by the native engine before reading, so LATEST survives restart.
// Next must not mutate a previously returned record or token.
type DocumentDBConsumer interface {
	Check(context.Context) error
	Position() DocumentDBCheckpoint
	Next(context.Context) (DocumentDBRecord, bool, error)
	Close() error
}

type DocumentDBRecord struct {
	Event       json.RawMessage
	ResumeToken []byte
	Time        time.Time
}

// ErrDocumentDBHistoryLost means the native change-stream resume point expired.
// Retrying from a newer position would silently lose documents.
var ErrDocumentDBHistoryLost = errors.New("DocumentDB change stream history is no longer available")

// ErrDocumentDBStreamClosed fences a collection or database invalidation. A
// replacement namespace must not silently acquire the old mapping's cursor.
var ErrDocumentDBStreamClosed = errors.New("DocumentDB change stream was invalidated; recreate the event source mapping")

type DocumentDBMappingSettings struct {
	Database, Collection, FullDocument, SecretARN string
	StartingPosition, Incarnation                 string
	StartingPositionTimestamp                     time.Time
}

func cloneDocumentDBMappingSettings(v *DocumentDBMappingSettings) *DocumentDBMappingSettings {
	if v == nil {
		return nil
	}
	return new(*v)
}

// DocumentDBCheckpoint retains only the native cursor, never source documents.
// StartSeconds/StartIncrement are the native BSON operation timestamp used until
// the first committed token. They are deliberately not service-clock time.
type DocumentDBCheckpoint struct {
	Mapping                      EventSourceMappingKey
	Incarnation                  string
	ResumeToken                  []byte
	StartSeconds, StartIncrement uint32
}

type DocumentDBCheckpointReader interface {
	DocumentDBCheckpoint(EventSourceMappingKey) (DocumentDBCheckpoint, error)
}
type DocumentDBCheckpointWriter interface {
	PutDocumentDBCheckpoint(DocumentDBCheckpoint) error
	DeleteDocumentDBCheckpoint(EventSourceMappingKey) error
}
