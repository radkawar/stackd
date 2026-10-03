package eventbridge

import "time"

// ArchiveKey identifies an archive independently of the source bus's lifetime.
type ArchiveKey struct {
	Scope
	Name string
}

func (k ArchiveKey) ARN() string {
	return "arn:" + k.Partition + ":events:" + k.Region + ":" + k.Account + ":archive/" + k.Name
}

// ArchivePayload contains an event envelope or an archive's original pattern.
// A nonempty DataKey is a KMS ciphertext blob; Content then contains the
// envelope-encrypted payload rather than plaintext customer JSON.
type ArchivePayload struct {
	Content, DataKey []byte
}

// ArchiveRecord owns its managed rule and retained event collection. ID is the
// native archive incarnation exposed by the managed target's input template.
// Version fences control changes prepared across an external KMS operation;
// event counts and retention processing do not change that configuration version.
type ArchiveRecord struct {
	Key                           ArchiveKey
	ID                            string
	Source                        BusKey
	Description, KmsKeyIdentifier string
	// The public identifier preserves its supplied form; KeyARN binds the
	// resolved key used for archive encryption.
	KeyARN                string
	Pattern               ArchivePayload
	RetentionDays         int32
	Created               time.Time
	State, StateReason    string
	Version               uint64
	EventCount, SizeBytes int64
	// KeyVersion labels retained payloads, independently of control versions.
	// MigrationDue is durable scheduler state, not an AWS latency promise.
	KeyVersion                               uint64
	MigrationDue                             time.Time
	PreviousKeyARN, PreviousKmsKeyIdentifier string
}

// ArchiveCursor orders an archive's event-time index. An empty ID starts a scan.
// Replay scans complete minute buckets before applying its exact time window.
type ArchiveCursor struct {
	Time time.Time
	ID   string
}

// ArchiveEntry retains a self-contained event envelope, not a reference whose
// lifetime depends on the accepted-event history. ID is the source admission ID.
// Ingested is bus ingestion time, distinct from the event's customer timestamp.
// A zero Expires means indefinite retention.
type ArchiveEntry struct {
	ArchiveID, ID           string
	Time, Ingested, Expires time.Time
	Payload                 ArchivePayload
	SizeBytes               int64
	KeyVersion              uint64
	// RuleContext preserves the authenticated context of pre-migration storage.
	// New retained envelopes use the bus-only storage context.
	RuleContext bool
}

// ArchiveReader returns detached archive records and bounded event selections.
type ArchiveReader interface {
	Archive(ArchiveKey) (ArchiveRecord, error)
	ArchiveByID(string) (ArchiveRecord, error)
	Archives(Scope) ([]ArchiveRecord, error)
	ArchiveEntry(archiveID, eventID string) (ArchiveEntry, error)
	NextArchiveEntry(archiveID string, start, end time.Time, after ArchiveCursor) (ArchiveEntry, bool, error)
	NextArchiveExpiration() (ArchiveEntry, bool, error)
	NextArchiveMigration() (ArchiveRecord, bool, error)
	NextArchiveMigrationEntry(archiveID string, keyVersion uint64) (ArchiveEntry, bool, error)
}

// ArchiveWriter participates in the same transaction as rule, delivery and
// journal changes. Deleting an archive also removes its retained entries.
type ArchiveWriter interface {
	PutArchive(ArchiveRecord) error
	DeleteArchive(ArchiveKey) error
	PutArchiveEntry(ArchiveEntry) error
	DeleteArchiveEntry(archiveID, eventID string) error
	UpdateArchiveEntryRetention(archiveID string, days int32) error
}
