package cloudtrail

import "time"

// DigestKeyRecord retains regional signing material independently of trail lifetime.
// Public key discovery exposes PublicDER only; PrivateDER never leaves this owner.
type DigestKeyRecord struct {
	Partition, Region, Fingerprint string
	Start, End                     time.Time
	PrivateDER, PublicDER          []byte
}

// DigestStream is one account/region chain in one enabled trail interval. Pending
// contains the exact gzip object to retry, not a regenerated signature or document.
// It intentionally survives trail deletion long enough to deliver its final digest.
type DigestStream struct {
	ID, TrailID                                                     string
	Trail                                                           TrailKey
	AccountID, Region, OrganizationID                               string
	Bucket, Prefix, KMSKeyID                                        string
	Start, End, Due                                                 time.Time
	Closed                                                          bool
	ClosedAt                                                        time.Time
	Version                                                         uint64
	PreviousBucket, PreviousObject, PreviousHash, PreviousSignature string
	Pending                                                         []byte
	PendingObject, PendingHash, PendingSignature                    string
}

// DigestLog describes a successful S3 log delivery; failed writes never enter it.
type DigestLog struct {
	StreamID, DeliveryID, Bucket, Object, Hash string
	Delivered, Oldest, Newest                  time.Time
}

type DigestStatus struct {
	TrailID, AccountID, Region string
	LastAttempt, LastSuccess   *time.Time
	LastError                  string
}

type DigestReader interface {
	DigestKeys(partition, region string) ([]DigestKeyRecord, error)
	DigestStream(id string) (DigestStream, error)
	DigestStreams(trailID string) ([]DigestStream, error)
	NextDigest() (DigestStream, error)
	DigestLogs(streamID string, end time.Time) ([]DigestLog, error)
	DigestStatus(trailID, accountID, region string) (DigestStatus, error)
}
type DigestTransaction interface {
	PutDigestKey(DigestKeyRecord) error
	PutDigestStream(DigestStream) error
	DeleteDigestStream(string) error
	PutDigestLog(DigestLog) error
	DeleteDigestLogs(string, time.Time) error
	PutDigestStatus(DigestStatus) error
}
