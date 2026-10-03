package s3

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"time"
)

// MultipartUploadKey scopes an opaque upload ID to its destination object.
type MultipartUploadKey struct {
	ObjectKey
	UploadID string
}

// MultipartUploadRecord owns initiation metadata, encryption and tags until
// completion or abort. ObjectRecord.Modified is initiation time; CreatedOrder
// reserves version ordering independently of completion's mutation sequence.
// An intervening newer object write or key deletion supersedes the upload.
// That fact belongs to the active upload, not an independent object history.
type MultipartUploadRecord struct {
	ObjectRecord
	Initiator  string
	Tags       []Tag
	Superseded bool
}

// AssignInitiation is called by the repository with its reserved version order.
// The opaque ID carries that order so pagination survives completion or abort.
func (v *MultipartUploadRecord) AssignInitiation(order int64) error {
	var token [32]byte
	binary.BigEndian.PutUint64(token[:8], uint64(order))
	if _, err := rand.Read(token[8:]); err != nil {
		return err
	}
	v.CreatedOrder = order
	v.UploadID = "mp1_" + base64.RawURLEncoding.EncodeToString(token[:])
	return nil
}

func (v ObjectRecord) UploadKey() MultipartUploadKey {
	return MultipartUploadKey{ObjectKey: v.Key, UploadID: v.UploadID}
}

// PartRecord is metadata for one encrypted part. Number remains the original
// upload number after publication; object-read ordinals follow selected order.
// Checksum is the initiation algorithm's digest, or automatic CRC64NVME when
// initiation did not request one. Ciphertext is stored separately.
type PartRecord struct {
	Number         int32
	Modified       time.Time
	Size           int64
	ETag, Checksum string
}

// MultipartQuery orders keys ascending, then initiation order ascending.
// The upload marker is exclusive within AfterKey; without it that key is skipped.
// Prefix and markers operate on original keys, not URL-encoded spellings.
type MultipartQuery struct {
	Bucket           BucketKey
	Prefix, AfterKey string
	AfterOrder       *int64
	Limit            int
}
