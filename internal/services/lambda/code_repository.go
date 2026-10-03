package lambda

import "time"

// CodeArchiveKey identifies immutable ZIP bytes within their owner scope.
// SHA256 is the base64 digest exposed by Lambda's CodeSha256 field.
type CodeArchiveKey struct {
	Scope
	SHA256 string
}

// CodeArchive is shared by deployments with identical code. RetainUntil keeps
// issued download URLs usable after every referencing function is deleted.
type CodeArchive struct {
	Key         CodeArchiveKey
	Code        []byte
	CreatedAt   time.Time
	RetainUntil time.Time
}

// CodeSigningKey belongs to Lambda, independently of IAM users and execution
// roles. It persists so restarting the service does not revoke issued URLs.
type CodeSigningKey struct {
	Scope
	AccessKeyID     string
	SecretAccessKey string
}

type CodeReader interface {
	CodeArchive(CodeArchiveKey) (CodeArchive, error)
	CodeSigningKey(Scope) (CodeSigningKey, error)
	// NextCodeArchiveDeadline ignores archives referenced by current or pending
	// deployments. The returned instant is the first time deletion is allowed.
	NextCodeArchiveDeadline() (time.Time, bool, error)
}

type CodeWriter interface {
	// PutCodeArchive inserts immutable bytes, preserving an existing archive's
	// contents and creation time and extending (never shortening) retention.
	PutCodeArchive(CodeArchive) error
	RetainCodeArchive(CodeArchiveKey, time.Time) error
	// PutCodeSigningKey inserts a scope's key without replacing an existing key.
	PutCodeSigningKey(CodeSigningKey) error
	// DeleteExpiredCodeArchives removes only unreferenced archives whose
	// retention deadline is strictly before now.
	DeleteExpiredCodeArchives(time.Time) (int64, error)
}
