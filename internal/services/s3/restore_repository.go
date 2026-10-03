package s3

import "time"

// ObjectRestore owns the temporary readable state of one archived version.
// Ongoing selects a completion deadline; otherwise Due is the cache expiry.
// A new object version or copy never inherits this state. Deleting or replacing
// its object version removes it in the same transaction.
type ObjectRestore struct {
	Key           ObjectVersionKey
	Due           time.Time
	Ongoing       bool
	Days          int32
	Tier          string
	ParentEventID string
}
