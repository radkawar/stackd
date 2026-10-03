package account

import "time"

type PrimaryEmailStatus string

const (
	PrimaryEmailPending   PrimaryEmailStatus = "PENDING"
	PrimaryEmailAccepted  PrimaryEmailStatus = "ACCEPTED"
	PrimaryEmailCompleted PrimaryEmailStatus = "COMPLETED"
	PrimaryEmailFailed    PrimaryEmailStatus = "FAILED"
)

// PrimaryEmailUpdate owns the latest challenge, verification state and delivery
// intent for an account. OTP is private state and must not be logged or returned
// through AWS APIs. Generation distinguishes replacements and stale callbacks.
type PrimaryEmailUpdate struct {
	Scope         Scope
	Generation    uint64
	Email, OTP    string
	Status        PrimaryEmailStatus
	UpdatedAt     time.Time
	ExpiresAt     time.Time
	Due           time.Time
	NoticePending bool
}
