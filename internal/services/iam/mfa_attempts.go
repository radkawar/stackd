package iam

import "time"

// AWS captures admit nine verifications per device before making it temporarily
// unavailable. Successful and invalid codes both use the same attempt budget.
const mfaAttemptLimit = 9

// Independent captures recovered at three-minute UTC boundaries, including
// roughly ten seconds after exhaustion. This models those observations in
// service time; AWS does not publish an exact rate or recovery deadline.
const mfaAttemptWindow = 3 * time.Minute

func (d *MFADevice) recordAttempt(now time.Time) bool {
	window := now.Truncate(mfaAttemptWindow)
	count := &d.VerificationCount
	if !count.Window.Equal(window) {
		*count = MFAVerificationCount{Window: window}
	}
	if count.Count >= mfaAttemptLimit {
		return false
	}
	count.Count++
	return true
}
