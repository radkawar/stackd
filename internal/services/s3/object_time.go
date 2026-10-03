package s3

import "time"

// objectDayDeadline is shared by lifecycle ages and temporary restore expiry.
// Calendar arithmetic admits the native positive int32 Days range without
// overflowing time.Duration. S3 rounds up to the following midnight UTC.
func objectDayDeadline(at time.Time, days int32) time.Time {
	until := at.UTC().AddDate(0, 0, int(days))
	return time.Date(until.Year(), until.Month(), until.Day()+1, 0, 0, 0, 0, time.UTC)
}
