package s3

import "time"

// AccessLogDelivery retains a completed request's native record and destination
// independently of the source bucket. Only Due changes while delivery is pending.
type AccessLogDelivery struct {
	ID                string
	Source            BucketKey
	AccountID, Region string
	Destination       LoggingConfiguration
	Record            string
	At, Due           time.Time
}
