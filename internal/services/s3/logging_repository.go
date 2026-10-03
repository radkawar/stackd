package s3

// LoggingConfiguration retains an admitted server access-log destination. Nil
// denotes disabled logging. Grants distinguishes omission from an empty list.
type LoggingConfiguration struct {
	TargetBucket, TargetPrefix string
	// KeyFormat is empty when omitted, SimplePrefix, PartitionedPrefix (date
	// omitted), EventTime, or DeliveryTime.
	KeyFormat string
	Grants    []ACLGrant
}
