package messageattribute

// ValidMessageID accepts the 1–128 printable ASCII characters shared by SNS
// message groups and SQS group, deduplication and receive-attempt identifiers.
func ValidMessageID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		if id[i] < 33 || id[i] > 126 {
			return false
		}
	}
	return true
}
