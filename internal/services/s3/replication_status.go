package s3

// objectReplicationStatus combines current destination/component outcomes. A
// replica retains its origin while metadata is pending or failed, and returns
// to REPLICA after all its accepted metadata work completes.
func objectReplicationStatus(reader Reader, object ObjectRecord) (string, error) {
	states, err := reader.ReplicationStates(object.VersionKey())
	if err != nil {
		return "", err
	}
	pending := false
	for _, state := range states {
		switch state.Status {
		case "FAILED":
			return "FAILED", nil
		case "PENDING":
			pending = true
		}
	}
	if pending {
		return "PENDING", nil
	}
	if object.Replica {
		return "REPLICA", nil
	}
	if len(states) != 0 {
		return "COMPLETED", nil
	}
	return "", nil
}
