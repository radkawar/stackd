package stackd_test

import "testing"

func TestS3CustomerEncryptionNativeReplay(t *testing.T) {
	t.Run("control", func(t *testing.T) {
		runS3NativeRawReplay(t, "s3/customer_encryption_control_replay.json")
	})
	t.Run("data", func(t *testing.T) {
		runS3MixedReplay(t, "s3/customer_encryption_data_replay.json")
	})
	t.Run("boundaries", func(t *testing.T) {
		runS3MixedReplay(t, "s3/customer_encryption_boundaries_replay.json")
	})
	t.Run("replication", func(t *testing.T) {
		runS3ExecutionReplay(t, "s3/customer_encryption_replication_replay.json")
	})
}
