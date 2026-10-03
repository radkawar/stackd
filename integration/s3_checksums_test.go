package stackd_test

import "testing"

func TestS3ChecksumAlgorithmsNativeReplay(t *testing.T) {
	t.Run("object", func(t *testing.T) {
		runS3MixedReplay(t, "s3/checksum_algorithms_object_replay.json")
	})
	t.Run("multipart", func(t *testing.T) {
		runS3MixedReplay(t, "s3/checksum_algorithms_multipart_replay.json")
	})
}
