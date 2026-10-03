package ebs

// SnapshotCopyKeys retains only KMS-wrapped keys and the real grants admitted by
// CopySnapshot. KeySource owns the destination data key selected for incremental
// copies; deletion hides its public identity without discarding that metadata.
type SnapshotCopyKeys struct {
	WrappedKey                                                            []byte
	KMSKeyARN                                                             string
	KeySource                                                             SnapshotKey
	SourceGrantToken, DestinationGrantToken, DestinationEncryptGrantToken string
}
