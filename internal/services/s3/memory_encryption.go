package s3

import (
	"maps"
	"slices"

	"stackd/storage/memory"
)

func (w memoryWriter) ReplaceObjectEncryption(key ObjectVersionKey, algorithm, arn string, wrapped []byte, encryptionContext map[string]string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	return w.repository.objects.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		record, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		record.EncryptionAlgorithm, record.KMSKeyARN = algorithm, arn
		record.EncryptionKey, record.EncryptionContext = slices.Clone(wrapped), maps.Clone(encryptionContext)
		(*state)[key] = record
		return nil
	})
}
