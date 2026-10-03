package kinesis

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	engine "stackd/engine/kinesis"
	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
)

// EncryptionKeys is the consumer-owned KMS boundary. Generate is producer-only;
// decrypt is reader-only. Implementations must preserve the forwarded caller.
type EncryptionKeys interface {
	ResolveKey(context.Context, StreamKey, string) (string, *awswire.Error)
	GenerateDataKey(context.Context, StreamKey, string) ([]byte, []byte, string, *awswire.Error)
	Decrypt(context.Context, StreamKey, []byte) ([]byte, string, *awswire.Error)
}

// Header v1: version, ARN length (uint16), wrapped-key length (uint32), nonce
// (12 bytes), canonical key ARN, KMS ciphertext. No plaintext key is persisted.
const encryptionHeaderSize = 19
const encryptionTagSize = 16

// recordPlaintextSize follows the stored GCM envelope without decrypting records
// outside the requested page. The nonce and wrapped key live in Metadata.
func recordPlaintextSize(record *engine.Record) int {
	size := len(record.Data)
	if len(record.Metadata) != 0 {
		size -= encryptionTagSize
	}
	return size
}

func recordCipher(key *encryptionMaterial) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key.plain[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithTagSize(block, encryptionTagSize)
}

func invalidEncryption() error {
	return failure("KMSInvalidStateException", "The encrypted record or data key is invalid.")
}

func (s *Service) encryptionKey(ctx context.Context, stream StreamRecord, slot encryptionSlot, wrapped []byte) (encryptionMaterial, error) {
	if err := ctx.Err(); err != nil {
		return encryptionMaterial{}, err
	}
	if key, ok := s.encryption.get(ctx, slot, s.clock.Now()); ok {
		return key, nil
	}
	if s.keys == nil {
		return encryptionMaterial{}, failure("KMSNotFoundException", "The KMS provider is unavailable.")
	}
	var plain, ciphertext []byte
	var arn string
	var rejected *awswire.Error
	if slot.decrypt {
		plain, arn, rejected = s.keys.Decrypt(ctx, stream.Key, wrapped)
	} else {
		plain, ciphertext, arn, rejected = s.keys.GenerateDataKey(ctx, stream.Key, slot.key)
	}
	defer clear(plain)
	if rejected != nil {
		return encryptionMaterial{}, rejected
	}
	if err := ctx.Err(); err != nil {
		return encryptionMaterial{}, err
	}
	if len(plain) != 32 || arn == "" || len(arn) > 2048 || (slot.decrypt && arn != slot.key) || (!slot.decrypt && (len(ciphertext) == 0 || len(ciphertext) > 65536)) {
		return encryptionMaterial{}, invalidEncryption()
	}
	key := encryptionMaterial{arn: arn, wrapped: ciphertext, expires: s.clock.Now().Add(dataKeyReuse)}
	copy(key.plain[:], plain)
	s.encryption.put(ctx, slot, key, s.clock.Now())
	return key, nil
}

func (s *Service) encryptRecords(ctx context.Context, stream StreamRecord, records []engine.Record) error {
	if len(records) == 0 || value(stream.Data.EncryptionType) != string(api.EncryptionTypeKMS) {
		return ctx.Err()
	}
	ctx, done := s.encryption.operation(ctx)
	defer done()
	slot := encryptionSlot{stream: stream.Key.ARN(), incarnation: stream.EngineID, key: value(stream.Data.KeyId), requester: encryptionRequester(ctx)}
	defer func() {
		if ctx.Err() != nil {
			s.encryption.drop(slot)
		}
	}()
	key, err := s.encryptionKey(ctx, stream, slot, nil)
	if err != nil {
		return err
	}
	defer clear(key.plain[:])
	aead, err := recordCipher(&key)
	if err != nil {
		return err
	}
	for i := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		metadata := make([]byte, encryptionHeaderSize+len(key.arn)+len(key.wrapped))
		metadata[0] = 1
		binary.BigEndian.PutUint16(metadata[1:3], uint16(len(key.arn)))
		binary.BigEndian.PutUint32(metadata[3:7], uint32(len(key.wrapped)))
		nonce := metadata[7:encryptionHeaderSize]
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		copy(metadata[encryptionHeaderSize:], key.arn)
		copy(metadata[encryptionHeaderSize+len(key.arn):], key.wrapped)
		records[i].Data = aead.Seal(nil, nonce, records[i].Data, metadata)
		records[i].Metadata = metadata
	}
	return ctx.Err()
}

func (s *Service) decryptRecords(ctx context.Context, stream StreamRecord, records []engine.Record) error {
	ctx, done := s.encryption.operation(ctx)
	defer done()
	requester := encryptionRequester(ctx)
	defer func() {
		if ctx.Err() != nil {
			s.encryption.dropRequester(stream, requester)
		}
	}()
	for i := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Historical plaintext is independent of the current stream setting.
		if len(records[i].Metadata) == 0 {
			continue
		}
		if err := s.decryptRecord(ctx, stream, requester, &records[i]); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (s *Service) decryptRecord(ctx context.Context, stream StreamRecord, requester [32]byte, record *engine.Record) error {
	metadata := record.Metadata
	if len(metadata) < encryptionHeaderSize || metadata[0] != 1 {
		return invalidEncryption()
	}
	arnSize := int(binary.BigEndian.Uint16(metadata[1:3]))
	wrappedSize := int(binary.BigEndian.Uint32(metadata[3:7]))
	if arnSize == 0 || arnSize > 2048 || wrappedSize == 0 || wrappedSize > 65536 || len(metadata) != encryptionHeaderSize+arnSize+wrappedSize {
		return invalidEncryption()
	}
	arn := string(metadata[encryptionHeaderSize : encryptionHeaderSize+arnSize])
	wrapped := metadata[encryptionHeaderSize+arnSize:]
	slot := encryptionSlot{stream: stream.Key.ARN(), incarnation: stream.EngineID, key: arn, requester: requester, wrapped: sha256.Sum256(wrapped), decrypt: true}
	defer func() {
		if ctx.Err() != nil {
			s.encryption.drop(slot)
		}
	}()
	key, err := s.encryptionKey(ctx, stream, slot, wrapped)
	if err != nil {
		return err
	}
	defer clear(key.plain[:])
	aead, err := recordCipher(&key)
	if err != nil {
		return err
	}
	plain, err := aead.Open(nil, metadata[7:encryptionHeaderSize], record.Data, metadata)
	if err != nil {
		return invalidEncryption()
	}
	if err := ctx.Err(); err != nil {
		clear(plain)
		return err
	}
	record.Data = plain
	// Keep Metadata so callers can report the record's actual EncryptionType,
	// even after StopStreamEncryption or a change to a different customer key.
	return nil
}
