// Package s3tablescrypt owns the local SSE-S3 boundary for private warehouse bytes.
// Like ordinary S3 SSE-S3, each encrypted value retains a random local 32-byte key.
package s3tablescrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const Algorithm = "AES256-GCM"
const Version int64 = 1

var ErrEnvelope = errors.New("invalid S3 Tables encrypted bytes")

// Envelope contains ciphertext only; plaintext is never retained in storage state.
type Envelope struct {
	Version   int64
	Algorithm string
	Key       []byte
	Nonce     []byte
	Data      []byte
}

// Legacy is only meaningful inside the eager, atomic SQLite migration. Reads
// never accept this marker and partially populated envelopes are never legacy.
func (e Envelope) Legacy() bool {
	return e.Version == 0 && e.Algorithm == "" && len(e.Key) == 0 && len(e.Nonce) == 0
}

func identity(kind, warehouse, key, upload string, number int64) []byte {
	out := make([]byte, 0, 8*5+len(kind)+len(warehouse)+len(key)+len(upload))
	for _, field := range []string{kind, warehouse, key, upload} {
		out = binary.BigEndian.AppendUint64(out, uint64(len(field)))
		out = append(out, field...)
	}
	return binary.BigEndian.AppendUint64(out, uint64(number))
}

func ObjectIdentity(warehouse, key string) []byte {
	return identity("s3tables/object/v1", warehouse, key, "", 0)
}

func PartIdentity(warehouse, key, upload string, number int64) []byte {
	return identity("s3tables/part/v1", warehouse, key, upload, number)
}

func Seal(data, aad []byte) (Envelope, error) {
	e := Envelope{Version: Version, Algorithm: Algorithm, Key: make([]byte, 32)}
	if _, err := rand.Read(e.Key); err != nil {
		return Envelope{}, err
	}
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return Envelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	e.Nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(e.Nonce); err != nil {
		return Envelope{}, err
	}
	e.Data = gcm.Seal(nil, e.Nonce, data, aad)
	return e, nil
}

// Open appends authenticated plaintext to a transient buffer, never to persisted
// ciphertext. Completion supplies one pre-sized buffer shared by all selected parts.
func (e Envelope) Open(dst, aad []byte, size int64) ([]byte, error) {
	if e.Version != Version || e.Algorithm != Algorithm || len(e.Key) != 32 {
		return nil, ErrEnvelope
	}
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, ErrEnvelope
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(e.Nonce) != gcm.NonceSize() || len(e.Data) < gcm.Overhead() || int64(len(e.Data)-gcm.Overhead()) != size {
		return nil, ErrEnvelope
	}
	plain, err := gcm.Open(dst, e.Nonce, e.Data, aad)
	if err != nil {
		return nil, ErrEnvelope
	}
	return plain, nil
}
