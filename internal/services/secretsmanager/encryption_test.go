package secretsmanager

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"stackd/internal/awswire"
)

// The spy observes clearing at the data-key boundary. Real KMS authorization,
// envelopes, version rotation and historical-key denial are integration-tested.
type requiredKeyDataKeys struct {
	DataKeys
	plain  []byte
	arn    string
	denied *awswire.Error
}

func (k *requiredKeyDataKeys) Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error) {
	return k.plain, k.arn, k.denied
}

type requiredKeyReader struct {
	Reader
	ctx    context.Context
	values []SealedValue
}

func (r requiredKeyReader) Context() context.Context { return r.ctx }
func (r requiredKeyReader) EncryptedVersion(VersionKey) ([]SealedValue, error) {
	return r.values, nil
}

func TestRequiredKMSKeyConstrainsActualDecryptIdentity(t *testing.T) {
	const oldKey = "arn:aws:kms:us-east-1:111111111111:key/old"
	const currentKey = "arn:aws:kms:us-east-1:111111111111:key/current"
	plainKey := bytes.Repeat([]byte{0x45}, 32)
	block, err := aes.NewCipher(plainKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("current secret version")
	nonce := make([]byte, aead.NonceSize())
	payload := aead.Seal(nonce, nonce, value, nil)
	for _, test := range []struct {
		name          string
		ctx           context.Context
		actualKey     string
		decryptDenied bool
		wantDenied    bool
	}{
		{"public historical fallback", context.Background(), oldKey, false, false},
		{"matching canonical key", WithRequiredKMSKey(context.Background(), currentKey), currentKey, false, false},
		{"old key cannot impersonate current metadata", WithRequiredKMSKey(context.Background(), currentKey), oldKey, false, true},
		{"missing required key fails closed", WithRequiredKMSKey(context.Background(), ""), oldKey, false, true},
		{"failed decrypt clears returned key", WithRequiredKMSKey(context.Background(), currentKey), currentKey, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			keys := &requiredKeyDataKeys{plain: bytes.Clone(plainKey), arn: test.actualKey}
			if test.decryptDenied {
				keys.denied = &awswire.Error{Code: "AccessDeniedException", Message: "Decryption is not allowed."}
			}
			s := &Service{keys: keys}
			r := requiredKeyReader{ctx: test.ctx, values: []SealedValue{{KeyID: currentKey, Payload: payload}}}
			got, err := s.openVersion(r, SecretRecord{}, VersionRecord{})
			if test.wantDenied {
				var denied *awswire.Error
				if !errors.As(err, &denied) || denied.Code != "AccessDeniedException" || len(got) != 0 {
					t.Fatalf("mismatched actual key returned plaintext: %q, %v", got, err)
				}
			} else if err != nil || !bytes.Equal(got, value) {
				t.Fatalf("authorized envelope did not decrypt: %q, %v", got, err)
			}
			var cleared [32]byte
			if !bytes.Equal(keys.plain, cleared[:]) {
				t.Fatal("plaintext data key was not cleared")
			}
		})
	}
	clear(plainKey)
}
