package ecr

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"

	"stackd/internal/awswire"
)

// DataKeys uses the existing KMS owner, including its current policies, key
// state and grants. Calls join the repository's transaction through ctx; they
// must not perform network or native-engine effects. No plaintext KMS data key
// may be retained in repository state or cached between commands.
type DataKeys interface {
	Provision(context.Context, RepositoryKey, string) (KeyMaterial, *awswire.Error)
	Generate(context.Context, RepositoryRecord, string) (KeyMaterial, *awswire.Error)
	Decrypt(context.Context, RepositoryRecord, string, []byte) ([]byte, *awswire.Error)
	Retire(context.Context, RepositoryRecord) *awswire.Error
}

// KeyMaterial contains either repository grants from Provision or a fresh
// per-payload data key from Generate. Clear Plaintext after use; only Wrapped
// belongs in the payload. GrantTokens are never public ECR response fields.
type KeyMaterial struct {
	KeyID               string
	Grants, GrantTokens []string
	Plaintext, Wrapped  []byte
}

func encryptionFailure(rejected *awswire.Error) *awswire.Error {
	code, _ := json.Marshal(rejected.Code)
	return &awswire.Error{
		Code: "KmsException", Message: rejected.Message, StatusCode: 400,
		Details: map[string]json.RawMessage{"kmsError": code}, Cause: rejected,
	}
}

func (s *Service) prepareRepositoryEncryption(ctx context.Context, repo RepositoryRecord, keyID string) (RepositoryRecord, error) {
	if repo.EncryptionType == "" {
		repo.EncryptionType = "AES256"
	}
	switch repo.EncryptionType {
	case "AES256":
		if keyID != "" {
			return RepositoryRecord{}, failure("InvalidParameterException", "A KMS key can only be specified with KMS encryption.")
		}
		repo.DataKey = make([]byte, 32)
		if _, err := rand.Read(repo.DataKey); err != nil {
			clear(repo.DataKey)
			return RepositoryRecord{}, failure("ServerException", "Unable to generate the repository encryption key.")
		}
		repo.KMSKeyID, repo.Grants, repo.GrantTokens = "", nil, nil
	case "KMS":
		if s.keys == nil {
			return RepositoryRecord{}, failure("ServerException", "ECR KMS encryption is not configured.")
		}
		material, rejected := s.keys.Provision(ctx, repo.Key, keyID)
		if rejected != nil {
			return RepositoryRecord{}, encryptionFailure(rejected)
		}
		if material.KeyID == "" || len(material.Grants) != 2 || len(material.GrantTokens) != 2 {
			return RepositoryRecord{}, failure("ServerException", "KMS returned invalid repository encryption material.")
		}
		repo.KMSKeyID = material.KeyID
		repo.Grants, repo.GrantTokens, repo.DataKey = material.Grants, material.GrantTokens, nil
	default:
		return RepositoryRecord{}, failure("InvalidParameterException", "Unsupported repository encryption type.")
	}
	return repo, nil
}

func (s *Service) retireRepositoryEncryption(ctx context.Context, repo RepositoryRecord) error {
	if repo.EncryptionType == "AES256" {
		return nil
	}
	if s.keys == nil {
		return failure("ServerException", "ECR KMS encryption is not configured.")
	}
	if rejected := s.keys.Retire(ctx, repo); rejected != nil {
		return encryptionFailure(rejected)
	}
	return nil
}

func payloadCipher(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, failure("ServerException", "Invalid payload encryption key.")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// KMS payloads retain a uint32 wrapped-key length followed by the wrapped key
// and AES-GCM nonce/ciphertext. Each write generates a new data key; each read
// decrypts that payload's key under current KMS policy and grant authority.
// AES256 payloads retain only nonce/ciphertext under the service-managed key.
// Associated data binds both modes to repository scope and object identity.
const maxPayloadWrappedKeySize = 6144

func (s *Service) sealPayload(ctx context.Context, repo RepositoryRecord, identity string, plain []byte) ([]byte, error) {
	key := repo.DataKey
	var wrapped []byte
	switch repo.EncryptionType {
	case "AES256":
	case "KMS":
		if s.keys == nil {
			return nil, failure("ServerException", "ECR KMS encryption is not configured.")
		}
		material, rejected := s.keys.Generate(ctx, repo, identity)
		defer clear(material.Plaintext)
		if rejected != nil {
			return nil, encryptionFailure(rejected)
		}
		if len(material.Wrapped) == 0 || len(material.Wrapped) > maxPayloadWrappedKeySize {
			return nil, failure("ServerException", "KMS returned an invalid wrapped payload key.")
		}
		key, wrapped = material.Plaintext, material.Wrapped
	default:
		return nil, failure("ServerException", "Invalid stored repository encryption type.")
	}
	aead, err := payloadCipher(key)
	if err != nil {
		return nil, err
	}
	headerSize := 0
	if len(wrapped) != 0 {
		headerSize = 4 + len(wrapped)
	}
	envelope := make([]byte, headerSize+aead.NonceSize(), headerSize+aead.NonceSize()+len(plain)+aead.Overhead())
	if headerSize != 0 {
		binary.BigEndian.PutUint32(envelope, uint32(len(wrapped)))
		copy(envelope[4:], wrapped)
	}
	nonce := envelope[headerSize:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(envelope, nonce, plain, payloadAAD(repo.Key, identity)), nil
}

func (s *Service) openPayload(ctx context.Context, repo RepositoryRecord, identity string, encrypted []byte) ([]byte, error) {
	key := repo.DataKey
	switch repo.EncryptionType {
	case "AES256":
	case "KMS":
		if s.keys == nil {
			return nil, failure("ServerException", "ECR KMS encryption is not configured.")
		}
		if len(encrypted) < 4 {
			return nil, errors.New("truncated ECR payload key envelope")
		}
		size := int(binary.BigEndian.Uint32(encrypted[:4]))
		if size == 0 || size > maxPayloadWrappedKeySize || size > len(encrypted)-4 {
			return nil, errors.New("invalid ECR payload key envelope")
		}
		var rejected *awswire.Error
		key, rejected = s.keys.Decrypt(ctx, repo, identity, encrypted[4:4+size])
		defer clear(key)
		if rejected != nil {
			return nil, encryptionFailure(rejected)
		}
		encrypted = encrypted[4+size:]
	default:
		return nil, failure("ServerException", "Invalid stored repository encryption type.")
	}
	aead, err := payloadCipher(key)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("truncated encrypted ECR payload")
	}
	return aead.Open(nil, encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():], payloadAAD(repo.Key, identity))
}

func payloadAAD(key RepositoryKey, identity string) []byte {
	return []byte(repositoryARN(key) + "\x00" + identity)
}
