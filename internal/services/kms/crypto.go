package kms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"strings"
	"unicode/utf8"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

var ciphertextMagic = []byte{'S', 'T', 'A', 'C', 'K', 'D', 'K', 'M', 'S', 2}

const materialIDLength = 64

func encryptionContext(in kmsapi.EncryptionContextType) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[string(k)] = string(v)
	}
	return out
}

func validateContext(in map[string]string) *awswire.Error {
	size := 0
	for k, v := range in {
		if k == "" || !utf8.ValidString(k) || !utf8.ValidString(v) {
			return failure("ValidationException", "Encryption context keys must not be empty and all context strings must be UTF-8.")
		}
		size += len(k) + len(v)
	}
	if size > 8192 {
		return failure("ValidationException", "Encryption context exceeds 8192 bytes.")
	}
	return nil
}

func associatedData(header []byte, context map[string]string) []byte {
	// encoding/json sorts string map keys, preserving case and exact UTF-8 bytes.
	if context == nil {
		context = map[string]string{}
	}
	encoded, _ := json.Marshal(context)
	data := make([]byte, 0, len(header)+len(encoded))
	data = append(data, header...)
	return append(data, encoded...)
}

func cipherFor(k *key, material *KeyMaterialRecord) (cipher.AEAD, *awswire.Error) {
	if k.Spec != "SYMMETRIC_DEFAULT" || k.Usage != "ENCRYPT_DECRYPT" {
		return nil, failure("InvalidKeyUsageException", "The key does not support symmetric encryption.")
	}
	block, err := aes.NewCipher(material.Material)
	if err != nil {
		return nil, failure("KMSInternalException", "Invalid stored key material.")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, failure("KMSInternalException", "Unable to initialize key encryption.")
	}
	return aead, nil
}

func prepareSymmetricEncryption(k *key, context map[string]string) (cipher.AEAD, *awswire.Error) {
	if err := usable(k); err != nil {
		return nil, err
	}
	if err := validateContext(context); err != nil {
		return nil, err
	}
	return cipherFor(k, k.currentMaterial())
}

func seal(k *key, plaintext []byte, context map[string]string) ([]byte, *awswire.Error) {
	aead, err := prepareSymmetricEncryption(k, context)
	if err != nil {
		return nil, err
	}
	return sealPrepared(aead, k.arn, k.currentMaterial().ID, plaintext, context)
}

func sealPrepared(aead cipher.AEAD, keyARN, materialID string, plaintext []byte, context map[string]string) ([]byte, *awswire.Error) {
	if len(plaintext) < 1 || len(plaintext) > 4096 {
		return nil, failure("ValidationException", "Plaintext must contain between 1 and 4096 bytes.")
	}
	header := append([]byte{}, ciphertextMagic...)
	header = binary.BigEndian.AppendUint16(header, uint16(len(keyARN)))
	header = append(header, keyARN...)
	header = append(header, materialID...)
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	out := append(append([]byte{}, header...), nonce...)
	return aead.Seal(out, nonce, plaintext, associatedData(header, context)), nil
}

func ciphertextKeyID(blob []byte) (string, int, *awswire.Error) {
	invalid := func() (string, int, *awswire.Error) {
		return "", 0, failure("InvalidCiphertextException", "The ciphertext is invalid.")
	}
	if len(blob) < len(ciphertextMagic)+2 || !bytes.Equal(blob[:len(ciphertextMagic)], ciphertextMagic) {
		return invalid()
	}
	length := int(binary.BigEndian.Uint16(blob[len(ciphertextMagic):]))
	end := len(ciphertextMagic) + 2 + length
	if length == 0 || end+materialIDLength > len(blob) {
		return invalid()
	}
	return string(blob[len(ciphertextMagic)+2 : end]), end + materialIDLength, nil
}

func (s *Service) openSymmetric(ctx context.Context, blob []byte, context map[string]string, expectedKeyID string) ([]byte, *key, *KeyMaterialRecord, *awswire.Error) {
	if err := validateContext(context); err != nil {
		return nil, nil, nil, err
	}
	id, end, err := ciphertextKeyID(blob)
	if err != nil {
		return nil, nil, nil, err
	}
	k, err := s.resolveCiphertextKey(ctx, id)
	if err != nil {
		return nil, nil, nil, err
	}
	if expectedKeyID != "" {
		if k.MultiRegion && strings.HasPrefix(expectedKeyID, "arn:") {
			parts := strings.SplitN(expectedKeyID, ":", 6)
			if len(parts) == 6 && parts[3] != scopeFor(ctx).region {
				return nil, nil, nil, failure("IncorrectKeyException", "The key must be in the current Region.")
			}
		}
		expected, err := s.resolve(ctx, expectedKeyID, true)
		if err != nil {
			return nil, nil, nil, err
		}
		if expected.arn != k.arn {
			return nil, nil, nil, failure("IncorrectKeyException", "The ciphertext was encrypted with a different KMS key.")
		}
	}
	authorizationID := k.arn
	if expectedKeyID != "" {
		authorizationID = expectedKeyID
	}
	err = s.authorizeResolvedKey(ctx, k, authorizationID)
	if err != nil {
		return nil, nil, nil, err
	}
	return openSymmetricMaterial(k, blob, context, end)
}

func openSymmetricMaterial(k *key, blob []byte, context map[string]string, end int) ([]byte, *key, *KeyMaterialRecord, *awswire.Error) {
	if err := usable(k); err != nil {
		return nil, nil, nil, err
	}
	materialID := string(blob[end-materialIDLength : end])
	var material *KeyMaterialRecord
	for i := range k.Materials {
		if k.Materials[i].ID == materialID {
			material = &k.Materials[i]
			break
		}
	}
	if material == nil {
		return nil, nil, nil, failure("InvalidCiphertextException", "The ciphertext is invalid.")
	}
	aead, err := cipherFor(k, material)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(blob) < end+aead.NonceSize()+aead.Overhead()+1 {
		return nil, nil, nil, failure("InvalidCiphertextException", "The ciphertext is invalid.")
	}
	nonce := blob[end : end+aead.NonceSize()]
	plaintext, openErr := aead.Open(nil, nonce, blob[end+aead.NonceSize():], associatedData(blob[:end], context))
	if openErr != nil {
		return nil, nil, nil, failure("InvalidCiphertextException", "The ciphertext or encryption context is invalid.")
	}
	return plaintext, k, material, nil
}

// Encrypt encrypts bytes with a scoped symmetric key and authenticated context.
func (s *Service) Encrypt(ctx context.Context, keyID string, plaintext []byte, encryption map[string]string) ([]byte, string, *awswire.Error) {
	input := &kmsapi.EncryptInput{KeyId: ptr(kmsapi.KeyIdType(keyID)), Plaintext: plaintext, EncryptionContext: internalEncryptionContext(encryption), EncryptionAlgorithm: ptr(kmsapi.EncryptionAlgorithmSpec("SYMMETRIC_DEFAULT"))}
	output, err := s.auditCommand(ctx, "Encrypt", input, func(ctx context.Context) (any, *awswire.Error) {
		return s.encryptOperation(ctx, input)
	})
	if err != nil {
		return nil, "", err
	}
	out := output.(*kmsapi.EncryptOutput)
	return out.CiphertextBlob, value(out.KeyId), nil
}

// Decrypt authenticates the ciphertext header and exact encryption context.
func (s *Service) Decrypt(ctx context.Context, ciphertext []byte, encryption map[string]string) ([]byte, string, *awswire.Error) {
	return s.DecryptWithKey(ctx, ciphertext, "", encryption)
}

// DecryptWithKey additionally binds decryption to a resource's configured key.
func (s *Service) DecryptWithKey(ctx context.Context, ciphertext []byte, keyID string, encryption map[string]string) ([]byte, string, *awswire.Error) {
	input := &kmsapi.DecryptInput{CiphertextBlob: ciphertext, EncryptionContext: internalEncryptionContext(encryption), EncryptionAlgorithm: ptr(kmsapi.EncryptionAlgorithmSpec("SYMMETRIC_DEFAULT"))}
	if keyID != "" {
		input.KeyId = ptr(kmsapi.KeyIdType(keyID))
	}
	var out *kmsapi.DecryptOutput
	_, err := s.auditCommand(ctx, "Decrypt", input, func(ctx context.Context) (any, *awswire.Error) {
		var err *awswire.Error
		out, err = s.decryptOperation(ctx, input)
		return out, err
	})
	if err != nil {
		if out != nil {
			clear(out.Plaintext)
		}
		return nil, "", err
	}
	return out.Plaintext, value(out.KeyId), nil
}

// GenerateDataKey creates a 256-bit data key for service envelope encryption.
// The plaintext is returned only to the caller; KMS retains only its master key.
func (s *Service) GenerateDataKey(ctx context.Context, keyID string, encryption map[string]string) ([]byte, []byte, string, *awswire.Error) {
	input := &kmsapi.GenerateDataKeyInput{KeyId: ptr(kmsapi.KeyIdType(keyID)), KeySpec: ptr(kmsapi.DataKeySpec("AES_256")), EncryptionContext: internalEncryptionContext(encryption)}
	var out *kmsapi.GenerateDataKeyOutput
	_, err := s.auditCommand(ctx, "GenerateDataKey", input, func(ctx context.Context) (any, *awswire.Error) {
		var err *awswire.Error
		out, err = s.generateDataKey(ctx, input)
		return out, err
	})
	if err != nil {
		if out != nil {
			clear(out.Plaintext)
		}
		return nil, nil, "", err
	}
	return out.Plaintext, out.CiphertextBlob, value(out.KeyId), nil
}

// GenerateDataKeyWithoutPlaintext returns an encrypted 256-bit data key using
// the public operation's authorization and transactional audit behavior.
func (s *Service) GenerateDataKeyWithoutPlaintext(ctx context.Context, keyID string, encryption map[string]string) ([]byte, string, *awswire.Error) {
	input := &kmsapi.GenerateDataKeyWithoutPlaintextInput{KeyId: ptr(kmsapi.KeyIdType(keyID)), KeySpec: ptr(kmsapi.DataKeySpec("AES_256")), EncryptionContext: internalEncryptionContext(encryption)}
	output, err := s.auditCommand(ctx, "GenerateDataKeyWithoutPlaintext", input, func(ctx context.Context) (any, *awswire.Error) {
		return s.generateDataKeyWithoutPlaintext(ctx, input)
	})
	if err != nil {
		return nil, "", err
	}
	out := output.(*kmsapi.GenerateDataKeyWithoutPlaintextOutput)
	return out.CiphertextBlob, value(out.KeyId), nil
}

// ReEncrypt rewraps ciphertext and its authenticated context, enforcing
// ReEncryptFrom and ReEncryptTo through the public command.
func (s *Service) ReEncrypt(ctx context.Context, ciphertext []byte, destination string, sourceContext, destinationContext map[string]string) ([]byte, *awswire.Error) {
	input := &kmsapi.ReEncryptInput{CiphertextBlob: ciphertext, DestinationKeyId: ptr(kmsapi.KeyIdType(destination)),
		SourceEncryptionContext: internalEncryptionContext(sourceContext), DestinationEncryptionContext: internalEncryptionContext(destinationContext)}
	output, err := s.auditCommand(ctx, "ReEncrypt", input, func(ctx context.Context) (any, *awswire.Error) {
		return s.reEncrypt(ctx, input)
	})
	if err != nil {
		return nil, err
	}
	return output.(*kmsapi.ReEncryptOutput).CiphertextBlob, nil
}

// ReEncryptToService removes the customer-key wrapping at the service-owned
// storage boundary. It enforces the source half of ReEncrypt, not Decrypt.
// AWS-owned keys are outside the customer's KMS catalog; this emulator's
// service-owned storage is not represented by a fabricated customer key ARN.
func (s *Service) ReEncryptToService(ctx context.Context, ciphertext []byte, encryption map[string]string) ([]byte, *awswire.Error) {
	input := &kmsapi.ReEncryptInput{CiphertextBlob: ciphertext, SourceEncryptionContext: internalEncryptionContext(encryption)}
	var plaintext []byte
	_, rejected := s.auditCommand(ctx, "ReEncrypt", input, func(ctx context.Context) (any, *awswire.Error) {
		var source *key
		var material *KeyMaterialRecord
		var err *awswire.Error
		plaintext, source, material, err = s.open(withReEncryptAction(ctx, "ReEncryptFrom", encryption, "SYMMETRIC_DEFAULT", ""), ciphertext, encryption, "", "SYMMETRIC_DEFAULT")
		if err != nil {
			return nil, err
		}
		return &kmsapi.ReEncryptOutput{SourceKeyId: ptr(kmsapi.KeyIdType(source.arn)), SourceKeyMaterialId: keyMaterialID(source, material)}, nil
	})
	if rejected != nil {
		clear(plaintext)
		return nil, rejected
	}
	return plaintext, nil
}

func internalEncryptionContext(values map[string]string) kmsapi.EncryptionContextType {
	if values == nil {
		return nil
	}
	out := make(kmsapi.EncryptionContextType, len(values))
	for k, v := range values {
		out[kmsapi.EncryptionContextKey(k)] = kmsapi.EncryptionContextValue(v)
	}
	return out
}

func (s *Service) dataKey(ctx context.Context, keyID string, encryption map[string]string, size int) ([]byte, []byte, *key, *awswire.Error) {
	k, err := s.resolveAuthorized(ctx, keyID, true)
	if err != nil {
		return nil, nil, nil, err
	}
	if size < 1 || size > 1024 {
		return nil, nil, nil, failure("ValidationException", "NumberOfBytes must be between 1 and 1024.")
	}
	plaintext := make([]byte, size)
	_, _ = rand.Read(plaintext)
	blob, err := seal(k, plaintext, encryption)
	if err != nil {
		clear(plaintext)
		return nil, nil, nil, err
	}
	return plaintext, blob, k, nil
}

// Ciphertext keeps its authenticated original ARN, but related multi-Region
// keys decrypt locally using the replica in the request's Region.
func (s *Service) resolveCiphertextKey(ctx context.Context, arn string) (*key, *awswire.Error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && strings.HasPrefix(parts[5], "key/mrk-") {
		parts[3] = scopeFor(ctx).region
		arn = strings.Join(parts, ":")
	}
	return s.resolve(ctx, arn, false)
}
