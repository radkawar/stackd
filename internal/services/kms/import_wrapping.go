package kms

import (
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"slices"
	"strings"

	"stackd/internal/awswire"
)

func importWrapping(spec, algorithm, wrappingSpec string) (int, *awswire.Error) {
	bits := rsaBits(wrappingSpec)
	if bits == 0 {
		return 0, failure("UnsupportedOperationException", "This wrapping key specification is not supported.")
	}
	switch algorithm {
	case "RSAES_OAEP_SHA_1", "RSA_AES_KEY_WRAP_SHA_1", "RSAES_OAEP_SHA_256", "RSA_AES_KEY_WRAP_SHA_256":
	default:
		return 0, failure("ValidationException", "The wrapping algorithm is not supported.")
	}
	hybrid := strings.HasPrefix(algorithm, "RSA_AES_")
	if hybrid && !asymmetricSpec(spec) || !hybrid && rsaBits(spec) != 0 || !hybrid && (spec == "ECC_NIST_P521" || spec == "ECC_NIST_EDWARDS25519") && bits == 2048 {
		return 0, failure("ValidationException", "The wrapping algorithm and key specification are incompatible with this key material.")
	}
	return bits, nil
}

func unwrapImport(private *rsa.PrivateKey, algorithm string, ciphertext []byte) ([]byte, *awswire.Error) {
	hash := crypto.SHA256
	if strings.HasSuffix(algorithm, "SHA_1") {
		hash = crypto.SHA1
	}
	if !strings.HasPrefix(algorithm, "RSA_AES_") {
		plain, err := rsa.DecryptOAEP(hash.New(), rand.Reader, private, ciphertext, nil)
		if err != nil {
			return nil, invalidImportCiphertext()
		}
		return plain, nil
	}
	if len(ciphertext) <= private.Size() {
		return nil, invalidImportCiphertext()
	}
	kek, err := rsa.DecryptOAEP(hash.New(), rand.Reader, private, ciphertext[:private.Size()], nil)
	if err != nil {
		return nil, invalidImportCiphertext()
	}
	defer clear(kek)
	if len(kek) != 32 {
		return nil, invalidImportCiphertext()
	}
	return unwrapAESKey(kek, ciphertext[private.Size():])
}

// unwrapAESKey implements RFC 5649, used by KMS's RSA_AES wrapping algorithms.
// Integrity, encoded length and zero padding are verified before returning any
// plaintext material to ImportKeyMaterial.
func unwrapAESKey(kek, ciphertext []byte) ([]byte, *awswire.Error) {
	if len(ciphertext) < 16 || len(ciphertext)%8 != 0 {
		return nil, invalidImportCiphertext()
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, invalidImportCiphertext()
	}
	plain := slices.Clone(ciphertext)
	n := len(plain)/8 - 1
	if n == 1 {
		block.Decrypt(plain, plain)
	} else {
		var buffer [16]byte
		defer clear(buffer[:])
		for j := 5; j >= 0; j-- {
			for i := n; i >= 1; i-- {
				binary.BigEndian.PutUint64(buffer[:8], binary.BigEndian.Uint64(plain[:8])^uint64(n*j+i))
				copy(buffer[8:], plain[i*8:(i+1)*8])
				block.Decrypt(buffer[:], buffer[:])
				copy(plain[:8], buffer[:8])
				copy(plain[i*8:(i+1)*8], buffer[8:])
			}
		}
	}
	length := uint64(binary.BigEndian.Uint32(plain[4:8]))
	valid := subtle.ConstantTimeCompare(plain[:4], []byte{0xa6, 0x59, 0x59, 0xa6})
	if length <= uint64((n-1)*8) || length > uint64(n*8) {
		clear(plain)
		return nil, invalidImportCiphertext()
	}
	for _, pad := range plain[8+int(length):] {
		valid &= subtle.ConstantTimeByteEq(pad, 0)
	}
	if valid != 1 {
		clear(plain)
		return nil, invalidImportCiphertext()
	}
	return plain[8 : 8+int(length)], nil
}

func invalidImportCiphertext() *awswire.Error {
	return failure("InvalidCiphertextException", "The encrypted key material is invalid.")
}
