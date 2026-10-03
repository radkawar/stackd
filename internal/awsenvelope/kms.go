// Package awsenvelope implements the committing, framed AWS Encryption SDK
// envelope used by service-owned KMS data-key consumers.
package awsenvelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// FrameLength is the maximum plaintext size of a regular envelope frame.
const FrameLength = 4096

var errInvalid = errors.New("invalid encrypted AWS message")

func busMessageKeys(key, id []byte, suite uint16) (cipher.AEAD, []byte, error) {
	if len(key) != 32 {
		return nil, nil, errInvalid
	}
	info := [11]byte{byte(suite >> 8), byte(suite), 'D', 'E', 'R', 'I', 'V', 'E', 'K', 'E', 'Y'}
	derived, err := hkdf.Key(sha512.New, key, id, string(info[:]), 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(derived)
	commitment, err := hkdf.Key(sha512.New, key, id, "COMMITKEY", 32)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, commitment, err
}

func appendBusField(out, field []byte) []byte {
	out = binary.BigEndian.AppendUint16(out, uint16(len(field)))
	return append(out, field...)
}

func busFrameAAD(id []byte, sequence uint32, size int, final bool) []byte {
	label := "AWSKMSEncryptionClient Frame"
	if final {
		label = "AWSKMSEncryptionClient Final Frame"
	}
	aad := append([]byte(nil), id...)
	aad = append(aad, label...)
	aad = binary.BigEndian.AppendUint32(aad, sequence)
	return binary.BigEndian.AppendUint64(aad, uint64(size))
}

// Seal emits one KMS encrypted data key and the exact authenticated context.
// The envelope uses the unsigned committing suite (0x0478).
func Seal(key, wrapped []byte, keyARN string, context map[string]string, plaintext []byte) ([]byte, error) {
	return seal(key, wrapped, keyARN, context, plaintext, nil)
}

func seal(key, wrapped []byte, keyARN string, encryptionContext map[string]string, plaintext []byte, signer *Signer) ([]byte, error) {
	if len(key) != 32 || len(wrapped) > maxFieldLength || len(keyARN) > maxFieldLength || uint64(len(plaintext))/FrameLength >= uint64(^uint32(0)) {
		return nil, errInvalid
	}
	suite := unsignedSuite
	publicKey := ""
	if signer != nil {
		suite = signedSuite
		publicKey = signer.PublicKey()
	}
	context, err := marshalContext(encryptionContext, publicKey)
	if err != nil {
		return nil, err
	}
	var id [32]byte
	_, _ = rand.Read(id[:])
	aead, commitment, err := busMessageKeys(key, id[:], suite)
	if err != nil {
		return nil, err
	}
	regularFrames := 0
	if len(plaintext) > 0 {
		regularFrames = (len(plaintext) - 1) / FrameLength
	}
	// Header, final frame and regular-frame overhead, plus the signed footer.
	capacity := len(plaintext) + len(wrapped) + len(context) + len(keyARN) + 145 + regularFrames*32
	if signer != nil {
		capacity += 105
	}
	out := make([]byte, 0, capacity)
	out = append(out, 2, byte(suite>>8), byte(suite))
	out = append(out, id[:]...)
	out = appendBusField(out, context)
	out = append(out, 0, 1) // one encrypted KMS data key
	out = appendBusField(out, []byte("aws-kms"))
	out = appendBusField(out, []byte(keyARN))
	out = appendBusField(out, wrapped)
	out = append(out, 2) // framed content
	out = binary.BigEndian.AppendUint32(out, FrameLength)
	out = append(out, commitment...)
	var nonce [12]byte
	tag := aead.Seal(nil, nonce[:], nil, out)
	out = append(out, tag...)
	for sequence := uint32(1); ; sequence++ {
		size := min(len(plaintext), FrameLength)
		final := size == len(plaintext)
		if final {
			out = binary.BigEndian.AppendUint32(out, ^uint32(0))
		}
		out = binary.BigEndian.AppendUint32(out, sequence)
		binary.BigEndian.PutUint32(nonce[8:], sequence)
		out = append(out, nonce[:]...)
		if final {
			out = binary.BigEndian.AppendUint32(out, uint32(size))
		}
		out = aead.Seal(out, nonce[:], plaintext[:size], busFrameAAD(id[:], sequence, size, final))
		plaintext = plaintext[size:]
		if final {
			if signer != nil {
				signature, err := signer.sign(out)
				if err != nil {
					return nil, err
				}
				out = appendBusField(out, signature)
			}
			return out, nil
		}
	}
}

// Open accepts the one-key unsigned or signed committing envelopes emitted by
// Seal and Signer.Seal. It authenticates the complete message before returning
// any plaintext, and is deliberately not a general AWS Encryption SDK parser.
func Open(key, wrapped []byte, keyARN string, expected map[string]string, payload []byte) ([]byte, error) {
	invalid := errInvalid
	suite, position, _, verifier, err := parseContext(payload, expected)
	if err != nil || len(key) != 32 {
		return nil, invalid
	}
	id := payload[3:35]
	field := func() ([]byte, bool) { return readField(payload, &position) }
	if len(payload)-position < 2 || binary.BigEndian.Uint16(payload[position:]) != 1 {
		return nil, invalid
	}
	position += 2
	provider, ok := field()
	if !ok || string(provider) != "aws-kms" {
		return nil, invalid
	}
	arn, ok := field()
	if !ok || string(arn) != keyARN {
		return nil, invalid
	}
	edk, ok := field()
	if !ok || !bytes.Equal(edk, wrapped) {
		return nil, invalid
	}
	if len(payload)-position < 53 || payload[position] != 2 || binary.BigEndian.Uint32(payload[position+1:]) != FrameLength {
		return nil, invalid
	}
	position += 5
	aead, commitment, err := busMessageKeys(key, id, suite)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(payload[position:position+32], commitment) != 1 {
		return nil, invalid
	}
	position += 32
	var nonce [12]byte
	if _, err := aead.Open(nil, nonce[:], payload[position:position+16], payload[:position]); err != nil {
		return nil, err
	}
	position += 16
	plaintext := make([]byte, 0, len(payload)-position)
	authenticated := false
	defer func() {
		if !authenticated {
			clear(plaintext)
		}
	}()
	for sequence := uint32(1); ; sequence++ {
		if len(payload)-position < 4 {
			return nil, invalid
		}
		marker := binary.BigEndian.Uint32(payload[position:])
		position += 4
		final := marker == ^uint32(0)
		if final {
			if len(payload)-position < 4 {
				return nil, invalid
			}
			marker = binary.BigEndian.Uint32(payload[position:])
			position += 4
		}
		if marker != sequence || len(payload)-position < 12 {
			return nil, invalid
		}
		binary.BigEndian.PutUint32(nonce[8:], sequence)
		if !bytes.Equal(payload[position:position+12], nonce[:]) {
			return nil, invalid
		}
		position += 12
		size := FrameLength
		if final {
			if len(payload)-position < 4 {
				return nil, invalid
			}
			frameSize := binary.BigEndian.Uint32(payload[position:])
			if frameSize > FrameLength {
				return nil, invalid
			}
			size = int(frameSize)
			position += 4
		}
		if len(payload)-position < size+16 {
			return nil, invalid
		}
		opened, err := aead.Open(plaintext, nonce[:], payload[position:position+size+16], busFrameAAD(id, sequence, size, final))
		if err != nil {
			return nil, err
		}
		plaintext = opened
		position += size + 16
		if final {
			if verifier != nil {
				signedEnd := position
				signature, ok := field()
				if !ok {
					return nil, invalid
				}
				digest := sha512.Sum384(payload[:signedEnd])
				if !ecdsa.VerifyASN1(verifier, digest[:], signature) {
					return nil, invalid
				}
			}
			if position != len(payload) {
				return nil, invalid
			}
			authenticated = true
			return plaintext, nil
		}
		if sequence == ^uint32(0) {
			return nil, invalid
		}
	}
}
