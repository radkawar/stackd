package awsenvelope

import (
	"crypto/ecdsa"
	"encoding/binary"
	"slices"
	"unicode/utf8"
)

const (
	unsignedSuite  uint16 = 0x0478
	signedSuite    uint16 = 0x0578
	maxFieldLength        = 1<<16 - 1
)

func readField(payload []byte, position *int) ([]byte, bool) {
	if len(payload)-*position < 2 {
		return nil, false
	}
	size := int(binary.BigEndian.Uint16(payload[*position:]))
	*position += 2
	if size > len(payload)-*position {
		return nil, false
	}
	value := payload[*position : *position+size]
	*position += size
	return value, true
}

func contextSize(context map[string]string, signed bool) (int, error) {
	size := 2
	if signed {
		size += 4 + len(signingContextKey) + 68
	}
	for key, value := range context {
		if key == signingContextKey || !utf8.ValidString(key) || !utf8.ValidString(value) || len(key) > maxFieldLength || len(value) > maxFieldLength {
			return 0, errInvalid
		}
		size += 4 + len(key) + len(value)
		if size > maxFieldLength {
			return 0, errInvalid
		}
	}
	return size, nil
}

func marshalContext(context map[string]string, publicKey string) ([]byte, error) {
	size, err := contextSize(context, publicKey != "")
	if err != nil {
		return nil, err
	}
	count := len(context)
	if publicKey != "" {
		count++
	}
	keys := make([]string, 0, count)
	for key := range context {
		keys = append(keys, key)
	}
	if publicKey != "" {
		keys = append(keys, signingContextKey)
	}
	slices.Sort(keys)
	out := make([]byte, 2, size)
	binary.BigEndian.PutUint16(out, uint16(count))
	for _, key := range keys {
		value := context[key]
		if key == signingContextKey {
			value = publicKey
		}
		out = appendBusField(out, []byte(key))
		out = appendBusField(out, []byte(value))
	}
	return out, nil
}

// EncryptionContext extracts the exact expected context and, for signed
// messages, the signing public key for KMS Decrypt. These values are untrusted
// until Open authenticates the complete message. Expected excludes the reserved
// signing key. Extra, duplicate, substituted, unsorted and malformed entries are
// rejected, and the caller's map is never modified.
func EncryptionContext(payload []byte, expected map[string]string) (map[string]string, error) {
	_, _, publicKey, _, err := parseContext(payload, expected)
	if err != nil {
		return nil, err
	}
	context := make(map[string]string, len(expected)+1)
	for key, value := range expected {
		context[key] = value
	}
	if publicKey != "" {
		context[signingContextKey] = publicKey
	}
	return context, nil
}

func parseContext(payload []byte, expected map[string]string) (suite uint16, position int, publicKey string, verifier *ecdsa.PublicKey, err error) {
	if len(payload) < 37 || payload[0] != 2 {
		err = errInvalid
		return
	}
	suite = binary.BigEndian.Uint16(payload[1:])
	count := len(expected)
	switch suite {
	case signedSuite:
		count++
	case unsignedSuite:
	default:
		err = errInvalid
		return
	}
	if _, err = contextSize(expected, suite == signedSuite); err != nil {
		return
	}
	position = 35
	context, ok := readField(payload, &position)
	if !ok || len(context) < 2 || int(binary.BigEndian.Uint16(context)) != count {
		err = errInvalid
		return
	}
	cursor := 2
	previous := ""
	for i := range count {
		key, keyOK := readField(context, &cursor)
		value, valueOK := readField(context, &cursor)
		name := string(key)
		if !keyOK || !valueOK || !utf8.Valid(key) || !utf8.Valid(value) || (i > 0 && name <= previous) {
			err = errInvalid
			return
		}
		previous = name
		switch name {
		case signingContextKey:
			if suite != signedSuite {
				err = errInvalid
				return
			}
			publicKey = string(value)
			verifier, err = parsePublicKey(publicKey)
			if err != nil {
				return
			}
		default:
			if want, found := expected[name]; !found || string(value) != want {
				err = errInvalid
				return
			}
		}
	}
	if cursor != len(context) || (suite == signedSuite && verifier == nil) {
		err = errInvalid
	}
	return
}
