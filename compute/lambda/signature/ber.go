package signature

import (
	"bytes"
	"errors"
)

// AWS emits BER indefinite-length wrappers around otherwise DER CMS values.
// Normalize those wrappers before encoding/asn1 parsing, without interpreting
// primitive octets as ASN.1 or accepting trailing, truncated or unbounded input.
func codeSignatureDER(input []byte, depth int) ([]byte, int, error) {
	invalid := errors.New("invalid or unsupported CMS BER encoding")
	if depth > 64 || len(input) < 2 || input[0]&31 == 31 || input[0] == 0 {
		return nil, 0, invalid
	}
	tag, lengthByte := input[0], input[1]
	position, length := 2, int(lengthByte)
	indefinite := lengthByte == 0x80
	if lengthByte > 0x80 {
		count := int(lengthByte & 0x7f)
		if count > 4 || len(input)-position < count || input[position] == 0 {
			return nil, 0, invalid
		}
		length = 0
		for _, b := range input[position : position+count] {
			length = length<<8 | int(b)
		}
		position += count
		if length < 128 {
			return nil, 0, invalid
		}
	}
	if indefinite && tag&0x20 == 0 {
		return nil, 0, invalid
	}
	end := len(input)
	if !indefinite {
		if length > len(input)-position {
			return nil, 0, invalid
		}
		end = position + length
	}
	if tag&0x20 == 0 {
		return input[:end], end, nil
	}
	start := position
	var normalized []byte
	changed := indefinite
	for {
		if indefinite && len(input)-position >= 2 && input[position] == 0 && input[position+1] == 0 {
			if normalized == nil {
				normalized = input[start:position]
			}
			return signatureDERValue(tag, normalized), position + 2, nil
		}
		if position == end {
			if indefinite {
				return nil, 0, invalid
			}
			if !changed {
				return input[:end], end, nil
			}
			return signatureDERValue(tag, normalized), end, nil
		}
		child, consumed, err := codeSignatureDER(input[position:end], depth+1)
		if err != nil {
			return nil, 0, err
		}
		if !bytes.Equal(child, input[position:position+consumed]) && normalized == nil {
			normalized = append([]byte{}, input[start:position]...)
			changed = true
		}
		if normalized != nil {
			normalized = append(normalized, child...)
		}
		position += consumed
	}
}

func signatureDERValue(tag byte, content []byte) []byte {
	var header [6]byte
	header[0] = tag
	n := 2
	if len(content) < 128 {
		header[1] = byte(len(content))
	} else {
		count := 0
		for size := len(content); size != 0; size >>= 8 {
			count++
		}
		header[1] = 0x80 | byte(count)
		for i := range count {
			header[2+i] = byte(len(content) >> (8 * (count - i - 1)))
		}
		n += count
	}
	encoded := make([]byte, n+len(content))
	copy(encoded, header[:n])
	copy(encoded[n:], content)
	return encoded
}
