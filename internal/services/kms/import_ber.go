package kms

import "errors"

var errImportBER = errors.New("invalid imported BER private key")

// importBER converts definite or indefinite BER containers to DER lengths.
// KMS accepts BER PKCS8 for RSA/ECC imports. The API bounds input to 6144
// bytes; nesting is bounded here because this parser receives external bytes.
func importBER(input []byte, depth int) ([]byte, []byte, error) {
	if len(input) < 2 || depth > 32 || input[0] == 0 || input[0]&31 == 31 {
		return nil, nil, errImportBER
	}
	tag, size := input[0], int(input[1])
	rest := input[2:]
	indefinite := size == 128
	if size > 128 {
		count := size & 127
		if count > 4 || len(rest) < count {
			return nil, nil, errImportBER
		}
		size = 0
		for _, b := range rest[:count] {
			size = size<<8 | int(b)
		}
		rest = rest[count:]
	}
	if indefinite && tag&32 == 0 || !indefinite && size > len(rest) {
		return nil, nil, errImportBER
	}
	body := rest
	if !indefinite {
		body, rest = rest[:size], rest[size:]
	}
	if tag&32 != 0 {
		var children []byte
		defer func() { clear(children) }()
		for {
			if indefinite && len(body) >= 2 && body[0] == 0 && body[1] == 0 {
				rest = body[2:]
				break
			}
			if !indefinite && len(body) == 0 {
				break
			}
			child, remaining, err := importBER(body, depth+1)
			if err != nil {
				return nil, nil, err
			}
			if tag == 0x24 { // BER permits constructed OCTET STRINGs.
				if child[0] != 4 {
					clear(child)
					return nil, nil, errImportBER
				}
				header := 2
				if child[1] > 127 {
					header += int(child[1] & 127)
				}
				children = append(children, child[header:]...)
			} else {
				children = append(children, child...)
			}
			clear(child)
			body = remaining
		}
		body = children
		if tag == 0x24 {
			tag = 4
		}
	}
	out := []byte{tag}
	length := len(body)
	if length < 128 {
		out = append(out, byte(length))
	} else {
		var encoded [8]byte
		i := len(encoded)
		for length > 0 {
			i--
			encoded[i] = byte(length)
			length >>= 8
		}
		out = append(out, 128|byte(len(encoded)-i))
		out = append(out, encoded[i:]...)
	}
	out = append(out, body...)
	return out, rest, nil
}
