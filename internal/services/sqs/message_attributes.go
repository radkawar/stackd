package sqs

import (
	"crypto/md5" // SQS wire checksums require MD5.
	"encoding/binary"
	"encoding/hex"
	"hash"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
	"stackd/internal/messageattribute"
)

var attributeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var tracePattern = regexp.MustCompile(`(?:^|;)\s*Root=1-[0-9a-fA-F]{8}-[0-9a-fA-F]{24}(?:;|$)`)

func validText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == 9 || r == 10 || r == 13 || r >= 0x20 && r <= 0xd7ff || r >= 0xe000 && r <= 0xfffd || r >= 0x10000 && r <= 0x10ffff {
			continue
		}
		return false
	}
	return true
}
func bodyDigest(body string) string { sum := md5.Sum([]byte(body)); return hex.EncodeToString(sum[:]) }
func writeSized(h hash.Hash, b []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(b)
}
func attributeDigest(attrs api.MessageBodyAttributeMap) string {
	if len(attrs) == 0 {
		return ""
	}
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, string(name))
	}
	slices.Sort(names)
	h := md5.New()
	for _, name := range names {
		a := attrs[api.String(name)]
		writeSized(h, []byte(name))
		writeSized(h, []byte(value(a.DataType)))
		if strings.HasPrefix(value(a.DataType), "Binary") {
			_, _ = h.Write([]byte{2})
			writeSized(h, a.BinaryValue)
		} else {
			_, _ = h.Write([]byte{1})
			writeSized(h, []byte(value(a.StringValue)))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
func normalizeAttributes(attrs api.MessageBodyAttributeMap) (api.MessageBodyAttributeMap, int, *awswire.Error) {
	if len(attrs) > 10 {
		return nil, 0, failure("InvalidParameterValue", "A message can have at most 10 attributes.")
	}
	result := make(api.MessageBodyAttributeMap, len(attrs))
	size := 0
	for name, a := range attrs {
		n := string(name)
		lower := strings.ToLower(n)
		typ := value(a.DataType)
		base, _, _ := strings.Cut(typ, ".")
		if len(n) == 0 || len(n) > 256 || !attributeNamePattern.MatchString(n) || strings.HasPrefix(lower, "aws.") || strings.HasPrefix(lower, "amazon.") || strings.HasPrefix(n, ".") || strings.HasSuffix(n, ".") || strings.Contains(n, "..") {
			return nil, 0, failure("InvalidParameterValue", "Invalid message attribute name.")
		}
		if len(typ) == 0 || len(typ) > 256 || !validText(typ) || len(a.StringListValues) != 0 || len(a.BinaryListValues) != 0 {
			return nil, 0, failure("InvalidParameterValue", "Invalid message attribute type or unsupported list value.")
		}
		normalized := api.MessageAttributeValue{DataType: str(typ)}
		switch base {
		case "String", "Number":
			v := value(a.StringValue)
			if v == "" || !validText(v) || a.BinaryValue != nil {
				return nil, 0, failure("InvalidParameterValue", "Message attribute must contain a nonempty string value.")
			}
			if base == "Number" {
				number, err := messageattribute.ParseNumber(v, -128)
				if err != nil {
					return nil, 0, failure("InvalidParameterValue", "Invalid number attribute value.")
				}
				v = number.String()
			}
			normalized.StringValue = str(v)
			size += len(v)
		case "Binary":
			if len(a.BinaryValue) == 0 || a.StringValue != nil {
				return nil, 0, failure("InvalidParameterValue", "Message attribute must contain a nonempty binary value.")
			}
			normalized.BinaryValue = slices.Clone(a.BinaryValue)
			size += len(a.BinaryValue)
		default:
			return nil, 0, failure("InvalidParameterValue", "Unknown message attribute data type.")
		}
		result[name] = normalized
		size += len(n) + len(typ)
	}
	return result, size, nil
}
func normalizeSystemAttributes(attrs api.MessageBodySystemAttributeMap) (string, string, *awswire.Error) {
	if len(attrs) == 0 {
		return "", "", nil
	}
	if len(attrs) != 1 {
		return "", "", failure("InvalidParameterValue", "Only AWSTraceHeader system attributes are supported.")
	}
	a, ok := attrs["AWSTraceHeader"]
	if !ok || value(a.DataType) != "String" || !tracePattern.MatchString(value(a.StringValue)) || len(a.BinaryValue) != 0 || len(a.BinaryListValues) != 0 || len(a.StringListValues) != 0 {
		return "", "", failure("InvalidParameterValue", "Invalid AWSTraceHeader system attribute.")
	}
	converted := api.MessageBodyAttributeMap{"AWSTraceHeader": {DataType: str("String"), StringValue: str(value(a.StringValue))}}
	return value(a.StringValue), attributeDigest(converted), nil
}
