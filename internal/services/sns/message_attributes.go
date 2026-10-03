package sns

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/awswire"
	"stackd/internal/messageattribute"
)

const maximumMessageBytes = 262144

var attributeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,255}$`)
var batchEntryIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

// publication is an admitted command before recipient selection. Only selected
// protocol variants become retained MessageRecords; unused overrides stay here.
type publication struct {
	MessageRecord
	protocolBodies   map[string]string
	originalBody     string
	deduplicationSet bool
	size             int
}

// Attribute error origin determines whole-batch rejection, independently of the
// AWS wire code (InvalidParameter also describes per-entry content failures).
type publicationAttributeError struct{ error }

func (e publicationAttributeError) Unwrap() error { return e.error }

// Attribute failures are request-level errors even for PublishBatch; ordinary
// entry content failures are reported per entry. SNS preserves Number spelling;
// the SQS destination owns raw-delivery normalization.
func normalizePublication(in api.PublishBatchRequestEntry) (publication, int, error) {
	size, rejected := validatePublicationAttributes(in.MessageAttributes)
	out := publication{MessageRecord: MessageRecord{Body: value(in.Message), Attributes: in.MessageAttributes}, originalBody: value(in.Message)}
	size += len(out.Body)
	if rejected != nil {
		return out, size, publicationAttributeError{rejected}
	}
	if in.Message == nil || out.Body == "" {
		return out, size, failure("InvalidParameter", "Invalid parameter: Empty message")
	}
	if !utf8.ValidString(out.Body) {
		return out, size, failure("InvalidParameter", "Invalid parameter: Message")
	}
	if in.MessageStructure != nil {
		if value(in.MessageStructure) != "json" {
			return out, size, failure("InvalidParameter", "Invalid parameter: MessageStructure")
		}
		out.Structured = true
		out.Body, out.protocolBodies, rejected = protocolMessage(out.Body)
		if rejected != nil {
			return out, size, rejected
		}
	}
	if in.MessageDeduplicationId != nil {
		out.deduplicationSet = true
		out.MessageDeduplicationID = value(in.MessageDeduplicationId)
	}
	if in.MessageGroupId != nil {
		if !messageattribute.ValidMessageID(value(in.MessageGroupId)) {
			return out, size, failure("InvalidParameter", "Invalid parameter: The MessageGroupId parameter can only include alphanumeric and punctuation characters. 1 to 128 in length")
		}
		out.MessageGroupID = value(in.MessageGroupId)
	}
	if in.Subject != nil {
		subject := value(in.Subject)
		if !validPublicationSubject(subject) {
			return out, size, failure("InvalidParameter", "Invalid parameter: Subject")
		}
		out.Subject = &subject
	}
	if size > maximumMessageBytes {
		return out, size, failure("InvalidParameter", "Invalid parameter: Message too long")
	}
	out.size = size
	return out, size, nil
}

// Native Subject length is inclusive and measured in UTF-16 code units, not
// UTF-8 bytes or Unicode scalar values: 100 BMP characters or 50 emoji fit.
func validPublicationSubject(subject string) bool {
	if subject == "" || !utf8.ValidString(subject) {
		return false
	}
	units := 0
	for _, r := range subject {
		if unicode.IsControl(r) {
			return false
		}
		units++
		if r > 0xffff {
			units++
		}
	}
	return units <= 100
}

func protocolMessage(body string) (string, map[string]string, *awswire.Error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		return "", nil, failure("InvalidParameter", "Message Structure - JSON message body failed to parse")
	}
	raw, exists := document["default"]
	if !exists {
		return "", nil, failure("InvalidParameter", "Message Structure - No default entry in JSON message body")
	}
	var fallback string
	// Native default scalars are rendered as text, including null. Containers
	// are not default bodies. Non-string overrides are ignored; duplicate
	// keys have already resolved to their last values.
	switch raw[0] {
	case '"':
		if err := json.Unmarshal(raw, &fallback); err != nil {
			return "", nil, wireError(err)
		}
	case '{', '[':
		return "", nil, failure("InvalidParameter", "Message Structure - Default entry must be a scalar")
	default:
		fallback = string(raw)
	}
	var overrides map[string]string
	for protocol, raw := range document {
		if protocol == "default" || raw[0] != '"' {
			continue
		}
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return "", nil, wireError(err)
		}
		if text == fallback {
			continue
		}
		if overrides == nil {
			overrides = make(map[string]string)
		}
		overrides[protocol] = text
	}
	return fallback, overrides, nil
}

func validatePublicationAttributes(input api.MessageAttributeMap) (int, *awswire.Error) {
	size := 0
	for name, attribute := range input {
		key := string(name)
		lower := strings.ToLower(key)
		if !attributeNamePattern.MatchString(key) || strings.HasSuffix(key, ".") || strings.Contains(key, "..") || strings.HasPrefix(lower, "aws.") || strings.HasPrefix(lower, "amazon.") {
			return size, failure("ParameterValueInvalid", "Invalid message attribute name: "+key)
		}
		kind := value(attribute.DataType)
		size += len(key) + len(kind)
		switch kind {
		case "String", "String.Array", "Number":
			text := value(attribute.StringValue)
			if attribute.StringValue == nil || text == "" || !utf8.ValidString(text) || attribute.BinaryValue != nil {
				return size, failure("ParameterValueInvalid", "Empty or invalid message attribute value: "+key)
			}
			size += len(text)
			if kind == "Number" {
				if _, err := messageattribute.ParseNumber(text, -128); err != nil {
					description := "Could not cast message attribute '" + key + "' value to number."
					if errors.Is(err, messageattribute.ErrNumberRange) {
						description = "Message attribute '" + key + "' number value [" + text + "] scale must be 10^-128 and 10^126."
					}
					if errors.Is(err, messageattribute.ErrNumberPrecision) {
						description = "Message attribute '" + key + "' number value [" + text + "] must have less than 38 precision digits."
					}
					return size, failure("ParameterValueInvalid", description)
				}
			} else {
				// SNS rejects supplementary characters in string attributes,
				// unlike the message body, Subject, and SQS string attributes.
				for _, r := range text {
					if r > 0xffff {
						return size, failure("InvalidParameter", "Invalid parameter: Invalid attribute value was passed in for message attribute "+key)
					}
				}
			}
		case "Binary":
			if len(attribute.BinaryValue) == 0 || attribute.StringValue != nil {
				return size, failure("ParameterValueInvalid", "Empty or invalid binary attribute: "+key)
			}
			size += len(attribute.BinaryValue)
		default:
			return size, failure("ParameterValueInvalid", "Invalid message attribute type: "+kind)
		}
	}
	return size, nil
}
