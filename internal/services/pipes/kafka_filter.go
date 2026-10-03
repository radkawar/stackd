package pipes

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"unicode/utf8"

	"stackd/internal/services/eventbridge/eventpattern"
)

type kafkaFilterField struct {
	value             json.RawMessage
	valid, structured bool
}

// Kafka filters decode UTF-8 key/value bytes. Unlike Kinesis, a structured/plain
// mismatch ignores the message fields and evaluates only metadata, as specified
// by the Pipes Kafka filtering contract. Transformations still retain base64
// for non-JSON bytes, so this must not change the shared template decoder.
func matchesKafka(filters []string, event []byte) (bool, error) {
	if len(filters) == 0 {
		return true, nil
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(event, &document); err != nil {
		return false, err
	}
	fields := make(map[string]kafkaFilterField, 2)
	for _, key := range []string{"key", "value"} {
		if bytes.Equal(document[key], []byte("null")) {
			fields[key] = kafkaFilterField{value: document[key], valid: true}
			continue
		}
		var encoded string
		if err := json.Unmarshal(document[key], &encoded); err != nil {
			return false, err
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || !utf8.Valid(raw) {
			fields[key] = kafkaFilterField{}
			continue
		}
		if json.Valid(raw) {
			trimmed := bytes.TrimSpace(raw)
			fields[key] = kafkaFilterField{value: raw, valid: true, structured: len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')}
		} else {
			value, err := json.Marshal(string(raw))
			if err != nil {
				return false, err
			}
			fields[key] = kafkaFilterField{value: value, valid: true}
		}
	}
	for key, field := range fields {
		if field.valid {
			document[key] = field.value
		}
	}
	input, err := json.Marshal(document)
	if err != nil {
		return false, err
	}
	for _, filter := range filters {
		var pattern map[string]json.RawMessage
		if err := json.Unmarshal([]byte(filter), &pattern); err != nil {
			return false, err
		}
		if err := prepareKafkaFilter(pattern, fields); err != nil {
			return false, err
		}
		if len(pattern) == 0 {
			return true, nil
		}
		rule, err := json.Marshal(pattern)
		if err != nil {
			return false, err
		}
		compiled, err := eventpattern.Compile(rule)
		if err != nil {
			return false, err
		}
		matched, err := compiled.Match(input)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func prepareKafkaFilter(pattern map[string]json.RawMessage, fields map[string]kafkaFilterField) error {
	metadataOnly := false
	for key, value := range fields {
		expected, present := pattern[key]
		if !present {
			continue
		}
		raw := bytes.TrimSpace(expected)
		structured := len(raw) > 0 && raw[0] == '{'
		if !value.valid || value.structured != structured {
			metadataOnly = true
		}
	}
	if metadataOnly {
		delete(pattern, "key")
		delete(pattern, "value")
	}
	if raw, present := pattern["$or"]; present {
		var branches []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &branches); err != nil {
			return err
		}
		for _, branch := range branches {
			if err := prepareKafkaFilter(branch, fields); err != nil {
				return err
			}
			if len(branch) == 0 {
				delete(pattern, "$or")
				return nil
			}
		}
		encoded, err := json.Marshal(branches)
		if err != nil {
			return err
		}
		pattern["$or"] = encoded
	}
	return nil
}

func validateKafkaFilter(pattern string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(pattern), &fields); err != nil {
		return invalid(err.Error())
	}
	for _, key := range []string{"awsRegion", "eventSource", "eventSourceARN", "eventSourceArn", "eventVersion", "eventID", "eventName", "invokeIdentityArn", "eventSourceKey", "bootstrapServers"} {
		if _, present := fields[key]; present {
			return invalid("Kafka filters cannot reference polling metadata field " + key + ".")
		}
	}
	if raw, present := fields["$or"]; present {
		var branches []json.RawMessage
		if err := json.Unmarshal(raw, &branches); err != nil {
			return invalid(err.Error())
		}
		for _, branch := range branches {
			if err := validateKafkaFilter(string(branch)); err != nil {
				return err
			}
		}
	}
	return nil
}
