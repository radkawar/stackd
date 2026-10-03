package lambda

import (
	"encoding/json"
	"errors"
)

// MQ and Kafka share the documented UTF-8/JSON type-mismatch filtering rules.
// Only the source field name differs; retain one matcher for those semantics.
func mqFilterPattern(pattern string) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(pattern), &fields); err != nil {
		return "", err
	}
	if fields == nil {
		return "", errors.New("MQ filter must be an object")
	}
	for key, raw := range fields {
		switch key {
		case "data":
		case "$or":
			var branches []json.RawMessage
			if err := json.Unmarshal(raw, &branches); err != nil {
				return "", err
			}
			for i, branch := range branches {
				translated, err := mqFilterPattern(string(branch))
				if err != nil {
					return "", err
				}
				branches[i] = json.RawMessage(translated)
			}
			translated, err := json.Marshal(branches)
			if err != nil {
				return "", err
			}
			fields[key] = translated
		default:
			return "", errors.New("MQ filters support only the data field")
		}
	}
	if data, ok := fields["data"]; ok {
		delete(fields, "data")
		fields["value"] = data
	}
	raw, err := json.Marshal(fields)
	return string(raw), err
}
func validateMQMappingFilter(pattern string) error { _, e := mqFilterPattern(pattern); return e }
func compileMQMappingFilters(patterns []string) ([]kafkaMappingFilter, error) {
	translated := make([]string, len(patterns))
	for i, p := range patterns {
		v, e := mqFilterPattern(p)
		if e != nil {
			return nil, e
		}
		translated[i] = v
	}
	return compileKafkaMappingFilters(translated)
}
func mqEventPayload(mapping EventSourceMappingRecord, records []json.RawMessage) ([]byte, error) {
	d := mapping.Settings.MQ
	if d.Identity.Engine == "RABBITMQ" {
		return json.Marshal(struct {
			EventSource    string                       `json:"eventSource"`
			EventSourceARN string                       `json:"eventSourceArn"`
			Messages       map[string][]json.RawMessage `json:"rmqMessagesByQueue"`
		}{"aws:rmq", mapping.EventSourceARN, map[string][]json.RawMessage{d.Queue + "::" + d.VirtualHost: records}})
	}
	return json.Marshal(struct {
		EventSource    string            `json:"eventSource"`
		EventSourceARN string            `json:"eventSourceArn"`
		Messages       []json.RawMessage `json:"messages"`
	}{"aws:mq", mapping.EventSourceARN, records})
}
