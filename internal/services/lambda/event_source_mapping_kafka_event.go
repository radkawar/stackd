package lambda

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"stackd/internal/services/eventbridge/eventpattern"
)

type kafkaEventRecord struct {
	Topic         string             `json:"topic"`
	Partition     int                `json:"partition"`
	Offset        int64              `json:"offset"`
	Timestamp     int64              `json:"timestamp"`
	TimestampType string             `json:"timestampType"`
	Key           []byte             `json:"key"`
	Value         []byte             `json:"value"`
	Headers       []map[string][]int `json:"headers"`
}

func kafkaRecordEvent(topic string, record KafkaRecord) ([]byte, error) {
	headers := make([]map[string][]int, len(record.Headers))
	for i, h := range record.Headers {
		var values []int
		if h.Value != nil {
			values = make([]int, len(h.Value))
			for j, v := range h.Value {
				values[j] = int(v)
			}
		}
		headers[i] = map[string][]int{h.Key: values}
	}
	return json.Marshal(kafkaEventRecord{Topic: topic, Partition: record.Partition, Offset: record.Offset, Timestamp: record.Timestamp.UnixMilli(), TimestampType: record.TimestampType, Key: record.Key, Value: record.Value, Headers: headers})
}
func kafkaEventPayload(mapping EventSourceMappingRecord, bootstrap string, partition int, records []json.RawMessage) ([]byte, error) {
	eventSource := "aws:kafka"
	if len(mapping.Settings.Kafka.BootstrapServers) != 0 {
		eventSource = "SelfManagedKafka"
	}
	return json.Marshal(struct {
		EventSource      string                       `json:"eventSource"`
		EventSourceARN   string                       `json:"eventSourceArn,omitempty"`
		BootstrapServers string                       `json:"bootstrapServers"`
		Records          map[string][]json.RawMessage `json:"records"`
	}{eventSource, mapping.EventSourceARN, bootstrap, map[string][]json.RawMessage{fmt.Sprintf("%s-%d", mapping.Settings.Kafka.Topic, partition): records}})
}

func validateKafkaMappingFilter(text string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &fields); err != nil {
		return err
	}
	for key, raw := range fields {
		switch key {
		case "value", "topic", "partition", "offset", "timestamp", "timestampType":
		case "$or":
			var branches []json.RawMessage
			if err := json.Unmarshal(raw, &branches); err != nil {
				return err
			}
			for _, branch := range branches {
				if err := validateKafkaMappingFilter(string(branch)); err != nil {
					return err
				}
			}
		default:
			return errors.New("kafka filters support value and record metadata, not keys, headers or polling metadata")
		}
	}
	return nil
}

type kafkaMappingFilter struct{ structured, plain, metadata *eventpattern.Pattern }

func compileKafkaMappingFilters(patterns []string) ([]kafkaMappingFilter, error) {
	out := make([]kafkaMappingFilter, 0, len(patterns))
	for _, text := range patterns {
		var variants [3]*eventpattern.Pattern
		for i := range variants {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(text), &fields); err != nil {
				return nil, err
			}
			if err := kafkaFilterVariant(fields, i); err != nil {
				return nil, err
			}
			if len(fields) == 0 {
				continue
			}
			raw, err := json.Marshal(fields)
			if err != nil {
				return nil, err
			}
			variants[i], err = eventpattern.Compile(raw)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, kafkaMappingFilter{structured: variants[0], plain: variants[1], metadata: variants[2]})
	}
	return out, nil
}
func kafkaFilterVariant(fields map[string]json.RawMessage, kind int) error {
	if raw, ok := fields["value"]; ok {
		structured := bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{"))
		if kind == 2 || structured != (kind == 0) {
			delete(fields, "value")
		}
	}
	if raw, ok := fields["$or"]; ok {
		var branches []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &branches); err != nil {
			return err
		}
		for _, branch := range branches {
			if err := kafkaFilterVariant(branch, kind); err != nil {
				return err
			}
			if len(branch) == 0 {
				delete(fields, "$or")
				return nil
			}
		}
		raw, err := json.Marshal(branches)
		if err != nil {
			return err
		}
		fields["$or"] = raw
	}
	return nil
}
func matchesKafkaMappingFilters(filters []kafkaMappingFilter, record KafkaRecord, event []byte) (bool, error) {
	if len(filters) == 0 {
		return true, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(event, &fields); err != nil {
		return false, err
	}
	kind := 2
	if record.Value == nil {
		fields["value"] = json.RawMessage("null")
		kind = 1
	} else if utf8.Valid(record.Value) {
		if json.Valid(record.Value) {
			fields["value"] = record.Value
			kind = 0
		} else {
			raw, err := json.Marshal(string(record.Value))
			if err != nil {
				return false, err
			}
			fields["value"] = raw
			kind = 1
		}
	}
	input, err := json.Marshal(fields)
	if err != nil {
		return false, err
	}
	for _, filter := range filters {
		selected := filter.metadata
		if kind == 0 {
			selected = filter.structured
		} else if kind == 1 {
			selected = filter.plain
		}
		if selected == nil {
			return true, nil
		}
		match, err := selected.Match(input)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}
