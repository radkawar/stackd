package lambda

import (
	"bytes"
	"encoding/json"
	"fmt"

	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/services/eventbridge/eventpattern"
)

type sqsEventAttribute struct {
	StringValue      *sqsapi.String    `json:"stringValue,omitempty"`
	BinaryValue      sqsapi.Binary     `json:"binaryValue,omitempty"`
	StringListValues sqsapi.StringList `json:"stringListValues"`
	BinaryListValues sqsapi.BinaryList `json:"binaryListValues"`
	DataType         string            `json:"dataType"`
}

type sqsEventRecord struct {
	MessageID              string                           `json:"messageId"`
	ReceiptHandle          string                           `json:"receiptHandle"`
	Body                   string                           `json:"body"`
	Attributes             sqsapi.MessageSystemAttributeMap `json:"attributes"`
	MessageAttributes      map[string]sqsEventAttribute     `json:"messageAttributes"`
	MD5OfBody              string                           `json:"md5OfBody"`
	MD5OfMessageAttributes *sqsapi.String                   `json:"md5OfMessageAttributes,omitempty"`
	EventSource            string                           `json:"eventSource"`
	EventSourceARN         string                           `json:"eventSourceARN"`
	AWSRegion              string                           `json:"awsRegion"`
}

func sqsRecord(mapping EventSourceMappingRecord, message sqsapi.Message) sqsEventRecord {
	record := sqsEventRecord{MessageID: value(message.MessageId), ReceiptHandle: value(message.ReceiptHandle), Body: value(message.Body), Attributes: message.Attributes, MessageAttributes: make(map[string]sqsEventAttribute, len(message.MessageAttributes)), MD5OfBody: value(message.MD5OfBody), MD5OfMessageAttributes: message.MD5OfMessageAttributes, EventSource: "aws:sqs", EventSourceARN: mapping.EventSourceARN, AWSRegion: mapping.Key.Region}
	if record.Attributes == nil {
		record.Attributes = sqsapi.MessageSystemAttributeMap{}
	}
	for name, attribute := range message.MessageAttributes {
		strings, binaries := attribute.StringListValues, attribute.BinaryListValues
		if strings == nil {
			strings = sqsapi.StringList{}
		}
		if binaries == nil {
			binaries = sqsapi.BinaryList{}
		}
		record.MessageAttributes[string(name)] = sqsEventAttribute{StringValue: attribute.StringValue, BinaryValue: attribute.BinaryValue, StringListValues: strings, BinaryListValues: binaries, DataType: value(attribute.DataType)}
	}
	return record
}

type sqsFilter struct {
	pattern    *eventpattern.Pattern
	bodyFormat byte
}

func compileSQSFilters(patterns []string) ([]sqsFilter, error) {
	out := make([]sqsFilter, 0, len(patterns))
	for _, text := range patterns {
		p, err := eventpattern.Compile([]byte(text))
		if err != nil {
			return nil, err
		}
		var root map[string]json.RawMessage
		if err := json.Unmarshal([]byte(text), &root); err != nil {
			return nil, err
		}
		var format byte
		if body := bytes.TrimSpace(root["body"]); len(body) != 0 {
			format = body[0]
		}
		out = append(out, sqsFilter{pattern: p, bodyFormat: format})
	}
	return out, nil
}

func matchesSQSFilters(filters []sqsFilter, record sqsEventRecord) (bool, error) {
	if len(filters) == 0 {
		return true, nil
	}
	// Decode only for matching: the customer's body remains the original string.
	// Invalid JSON stays a string, so object-body filters dispose it while
	// plain-string and metadata-only patterns retain their documented meaning.
	encoded, err := sourceJSON(record)
	if err != nil {
		return false, err
	}
	var event map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &event); err != nil {
		return false, err
	}
	jsonBody := json.Valid([]byte(record.Body))
	if jsonBody {
		event["body"] = json.RawMessage(record.Body)
	}
	encoded, err = sourceJSON(event)
	if err != nil {
		return false, err
	}
	for _, filter := range filters {
		// Format mismatch drops a message even when an exists:false term
		// could otherwise match a missing child on a plain-string body.
		if filter.bodyFormat == '{' && !jsonBody || filter.bodyFormat == '[' && jsonBody {
			continue
		}
		matches, err := filter.pattern.Match(encoded)
		if err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

// Missing members are not explicit invalid identifiers. Native bounded capture
// acknowledged [{}], unlike unknown, empty, numeric IDs and a nonarray list.
// Do not collapse these shapes via a string-only struct decoder. This is not a
// promise about every malformed response: unobserved structural errors fail the
// batch conservatively, and propagation-sensitive captures are not exceptions.
func sqsBatchFailures(payload []byte, records []sqsEventRecord) (map[string]bool, error) {
	failed := make(map[string]bool)
	if len(bytes.TrimSpace(payload)) == 0 || bytes.Equal(bytes.TrimSpace(payload), []byte("null")) {
		return failed, nil
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, err
	}
	list, present := response["batchItemFailures"]
	if !present || bytes.Equal(bytes.TrimSpace(list), []byte("null")) {
		return failed, nil
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(list, &items); err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(records))
	for _, record := range records {
		known[record.MessageID] = true
	}
	for _, item := range items {
		if item == nil {
			return nil, fmt.Errorf("invalid null batch item failure")
		}
		raw, present := item["itemIdentifier"]
		if !present {
			continue
		}
		var id string
		if err := json.Unmarshal(raw, &id); err != nil {
			return nil, err
		}
		if id == "" || !known[id] {
			return nil, fmt.Errorf("invalid batch item identifier")
		}
		failed[id] = true
	}
	return failed, nil
}
