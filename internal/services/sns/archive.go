package sns

import (
	"encoding/json"
	"strconv"
	"time"

	"stackd/internal/awswire"
)

func (s *Service) setArchivePolicy(topic *TopicRecord, document string) *awswire.Error {
	if !topic.FIFO {
		return failure("InvalidParameter", "Invalid parameter: AttributeName")
	}
	if !json.Valid([]byte(document)) {
		return failure("InvalidParameter", "Invalid parameter: ArchivePolicy: Unable to parse JSON")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(document), &fields) != nil || fields == nil {
		return failure("InvalidParameter", "Invalid parameter: ArchivePolicy: JSON is missing required fields")
	}
	if len(fields) == 0 {
		topic.Archive = nil
		return nil
	}
	raw, exists := fields["MessageRetentionPeriod"]
	if !exists {
		return failure("InvalidParameter", "Invalid parameter: ArchivePolicy: JSON is missing required fields")
	}
	var number json.Number
	if json.Unmarshal(raw, &number) != nil {
		return failure("InvalidParameter", "Invalid parameter: ArchivePolicy: MessageRetentionPeriod value is invalid")
	}
	days, err := strconv.ParseInt(string(number), 10, 32)
	if err != nil || days < 1 || days > 365 {
		return failure("InvalidParameter", "Invalid parameter: ArchivePolicy: MessageRetentionPeriod value is invalid")
	}
	config := ArchiveConfig{Policy: document, RetentionDays: int32(days)}
	if topic.Archive == nil {
		config.Beginning = s.clock.Now().UTC().Truncate(time.Millisecond)
		config.MetricDue = config.Beginning.Truncate(time.Hour).Add(time.Hour)
	} else {
		config.Beginning, config.MetricDue = topic.Archive.Beginning, topic.Archive.MetricDue
	}
	topic.Archive = &config
	return nil
}

func beginningArchiveTime(config ArchiveConfig, now time.Time) time.Time {
	beginning := now.Add(-time.Duration(config.RetentionDays) * 24 * time.Hour).Truncate(time.Millisecond)
	if beginning.Before(config.Beginning) {
		return config.Beginning
	}
	return beginning
}

// Archive retention pins the same SQS payload used by ordinary FIFO delivery,
// even when there are no subscribers or every current subscription filters it.
func (s *Service) archivePublication(tx Transaction, topic TopicRecord, publication *publication, keys *publicationKeys) (MessageKey, error) {
	message := publication.MessageRecord
	if body, exists := publication.protocolBodies["sqs"]; exists {
		message.Key.Protocol, message.Body = "sqs", body
	}
	if err := keys.seal(topic, &message); err != nil {
		return MessageKey{}, err
	}
	if err := tx.PutMessage(message); err != nil {
		return MessageKey{}, err
	}
	sequence, err := strconv.ParseUint(message.SequenceNumber, 10, 64)
	if err != nil {
		return MessageKey{}, err
	}
	entry := ArchiveEntry{TopicID: topic.ID, Message: message.Key, Published: message.Published, Expires: message.Published.Add(time.Duration(topic.Archive.RetentionDays) * 24 * time.Hour), Sequence: sequence, SizeBytes: int64(publication.size)}
	if err := tx.PutArchiveEntry(entry); err != nil {
		return MessageKey{}, err
	}
	if err := s.stageMetric(tx, topic.Key, message.Published, metricArchiveProcessing, 1, 1); err != nil {
		return MessageKey{}, err
	}
	if err := s.stageMetric(tx, topic.Key, message.Published, metricArchiveBytesProcessing, entry.SizeBytes, 1); err != nil {
		return MessageKey{}, err
	}
	return message.Key, nil
}
