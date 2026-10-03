package sqs

import api "stackd/internal/awsapi/sqs"

const (
	metricMessageSize  = "SentMessageSize"
	metricDeduplicated = "NumberOfDeduplicatedSentMessages"
)

// messageBodySize counts submitted UTF-8/raw binary bytes, before Number value
// normalization. System attributes are excluded from the SQS payload quota.
func messageBodySize(body string, attrs api.MessageBodyAttributeMap) int {
	size := len(body)
	for name, attr := range attrs {
		size += len(name) + len(value(attr.DataType)) + len(value(attr.StringValue)) + len(attr.BinaryValue)
	}
	return size
}

// sentMessageSize is the observed CloudWatch measurement, not the payload quota:
// AWS includes AWSTraceHeader's name, type and value in this metric too.
func sentMessageSize(body string, attrs api.MessageBodyAttributeMap, system api.MessageBodySystemAttributeMap) int64 {
	size := messageBodySize(body, attrs)
	for name, attr := range system {
		size += len(name) + len(value(attr.DataType)) + len(value(attr.StringValue)) + len(attr.BinaryValue)
	}
	return int64(size)
}

func (s *Service) observeSend(in *api.SendMessageInput, duplicate bool) {
	if s.metrics == nil || s.command == nil {
		return
	}
	s.command.sendSizes = append(s.command.sendSizes, sentMessageSize(value(in.MessageBody), in.MessageAttributes, in.MessageSystemAttributes))
	if duplicate {
		s.command.deduplicated++
	}
}

// A rejected batch request records one size per entry ID. A repeated ID retains
// its last submitted payload. Successfully admitted batches instead observe
// only the entries that enqueue accepts.
func (s *Service) observeBatchPreflight(in *api.SendMessageBatchInput) {
	if s.metrics == nil || s.command == nil {
		return
	}
	positions := make(map[string]int, len(in.Entries))
	for _, entry := range in.Entries {
		id := value(entry.Id)
		size := sentMessageSize(value(entry.MessageBody), entry.MessageAttributes, entry.MessageSystemAttributes)
		if position, found := positions[id]; found {
			s.command.sendSizes[position] = size
		} else {
			positions[id] = len(s.command.sendSizes)
			s.command.sendSizes = append(s.command.sendSizes, size)
		}
	}
	s.command.failedBatchSizes = true
}

func (a *commandAudit) messageSizeSamples() []MetricSample {
	samples := make([]MetricSample, 0, len(a.sendSizes))
	for _, size := range a.sendSizes {
		samples = append(samples, MetricSample{Name: metricMessageSize, Value: size, SampleCount: 1})
	}
	return samples
}
