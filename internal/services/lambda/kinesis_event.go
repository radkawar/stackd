package lambda

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/kinesisaggregation"
	"stackd/internal/services/eventbridge/eventpattern"
)

type kinesisEventRecord struct {
	Kinesis struct {
		SchemaVersion               string  `json:"kinesisSchemaVersion"`
		PartitionKey                string  `json:"partitionKey"`
		SequenceNumber              string  `json:"sequenceNumber"`
		Data                        []byte  `json:"data"`
		ApproximateArrivalTimestamp float64 `json:"approximateArrivalTimestamp"`
	} `json:"kinesis"`
	EventSource       string `json:"eventSource"`
	EventVersion      string `json:"eventVersion"`
	EventID           string `json:"eventID"`
	EventName         string `json:"eventName"`
	InvokeIdentityARN string `json:"invokeIdentityArn"`
	AWSRegion         string `json:"awsRegion"`
	EventSourceARN    string `json:"eventSourceARN"`
}

func kinesisRecords(mapping EventSourceMappingRecord, role, source, shard string, native api.Record, topology api.Shard, fanout bool, now time.Time) ([]StreamQueuedRecord, error) {
	if native.ApproximateArrivalTimestamp == nil || value(native.SequenceNumber) == "" {
		return nil, fmt.Errorf("kinesis record has no timestamp or sequence")
	}
	created := time.Time(*native.ApproximateArrivalTimestamp)
	sequence := value(native.SequenceNumber)
	// Native shared-throughput mappings pass the original KPL bytes through;
	// enhanced fan-out alone deaggregates before event filtering. Inner records
	// retain the outer sequence and event ID, without synthetic subsequences.
	var records []kinesisaggregation.Record
	var aggregated bool
	if fanout {
		records, aggregated = kinesisaggregation.Decode(native.Data)
	}
	if !aggregated {
		records = []kinesisaggregation.Record{{PartitionKey: value(native.PartitionKey), Data: native.Data}}
	}
	// KCL rejects the complete aggregate if any inner key belongs outside the
	// delivering shard, rather than delivering a partial aggregate.
	if aggregated && !kinesisAggregateInShard(records, topology) {
		return nil, nil
	}
	out := make([]StreamQueuedRecord, 0, len(records))
	for _, record := range records {
		event := kinesisEventRecord{EventSource: "aws:kinesis", EventVersion: "1.0", EventID: shard + ":" + sequence, EventName: "aws:kinesis:record", InvokeIdentityARN: role, AWSRegion: mapping.Key.Region, EventSourceARN: source}
		event.Kinesis.SchemaVersion = "1.0"
		event.Kinesis.PartitionKey = record.PartitionKey
		event.Kinesis.SequenceNumber = sequence
		event.Kinesis.Data = record.Data
		event.Kinesis.ApproximateArrivalTimestamp = float64(created.UnixNano()) / float64(time.Second)
		payload, err := sourceJSON(event)
		if err != nil {
			return nil, err
		}
		out = append(out, StreamQueuedRecord{ID: event.EventID, Sequence: sequence, ItemKey: record.PartitionKey, CreatedAt: created, CapturedAt: now, Payload: payload})
	}
	return out, nil
}

func matchesStreamRecordFilters(mapping EventSourceMappingRecord, filters []*eventpattern.Pattern, payload []byte) (bool, error) {
	if len(filters) == 0 || !strings.Contains(mapping.EventSourceARN, ":kinesis:") {
		return matchesStreamFilters(filters, payload)
	}
	var record kinesisEventRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return false, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(payload, &document); err != nil {
		return false, err
	}
	// The filter's data property is decoded JSON, not the base64 event field.
	// Non-JSON payloads have no data object and therefore cannot match data
	// predicates, while metadata-only filters still work.
	if json.Valid(record.Kinesis.Data) {
		document["data"] = record.Kinesis.Data
	}
	decoded, err := json.Marshal(document)
	if err != nil {
		return false, err
	}
	return matchesStreamFilters(filters, decoded)
}
