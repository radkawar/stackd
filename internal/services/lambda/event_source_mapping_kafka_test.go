package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/lambda"
)

func TestMSKNativeAdmissionBoundaries(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/lambda/msk_admission.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Label  string
			Input  json.RawMessage
			Result struct{ Code string }
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	control := kafkaMappingControl{s: New(Config{})}
	defer control.s.Close()
	// Other captured cases reached cluster authority or CLI validation; do not
	// misrepresent their same error code as evidence for a different boundary.
	for _, row := range fixture.Observations {
		switch row.Label {
		case "missing_topics", "timestamp_required", "queue_options":
		default:
			continue
		}
		t.Run(row.Label, func(t *testing.T) {
			var input api.CreateEventSourceMappingInput
			if err := json.Unmarshal(row.Input, &input); err != nil {
				t.Fatal(err)
			}
			_, wire := control.createSettings(&input)
			if wire == nil || wire.Code != row.Result.Code {
				t.Fatalf("native rejection %s, local %v", row.Result.Code, wire)
			}
		})
	}
}

// The native CloudFormation Kafka capture reaches Lambda's InvalidParameterValue
// error: EventCount requires provisioned polling, not an on-demand source.
func TestKafkaMetricsRequireProvisionedPolling(t *testing.T) {
	settings := EventSourceMappingSettings{BatchSize: 100, Kafka: &KafkaMappingSettings{Topic: "orders"}}
	_, wire := (kafkaMappingControl{}).updateSettings(settings, &api.UpdateEventSourceMappingInput{
		MetricsConfig: &api.EventSourceMappingMetricsConfig{
			Metrics: api.EventSourceMappingMetricList{api.EventSourceMappingMetricEventCount},
		},
	})
	if wire == nil || wire.Code != "InvalidParameterValueException" {
		t.Fatalf("on-demand Kafka accepted provisioned-only metrics: %v", wire)
	}
}

func TestMSKKafkaPayloadPreservesBytesAndTombstones(t *testing.T) {
	mapping := EventSourceMappingRecord{EventSourceARN: "arn:aws:kafka:us-east-1:123456789012:cluster/owned/id", Settings: EventSourceMappingSettings{Kafka: &KafkaMappingSettings{Topic: "owned-topic"}}}
	record := KafkaRecord{Partition: 2, Offset: 9007199254740993, Timestamp: time.UnixMilli(1545084650987), TimestampType: "LOG_APPEND_TIME", Key: []byte{0, 255}, Value: []byte{}, Headers: []KafkaHeader{{Key: "same", Value: []byte{255, 0}}, {Key: "same", Value: []byte{}}}}
	encoded, err := kafkaRecordEvent("owned-topic", record)
	if err != nil {
		t.Fatal(err)
	}
	tombstone, err := kafkaRecordEvent("owned-topic", KafkaRecord{Partition: 2, Offset: record.Offset + 1, Timestamp: record.Timestamp, TimestampType: "CREATE_TIME"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := kafkaEventPayload(mapping, "127.0.0.1:9092", 2, []json.RawMessage{encoded, tombstone})
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		EventSource string `json:"eventSource"`
		ARN         string `json:"eventSourceArn"`
		Bootstrap   string `json:"bootstrapServers"`
		Records     map[string][]struct {
			Topic         string
			Partition     int
			Offset        int64
			Timestamp     int64
			TimestampType string
			Key, Value    *string
			Headers       []map[string][]int
		}
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	rows := event.Records["owned-topic-2"]
	if event.EventSource != "aws:kafka" || event.ARN != mapping.EventSourceARN || event.Bootstrap != "127.0.0.1:9092" || len(rows) != 2 {
		t.Fatalf("invalid event envelope: %s", payload)
	}
	if rows[0].Offset != record.Offset || rows[0].Timestamp != 1545084650987 || rows[0].TimestampType != "LOG_APPEND_TIME" || rows[0].Partition != 2 || rows[0].Topic != "owned-topic" {
		t.Fatalf("native record metadata changed: %s", payload)
	}
	if rows[0].Key == nil || *rows[0].Key != "AP8=" || rows[0].Value == nil || *rows[0].Value != "" || rows[1].Key != nil || rows[1].Value != nil {
		t.Fatalf("empty/null/binary bytes changed: %s", payload)
	}
	if !reflect.DeepEqual(rows[0].Headers, []map[string][]int{{"same": {255, 0}}, {"same": {}}}) || rows[1].Headers == nil {
		t.Fatalf("duplicate headers or empty header list changed: %s", payload)
	}
}

func TestMSKKafkaFilterFormatMatrix(t *testing.T) {
	// https://docs.aws.amazon.com/lambda/latest/dg/kafka-filtering.html
	for _, row := range []struct {
		name, pattern string
		value         []byte
		partition     int
		want          bool
	}{
		{"JSON match", `{"value":{"kind":["keep"]}}`, []byte(`{"kind":"keep"}`), 0, true},
		{"JSON reject", `{"value":{"kind":["keep"]}}`, []byte(`{"kind":"drop"}`), 0, false},
		{"plain match", `{"value":["keep"]}`, []byte("keep"), 0, true},
		{"plain reject", `{"value":["keep"]}`, []byte("drop"), 0, false},
		{"plain structured mismatch", `{"value":{"kind":["keep"]}}`, []byte("drop"), 0, true},
		{"JSON plain mismatch", `{"value":["drop"]}`, []byte(`{"kind":"keep"}`), 0, true},
		{"binary metadata match", `{"value":{"kind":["keep"]},"partition":[2]}`, []byte{255, 0}, 2, true},
		{"binary metadata reject", `{"value":{"kind":["keep"]},"partition":[2]}`, []byte{255, 0}, 1, false},
		{"OR retains metadata", `{"$or":[{"value":{"kind":["keep"]},"partition":[2]},{"partition":[3]}]}`, []byte("plain"), 1, false},
		{"tombstone", `{"value":[null]}`, nil, 0, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			filters, err := compileKafkaMappingFilters([]string{row.pattern})
			if err != nil {
				t.Fatal(err)
			}
			record := KafkaRecord{Partition: row.partition, Value: row.value}
			event, err := kafkaRecordEvent("topic", record)
			if err != nil {
				t.Fatal(err)
			}
			got, err := matchesKafkaMappingFilters(filters, record, event)
			if err != nil || got != row.want {
				t.Fatalf("match=%v err=%v want=%v", got, err, row.want)
			}
		})
	}
}

func TestMSKConsumerGroupsAndTopicsDoNotAlias(t *testing.T) {
	repo := NewMemoryRepository(nil)
	scope := Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
	original := EventSourceMappingRecord{Key: EventSourceMappingKey{Scope: scope, UUID: "one"}, EventSourceARN: "arn:aws:kafka:us-east-1:123456789012:cluster/owned/id", Function: FunctionReference{FunctionKey: FunctionKey{Scope: scope, Name: "function"}}, Settings: EventSourceMappingSettings{Kafka: &KafkaMappingSettings{Topic: "topic-one", ConsumerGroupID: "group-one"}}}
	if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutEventSourceMapping(original) }); err != nil {
		t.Fatal(err)
	}
	err := repo.View(t.Context(), func(r Reader) error {
		proposed := cloneEventSourceMapping(original)
		proposed.Key.UUID = "two"
		proposed.Settings.Kafka.Topic = "topic-two"
		proposed.Settings.Kafka.ConsumerGroupID = "group-two"
		if err := mappingUnique(r, proposed); err != nil {
			t.Fatalf("distinct topic was rejected: %v", err)
		}
		proposed.Settings.Kafka.ConsumerGroupID = "group-one"
		if err := mappingUnique(r, proposed); err == nil {
			t.Fatal("duplicate consumer group was admitted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestKafkaFirstIdentityBindingFencesStaleWorkers(t *testing.T) {
	first := KafkaIdentity{ClusterID: "cluster", TopicID: "first-topic"}
	replacement := KafkaIdentity{ClusterID: "cluster", TopicID: "replacement-topic"}
	for _, name := range []string{"first observation", "competing identity", "disabled", "updated", "deleted"} {
		t.Run(name, func(t *testing.T) {
			repo := NewMemoryRepository(nil)
			s := &Service{repository: repo}
			selected := EventSourceMappingRecord{
				Key:     EventSourceMappingKey{Scope: Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, UUID: "mapping"},
				Version: 7, State: "Enabled",
				Settings: EventSourceMappingSettings{Kafka: &KafkaMappingSettings{Topic: "topic"}},
			}
			current := cloneEventSourceMapping(selected)
			want := first
			switch name {
			case "competing identity":
				current.Settings.Kafka.Identity = replacement
				want = replacement
			case "disabled":
				current.State = "Disabled"
				want = KafkaIdentity{}
			case "updated":
				current.Version++
				want = KafkaIdentity{}
			}
			if name != "deleted" {
				if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutEventSourceMapping(current) }); err != nil {
					t.Fatal(err)
				}
			}
			err := s.bindKafkaIdentity(t.Context(), selected, first)
			switch name {
			case "first observation":
				if err != nil {
					t.Fatal(err)
				}
				// A second observer with the same initial snapshot can agree,
				// but must never replace an already committed identity.
				if err := s.bindKafkaIdentity(t.Context(), selected, first); err != nil {
					t.Fatal(err)
				}
			case "disabled", "updated":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("stale worker not canceled: %v", err)
				}
			case "deleted":
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("deleted mapping was recreated: %v", err)
				}
				return
			case "competing identity":
				if err == nil {
					t.Fatal("replacement topic was adopted")
				}
			}
			if err := repo.View(t.Context(), func(r Reader) error {
				got, err := r.EventSourceMapping(selected.Key)
				if err != nil {
					return err
				}
				if got.Settings.Kafka.Identity != want || got.Version != current.Version || got.State != current.State {
					t.Fatalf("binding changed retained fence or configuration: %+v", got)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
