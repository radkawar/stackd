package pipes

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/pipes"
)

func TestKafkaFilteringAndTransformationUseDecodedMessageFields(t *testing.T) {
	p := PipeRecord{SourceARN: "arn:aws:kafka:us-east-1:123456789012:cluster/orders/incarnation", Source: SourceSettings{Kind: "msk", Kafka: KafkaSettings{Topic: "orders"}}}
	event, err := kafkaEvent(p, KafkaRecord{Partition: 2, Offset: 41, Timestamp: time.UnixMilli(1700000000123), TimestampType: "LOG_APPEND_TIME", Key: []byte(`{"tenant":"one"}`), Value: []byte(`{"keep":true,"amount":7}`), Headers: []KafkaHeader{{Key: "trace", Value: []byte{0, 255}}}})
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(event, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["partition"] != "2" || envelope["eventSourceKey"] != "orders-2" || envelope["eventSourceArn"] != p.SourceARN || envelope["timestamp"] != float64(1700000000123) {
		t.Fatalf("Kafka event envelope differs from Pipes contract: %s", event)
	}
	if got := envelope["headers"]; !reflect.DeepEqual(got, []any{map[string]any{"trace": []any{float64(0), float64(255)}}}) {
		t.Fatalf("Kafka headers must contain byte-number arrays: %#v", got)
	}
	for _, tc := range []struct {
		pattern string
		want    bool
	}{
		{`{"value":{"keep":[true]},"key":{"tenant":["one"]}}`, true},
		{`{"value":{"keep":[false]}}`, false},
		{`{"$or":[{"value":{"amount":[7]}},{"partition":["9"]}]}`, true},
		{`{"topic":["other"],"value":["plain"]}`, false},
		{`{"topic":["orders"],"value":["plain"]}`, true},
	} {
		got, err := matchesKafka([]string{tc.pattern}, event)
		if err != nil || got != tc.want {
			t.Fatalf("pattern %s: matched=%v want=%v err=%v", tc.pattern, got, tc.want, err)
		}
	}
	template, err := compileTemplate(`{"amount":<$.value.amount>,"tenant":<$.key.tenant>,"offset":<$.offset>}`)
	if err != nil {
		t.Fatal(err)
	}
	transformed, err := template.apply(event, p, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(transformed, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{"amount": float64(7), "tenant": "one", "offset": float64(41)}) {
		t.Fatalf("decoded transformation: %s", transformed)
	}
}

func TestKafkaPlainAndNonUTF8FiltersFallBackOnlyToMetadata(t *testing.T) {
	p := PipeRecord{SourceARN: "smk://localhost:9092", Source: SourceSettings{Kind: "kafka", Kafka: KafkaSettings{Topic: "orders"}}}
	for _, tc := range []struct {
		payload []byte
		pattern string
		want    bool
	}{
		{[]byte("hello"), `{"value":["hello"]}`, true},
		{[]byte("hello"), `{"value":["different"]}`, false},
		{[]byte("hello"), `{"value":{"missing":[1]}}`, true},
		{[]byte{0xff, 0xfe}, `{"topic":["orders"],"value":{"keep":[true]}}`, true},
		{[]byte{0xff, 0xfe}, `{"topic":["other"],"value":{"keep":[true]}}`, false},
	} {
		event, err := kafkaEvent(p, KafkaRecord{Value: tc.payload})
		if err != nil {
			t.Fatal(err)
		}
		matched, err := matchesKafka([]string{tc.pattern}, event)
		if err != nil || matched != tc.want {
			t.Fatalf("payload=%x pattern=%s got=%v want=%v err=%v", tc.payload, tc.pattern, matched, tc.want, err)
		}
	}
}

func TestKafkaPartialFailureRetainsWholeBatchAcrossRecovery(t *testing.T) {
	now := time.Unix(100, 0)
	sourceClock := clock.NewManual(now)
	repository := NewMemoryRepository(nil)
	p := PipeRecord{ID: "pipe", State: "RUNNING", Source: SourceSettings{Kind: "kafka", BatchSize: 10, Parallelism: 1, MaximumAge: -1, MaximumRetries: -1}}
	batch := []Work{
		{ID: "filtered", PipeID: p.ID, RecordID: "orders-0:4", ShardID: "0", Sequence: "4", Ordinal: 1, Phase: "executing", Filtered: true},
		{ID: "failed", PipeID: p.ID, RecordID: "orders-0:5", ShardID: "0", Sequence: "5", Ordinal: 2, Phase: "executing"},
	}
	if err := repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutPipe(p); err != nil {
			return err
		}
		for _, w := range batch {
			if err := tx.PutWork(w); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	service := NewWithConfig(Config{Repository: repository, Clock: sourceClock})
	if err := service.completeAttempt(t.Context(), p, batch, map[string]bool{batch[1].RecordID: true}, nil); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	service = NewWithConfig(Config{Repository: repository, Clock: sourceClock})
	defer service.Close()
	var retry []Work
	if err := repository.View(t.Context(), func(reader Reader) error {
		work, err := reader.Work(p.ID)
		if err != nil {
			return err
		}
		if got := acknowledgeable(p, work, now.Add(time.Hour)); len(got) != 0 {
			t.Fatalf("failed batch acknowledged filtered prefix: %+v", got)
		}
		if len(work) != 2 || !work[0].Filtered || work[0].Attempts != 1 || work[1].Attempts != 1 {
			t.Fatalf("failure lost batch state: %+v", work)
		}
		work = append(work, Work{ID: "later", RecordID: "orders-0:6", ShardID: "0", Sequence: "6", Ordinal: 3, Phase: "ready"})
		retry = selectBatch(p, work, now.Add(2*time.Second))
		if len(retry) != 2 || retry[0].ID != "filtered" || retry[1].ID != "failed" {
			t.Fatalf("retry did not preserve original batch: %+v", retry)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(t.Context(), func(tx Transaction) error {
		for _, w := range retry {
			w.Phase = "executing"
			if err := tx.PutWork(w); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.completeAttempt(t.Context(), p, retry, map[string]bool{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(t.Context(), func(reader Reader) error {
		work, err := reader.Work(p.ID)
		if err != nil {
			return err
		}
		ack := acknowledgeable(p, work, now)
		if len(ack) != 2 || ack[1].Sequence != "5" {
			t.Fatalf("successful recovery did not release contiguous offsets: %+v", ack)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestKafkaAssignmentAndCommittedOffsetFenceRetainedWork(t *testing.T) {
	work := []Work{{ID: "old", ShardID: "0", Sequence: "4"}, {ID: "next", ShardID: "0", Sequence: "5"}, {ID: "revoked", ShardID: "1", Sequence: "8"}}
	assigned, obsolete := kafkaAssignedWork(work, []KafkaPartition{{ID: 0, Offset: 5, Committed: true}})
	if len(assigned) != 1 || assigned[0].ID != "next" || len(obsolete) != 1 || obsolete[0].ID != "old" {
		t.Fatalf("native ownership/offset not respected: assigned=%+v obsolete=%+v", assigned, obsolete)
	}
	checkpoints := []Checkpoint{{ShardID: "0", Sequence: "6", Initialized: true}}
	if got := kafkaPartitionOffset(KafkaPartition{ID: 0, Offset: 99}, checkpoints); got != 7 {
		t.Fatalf("LATEST restart skipped retained start: %d", got)
	}
	if got := kafkaPartitionOffset(KafkaPartition{ID: 0, Offset: 9, Committed: true}, checkpoints); got != 9 {
		t.Fatalf("native group offset did not override starting position: %d", got)
	}
}

func TestKafkaRejectsInertNetworkAndMismatchedSourceSettings(t *testing.T) {
	topic := api.KafkaTopicName("orders")
	for _, tc := range []struct {
		arn    string
		params *api.PipeSourceParameters
	}{
		{"smk://localhost:9092", &api.PipeSourceParameters{SelfManagedKafkaParameters: &api.PipeSourceSelfManagedKafkaParameters{TopicName: &topic, Vpc: &api.SelfManagedKafkaAccessConfigurationVpc{}}}},
		{"arn:aws:sqs:us-east-1:123456789012:orders", &api.PipeSourceParameters{SelfManagedKafkaParameters: &api.PipeSourceSelfManagedKafkaParameters{TopicName: &topic}}},
		{"smk://localhost:9092/path", &api.PipeSourceParameters{SelfManagedKafkaParameters: &api.PipeSourceSelfManagedKafkaParameters{TopicName: &topic}}},
	} {
		if _, err := sourceSettings(tc.arn, tc.params); err == nil {
			t.Fatalf("unsupported connector configuration accepted: %+v", tc)
		}
	}
}

func TestKafkaIdentityCannotRebindRetainedSource(t *testing.T) {
	original := KafkaIdentity{ClusterID: "native-cluster", TopicID: "native-topic"}
	for _, retained := range []string{"work", "cursor", "none", "legacy-work", "legacy-cursor"} {
		t.Run(retained, func(t *testing.T) {
			repo := NewMemoryRepository(nil)
			p := PipeRecord{ID: "pipe"}
			err := repo.Update(t.Context(), func(tx Transaction) error {
				if err := tx.PutPipe(p); err != nil {
					return err
				}
				if retained != "legacy-work" && retained != "legacy-cursor" {
					if err := bindKafkaIdentity(tx, p.ID, original); err != nil {
						return err
					}
				}
				switch retained {
				case "work", "legacy-work":
					return tx.PutWork(Work{ID: "record", PipeID: p.ID, ShardID: "0", Sequence: "0"})
				case "cursor", "legacy-cursor":
					return tx.PutCheckpoint(Checkpoint{PipeID: p.ID, ShardID: "0", Sequence: "0", Iterator: "1", Initialized: true})
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, replacement := range []KafkaIdentity{
				{ClusterID: original.ClusterID, TopicID: "replacement-topic"},
				{ClusterID: "replacement-cluster", TopicID: original.TopicID},
			} {
				err := repo.Update(t.Context(), func(tx Transaction) error {
					return bindKafkaIdentity(tx, p.ID, replacement)
				})
				if !errors.Is(err, ErrKafkaSourceChanged) {
					t.Fatalf("replacement admitted: %v", err)
				}
			}
			if retained != "legacy-work" && retained != "legacy-cursor" {
				if err := repo.Update(t.Context(), func(tx Transaction) error {
					return bindKafkaIdentity(tx, p.ID, original)
				}); err != nil {
					t.Fatalf("unchanged source could not resume: %v", err)
				}
			}
		})
	}
}
