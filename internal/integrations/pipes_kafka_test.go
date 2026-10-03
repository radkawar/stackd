package integrations

import (
	"context"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/protocol"
	"github.com/twmb/franz-go/pkg/kmsg"
	"stackd/internal/services/pipes"
)

func TestKafkaReadCommittedSkipsAbortedTransactionsAndRetainsCursor(t *testing.T) {
	record := func(offset int64, body string) protocol.Record {
		return protocol.Record{Offset: offset, Time: time.UnixMilli(1700000000000 + offset), Value: protocol.NewBytes([]byte(body))}
	}
	batch := func(offset int64, transactional bool, body string) *protocol.RecordBatch {
		attributes := protocol.Attributes(8)
		if transactional {
			attributes |= protocol.Transactional
		}
		return &protocol.RecordBatch{BaseOffset: offset, ProducerID: 7, Attributes: attributes, Records: protocol.NewRecordReader(record(offset, body))}
	}
	marker := func(offset int64) *protocol.ControlBatch {
		return &protocol.ControlBatch{BaseOffset: offset, ProducerID: 7, Records: protocol.NewRecordReader(record(offset, "marker"))}
	}
	stream := &protocol.RecordStream{Records: []protocol.RecordReader{
		batch(4, true, "aborted-one"), marker(5), batch(6, true, "committed"),
		batch(7, true, "aborted-two"), marker(8), batch(9, false, "ordinary"),
	}}
	reader := pipesKafkaRead{page: pipes.KafkaPage{NextOffset: 4}, partition: 2, offset: 4, limit: 10, aborted: map[int64][]int64{7: {4, 7}}}
	if err := reader.read(stream, "CREATE_TIME", false); err != nil {
		t.Fatal(err)
	}
	if len(reader.page.Records) != 2 || string(reader.page.Records[0].Value) != "committed" || string(reader.page.Records[1].Value) != "ordinary" {
		t.Fatalf("aborted/control records escaped into delivery: %+v", reader.page)
	}
	if reader.page.NextOffset != 10 || reader.page.Records[0].Offset != 6 || reader.page.Records[0].TimestampType != "LOG_APPEND_TIME" {
		t.Fatalf("native record metadata/cursor lost: %+v", reader.page)
	}
}

func TestKafkaReadLimitDoesNotSkipUnretainedRecords(t *testing.T) {
	reader := pipesKafkaRead{page: pipes.KafkaPage{NextOffset: 11}, partition: 0, offset: 11, limit: 1}
	stream := protocol.NewRecordReader(
		protocol.Record{Offset: 10, Value: protocol.NewBytes([]byte("already-read"))},
		protocol.Record{Offset: 11, Value: protocol.NewBytes([]byte("retain"))},
		protocol.Record{Offset: 12, Value: protocol.NewBytes([]byte("next-fetch"))},
	)
	if err := reader.read(stream, "CREATE_TIME", false); err != nil {
		t.Fatal(err)
	}
	if len(reader.page.Records) != 1 || reader.page.Records[0].Offset != 11 || reader.page.NextOffset != 12 {
		t.Fatalf("fetch limit skipped native bytes: %+v", reader.page)
	}
}

func TestKafkaGenerationRevocationCancelsTargetLease(t *testing.T) {
	generation, revoke := context.WithCancel(t.Context())
	lifetime, closeConsumer := context.WithCancel(t.Context())
	defer closeConsumer()
	leased, release := kafkaGenerationContext(t.Context(), generation, lifetime)
	defer release()
	revoke()
	select {
	case <-leased.Done():
	case <-time.After(time.Second):
		t.Fatal("revoked generation left target lease live")
	}
}

func TestKafkaSASLNeverDowngradesToPlaintext(t *testing.T) {
	access := pipesKafkaAccess{mechanism: "SCRAM-SHA-512", credentials: []byte(`{"username":"reader","password":"secret"}`)}
	if _, _, err := access.security(); err == nil {
		t.Fatal("SASL source accepted without encrypted transport")
	}
	access.tls = true
	access.ca = []byte("not a CA certificate")
	if _, _, err := access.security(); err == nil {
		t.Fatal("invalid CA silently fell back to system trust")
	}
	access.ca = nil
	access.mechanism = "OAUTHBEARER"
	if _, _, err := access.security(); err == nil {
		t.Fatal("unsupported SASL silently fell back to unauthenticated access")
	}
}

func TestKafkaMetadataRequiresNativeIncarnation(t *testing.T) {
	cluster, topic := "native-cluster", "orders"
	id := [16]byte{1, 2, 3, 4}
	response := kmsg.MetadataResponse{Version: 10, ClusterID: &cluster, Topics: []kmsg.MetadataResponseTopic{{Topic: &topic, TopicID: id}}}
	for _, tc := range []struct {
		name   string
		change func(*kmsg.MetadataResponse)
	}{
		{"older-broker", func(r *kmsg.MetadataResponse) { r.Version = 8 }},
		{"missing-cluster", func(r *kmsg.MetadataResponse) { r.ClusterID = nil }},
		{"zero-topic-id", func(r *kmsg.MetadataResponse) { r.Topics[0].TopicID = [16]byte{} }},
		{"denied-topic", func(r *kmsg.MetadataResponse) { r.Topics[0].ErrorCode = int16(kafka.TopicAuthorizationFailed) }},
		{"missing-topic", func(r *kmsg.MetadataResponse) { r.Topics = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := response
			copy.Topics = append([]kmsg.MetadataResponseTopic(nil), response.Topics...)
			tc.change(&copy)
			if _, err := kafkaMetadataIdentity(topic, &copy); err == nil {
				t.Fatal("identity-less or inaccessible source admitted")
			}
		})
	}
	actual, err := kafkaMetadataIdentity(topic, &response)
	if err != nil || actual != (pipes.KafkaIdentity{ClusterID: cluster, TopicID: "01020304000000000000000000000000"}) {
		t.Fatalf("native identity changed: %+v %v", actual, err)
	}
	consumer := pipesKafkaConsumer{identity: actual}
	if err := consumer.acceptIdentity(pipes.KafkaIdentity{ClusterID: cluster, TopicID: "replacement"}); err != pipes.ErrKafkaSourceChanged || !consumer.sourceChanged {
		t.Fatalf("replacement not fenced: %v", err)
	}
}
