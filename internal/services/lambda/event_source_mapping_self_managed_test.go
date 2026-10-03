package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func TestSelfManagedKafkaNativeMissingSourceAccess(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/lambda/self_managed_kafka_admission.json")
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
	for _, row := range fixture.Observations {
		if row.Label != "disabled_public_source" {
			continue
		}
		var input api.CreateEventSourceMappingInput
		if err := json.Unmarshal(row.Input, &input); err != nil {
			t.Fatal(err)
		}
		s := New(Config{})
		defer s.Close()
		_, wire := (kafkaMappingControl{s}).createSettings(&input)
		if wire == nil || wire.Code != row.Result.Code {
			t.Fatalf("native %s; local %v", row.Result.Code, wire)
		}
		return
	}
	t.Fatal("native source-access observation is absent")
}

func TestSelfManagedKafkaPayloadHasNoSyntheticARN(t *testing.T) {
	mapping := EventSourceMappingRecord{Settings: EventSourceMappingSettings{Kafka: &KafkaMappingSettings{Topic: "source", BootstrapServers: []string{"broker.example:9093"}}}}
	record, err := kafkaRecordEvent("source", KafkaRecord{Partition: 0, Offset: 4, Timestamp: time.Unix(12, 0), Value: []byte("message")})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := kafkaEventPayload(mapping, "broker.example:9093", 0, []json.RawMessage{record})
	if err != nil {
		t.Fatal(err)
	}
	var event map[string]json.RawMessage
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	if string(event["eventSource"]) != `"SelfManagedKafka"` || event["eventSourceArn"] != nil {
		t.Fatalf("wrong self-managed envelope: %s", payload)
	}
}

func TestSelfManagedKafkaAuthenticationCannotDowngrade(t *testing.T) {
	const secret = "arn:aws:secretsmanager:us-east-1:123456789012:secret:credential"
	access := func(kind string) api.SourceAccessConfiguration {
		return api.SourceAccessConfiguration{Type: new(api.SourceAccessType(kind)), URI: new(api.URI(secret))}
	}
	for _, kinds := range [][]string{{"SASL_SCRAM_256_AUTH", "BASIC_AUTH"}, {"CLIENT_CERTIFICATE_TLS_AUTH", "SASL_SCRAM_512_AUTH"}, {"SERVER_ROOT_CA_CERTIFICATE", "SERVER_ROOT_CA_CERTIFICATE"}} {
		d := KafkaMappingSettings{BootstrapServers: []string{"broker.example:9093"}}
		if wire := kafkaSourceAccess(&d, api.SourceAccessConfigurations{access(kinds[0]), access(kinds[1])}); wire == nil {
			t.Fatalf("accepted ambiguous credentials %v", kinds)
		}
	}
	managed := KafkaMappingSettings{}
	if wire := kafkaSourceAccess(&managed, api.SourceAccessConfigurations{access("BASIC_AUTH")}); wire == nil {
		t.Fatal("MSK accepted self-managed PLAIN override")
	}
}

func TestSelfManagedKafkaDistinctBrokerSetsDoNotConflict(t *testing.T) {
	repo := NewMemoryRepository(nil)
	scope := Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
	row := EventSourceMappingRecord{Key: EventSourceMappingKey{Scope: scope, UUID: "first"}, Function: FunctionReference{FunctionKey: FunctionKey{Scope: scope, Name: "consumer"}}, Settings: EventSourceMappingSettings{Kafka: &KafkaMappingSettings{Topic: "topic", ConsumerGroupID: "group", BootstrapServers: []string{"first.example:9093"}}}}
	if err := repo.Update(context.Background(), func(tx Transaction) error { return tx.PutEventSourceMapping(row) }); err != nil {
		t.Fatal(err)
	}
	proposed := cloneEventSourceMapping(row)
	proposed.Key.UUID = "second"
	proposed.Settings.Kafka.BootstrapServers[0] = "second.example:9093"
	if err := repo.View(context.Background(), func(r Reader) error { return mappingUnique(r, proposed) }); err != nil {
		t.Fatalf("independent broker source conflicts: %v", err)
	}
	proposed.Settings.Kafka.BootstrapServers[0] = "first.example:9093"
	err := repo.View(context.Background(), func(r Reader) error { return mappingUnique(r, proposed) })
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != "ResourceConflictException" {
		t.Fatalf("duplicate consumer group accepted: %v", err)
	}
}
