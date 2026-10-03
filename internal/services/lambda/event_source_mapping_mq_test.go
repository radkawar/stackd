package lambda

import (
	"encoding/json"
	"testing"

	api "stackd/internal/awsapi/lambda"
)

func TestMQFilterDataFormats(t *testing.T) {
	// https://docs.aws.amazon.com/lambda/latest/dg/with-mq-filtering.html
	cases := []struct {
		name, pattern string
		data          []byte
		want          bool
	}{
		{"structured match", `{"data":{"amount":[{"numeric":[">",2]}]}}`, []byte(`{"amount":3}`), true},
		{"structured reject", `{"data":{"amount":[{"numeric":[">",2]}]}}`, []byte(`{"amount":1}`), false},
		{"plain prefix", `{"data":[{"prefix":"Result: "}]}`, []byte("Result: ready"), true},
		{"plain reject", `{"data":[{"prefix":"Result: "}]}`, []byte("other"), false},
		{"JSON plain mismatch", `{"data":["never"]}`, []byte(`{"amount":1}`), true},
		{"non UTF8 mismatch", `{"data":{"amount":[2]}}`, []byte{0xff, 0}, true},
		{"nested OR", `{"$or":[{"data":{"kind":["one"]}},{"data":{"kind":["two"]}}]}`, []byte(`{"kind":"two"}`), true},
		{"nested OR reject", `{"$or":[{"data":{"kind":["one"]}},{"data":{"kind":["two"]}}]}`, []byte(`{"kind":"three"}`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filters, err := compileMQMappingFilters([]string{tc.pattern})
			if err != nil {
				t.Fatal(err)
			}
			match, err := matchesKafkaMappingFilters(filters, KafkaRecord{Value: tc.data}, []byte(`{}`))
			if err != nil || match != tc.want {
				t.Fatalf("match=%v error=%v want=%v", match, err, tc.want)
			}
		})
	}
	if err := validateMQMappingFilter(`{"messageID":["not-filterable"]}`); err == nil {
		t.Fatal("MQ metadata filter was admitted")
	}
}
func TestMQEventPreservesNativeEnvelope(t *testing.T) {
	for _, engine := range []string{"RABBITMQ", "ACTIVEMQ"} {
		t.Run(engine, func(t *testing.T) {
			mapping := EventSourceMappingRecord{EventSourceARN: "arn:aws:mq:us-east-1:123456789012:broker:owned:b-123", Settings: EventSourceMappingSettings{MQ: &MQMappingSettings{Queue: "queue", VirtualHost: "/tenant", Identity: MQIdentity{Engine: engine}}}}
			payload, err := mqEventPayload(mapping, []json.RawMessage{json.RawMessage(`{"data":"AP8=","redelivered":true}`)})
			if err != nil {
				t.Fatal(err)
			}
			var event struct {
				EventSource string `json:"eventSource"`
				ARN         string `json:"eventSourceArn"`
				Messages    []struct {
					Data        []byte
					Redelivered bool
				} `json:"messages"`
				Queues map[string][]struct {
					Data        []byte
					Redelivered bool
				} `json:"rmqMessagesByQueue"`
			}
			if err = json.Unmarshal(payload, &event); err != nil {
				t.Fatal(err)
			}
			if event.ARN != mapping.EventSourceARN {
				t.Fatal("source ARN changed")
			}
			rows := event.Messages
			if engine == "RABBITMQ" {
				rows = event.Queues["queue::/tenant"]
				if event.EventSource != "aws:rmq" || event.Messages != nil {
					t.Fatalf("wrong RabbitMQ envelope: %s", payload)
				}
			} else if event.EventSource != "aws:mq" || event.Queues != nil {
				t.Fatalf("wrong ActiveMQ envelope: %s", payload)
			}
			if len(rows) != 1 || string(rows[0].Data) != string([]byte{0, 255}) || !rows[0].Redelivered {
				t.Fatalf("native message bytes/redelivery changed: %s", payload)
			}
		})
	}
}

func TestMQCredentialRotationPreservesVirtualHost(t *testing.T) {
	control := mqMappingControl{}
	original := "arn:aws:secretsmanager:us-east-1:123456789012:secret:original"
	replacement := "arn:aws:secretsmanager:us-east-1:123456789012:secret:replacement"
	settings, wire := control.createSettings(&api.CreateEventSourceMappingInput{
		Queues: api.Queues{"events"},
		SourceAccessConfigurations: api.SourceAccessConfigurations{
			{Type: new(api.SourceAccessType("BASIC_AUTH")), URI: new(api.URI(original))},
			{Type: new(api.SourceAccessType("VIRTUAL_HOST")), URI: new(api.URI("/tenant"))},
		},
	})
	if wire != nil {
		t.Fatal(wire)
	}
	updated, wire := control.updateSettings(settings, &api.UpdateEventSourceMappingInput{
		SourceAccessConfigurations: api.SourceAccessConfigurations{
			{Type: new(api.SourceAccessType("BASIC_AUTH")), URI: new(api.URI(replacement))},
		},
	})
	if wire != nil || updated.MQ.SecretARN != replacement || updated.MQ.VirtualHost != "/tenant" || !updated.MQ.VirtualHostSet {
		t.Fatalf("credential rotation changed source namespace: %+v, %v", updated.MQ, wire)
	}
	if settings.MQ.SecretARN != original || settings.MQ.VirtualHost != "/tenant" {
		t.Fatalf("credential rotation mutated prior settings: %+v", settings.MQ)
	}
}

func TestMQVirtualHostIsCreateOnly(t *testing.T) {
	// https://docs.aws.amazon.com/lambda/latest/api/API_SourceAccessConfiguration.html
	settings := EventSourceMappingSettings{BatchSize: 100, MQ: &MQMappingSettings{
		Queue: "events", VirtualHost: "/tenant",
		SecretARN: "arn:aws:secretsmanager:us-east-1:123456789012:secret:original",
	}}
	_, wire := (mqMappingControl{}).updateSettings(settings, &api.UpdateEventSourceMappingInput{
		SourceAccessConfigurations: api.SourceAccessConfigurations{
			{Type: new(api.SourceAccessType("BASIC_AUTH")), URI: new(api.URI(settings.MQ.SecretARN))},
			{Type: new(api.SourceAccessType("VIRTUAL_HOST")), URI: new(api.URI("/tenant"))},
		},
	})
	if wire == nil || wire.Code != "InvalidParameterValueException" {
		t.Fatalf("unchanged virtual-host parameter accepted on update: %v", wire)
	}
}
