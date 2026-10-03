package mq

import (
	"reflect"
	"strings"
	"testing"

	service "stackd/internal/services/mq"
)

func TestActiveMQMetricsPreserveDestinationIdentity(t *testing.T) {
	data := []byte(`{"connections":2,"consumers":3,"messages":7,"producers":4,"inactive_durable_topic_subscribers":2001,"destinations":[
		{"name":"space : = 雪\n","kind":"Topic","consumers":2,"producers":3},
		{"name":"space : = 雪\n","kind":"Queue","consumers":1,"producers":1,"queue_size":7},
		{"name":"ActiveMQ.Advisory.Connection","kind":"Topic","consumers":0,"producers":0}
	]}`)
	got, err := parseActiveMQMetrics(data)
	want := service.MetricSnapshot{ActiveMQ: &service.ActiveMQMetrics{
		Connections: 2, Consumers: 3, Messages: 7, Producers: 4,
		InactiveDurableTopicSubscribers: 2001,
		Destinations: []service.ActiveMQDestinationMetrics{
			{Name: "space : = 雪\n", Kind: "Queue", Consumers: 1, Producers: 1, QueueSize: 7},
			{Name: "ActiveMQ.Advisory.Connection", Kind: "Topic"},
			{Name: "space : = 雪\n", Kind: "Topic", Consumers: 2, Producers: 3},
		},
	}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("native destination names/counters changed: %+v, %v", got, err)
	}
}

func TestActiveMQMetricsRejectIncompleteDestinationCounters(t *testing.T) {
	valid := `{"name":"q","kind":"Queue","queue_size":7,"consumers":1,"producers":2}`
	rows := map[string]string{
		"missing name":          strings.Replace(valid, `"name":"q",`, "", 1),
		"missing kind":          strings.Replace(valid, `"kind":"Queue",`, "", 1),
		"unsupported kind":      strings.Replace(valid, `"Queue"`, `"Stream"`, 1),
		"empty name":            strings.Replace(valid, `"q"`, `""`, 1),
		"duplicate destination": valid + "," + valid,
		"topic queue size":      strings.Replace(valid, `"Queue"`, `"Topic"`, 1),
	}
	for field, value := range map[string]string{"queue_size": "7", "consumers": "1", "producers": "2"} {
		counter := `,"` + field + `":` + value
		rows[field+" missing"] = strings.Replace(valid, counter, "", 1)
		for _, invalid := range []string{"null", "-1", "1.5", "9223372036854775808", `"1"`} {
			rows[field+" "+invalid] = strings.Replace(valid, counter, `,"`+field+`":`+invalid, 1)
		}
	}
	for name, row := range rows {
		t.Run(name, func(t *testing.T) {
			got, err := parseActiveMQMetrics([]byte(`{"connections":0,"consumers":1,"messages":7,"producers":2,"inactive_durable_topic_subscribers":0,"destinations":[` + row + `]}`))
			if err == nil || !reflect.DeepEqual(got, service.MetricSnapshot{}) {
				t.Fatalf("accepted incomplete native destination: %+v, %v", got, err)
			}
		})
	}
}

func TestActiveMQMetricsRequireCompleteBrokerSnapshot(t *testing.T) {
	valid := `{"destinations":[],"connections":1,"consumers":2,"messages":3,"producers":4,"inactive_durable_topic_subscribers":5}`
	for field, value := range map[string]string{"connections": "1", "consumers": "2", "messages": "3", "producers": "4", "inactive_durable_topic_subscribers": "5"} {
		counter := `,"` + field + `":` + value
		for _, replacement := range []string{"", `,"` + field + `":null`, `,"` + field + `":-1`, `,"` + field + `":1.5`, `,"` + field + `":9223372036854775808`, `,"` + field + `":"1"`} {
			data := strings.Replace(valid, counter, replacement, 1)
			if got, err := parseActiveMQMetrics([]byte(data)); err == nil || !reflect.DeepEqual(got, service.MetricSnapshot{}) {
				t.Fatalf("accepted invalid broker counter %s: %+v, %v", field, got, err)
			}
		}
	}
	for _, data := range []string{
		`{}`, `null`, strings.Replace(valid, `"destinations":[],`, "", 1), strings.Replace(valid, `[]`, `null`, 1),
		valid + " trailing", strings.Replace(valid, `[]`, `[{`, 1),
		strings.Replace(valid, `[]`, `[],"invalid":"`+string([]byte{0xff})+`"`, 1),
		strings.Repeat(" ", mqMetricReadBytes+1),
	} {
		if got, err := parseActiveMQMetrics([]byte(data)); err == nil || !reflect.DeepEqual(got, service.MetricSnapshot{}) {
			t.Fatalf("accepted incomplete or malformed inventory: %+v, %v", got, err)
		}
	}
	got, err := parseActiveMQMetrics([]byte(`{"connections":0,"consumers":0,"messages":9223372036854775807,"producers":0,"inactive_durable_topic_subscribers":0,"destinations":[]}`))
	want := service.MetricSnapshot{ActiveMQ: &service.ActiveMQMetrics{Messages: 9223372036854775807, Destinations: []service.ActiveMQDestinationMetrics{}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("lost empty native inventory or integer precision: %+v, %v", got, err)
	}
}
