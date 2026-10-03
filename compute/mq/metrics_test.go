package mq

import (
	"reflect"
	"strings"
	"testing"

	service "stackd/internal/services/mq"
)

func TestRabbitQueueMetricsPreserveNamesAndOrder(t *testing.T) {
	data := []byte(`{"result":"ok","value":{"exchanges":9,"connections":2,"channels":5,"queues":[
		{"virtual_host":"/雪","name":"with space\n","ready":3,"unacknowledged":2,"consumers":1},
		{"virtual_host":"/","name":"z","ready":0,"unacknowledged":0,"consumers":0},
		{"virtual_host":"/","name":"a","ready":7,"unacknowledged":1,"consumers":4}
	]}}`)
	snapshot, err := parseRabbitQueueMetrics(data)
	want := service.MetricSnapshot{RabbitMQ: &service.RabbitMQMetrics{
		Exchanges: 9, Connections: 2, Channels: 5,
		Queues: []service.QueueMetrics{
			{VirtualHost: "/", Name: "a", Ready: 7, Unacknowledged: 1, Consumers: 4},
			{VirtualHost: "/", Name: "z"},
			{VirtualHost: "/雪", Name: "with space\n", Ready: 3, Unacknowledged: 2, Consumers: 1},
		},
	}}
	if err != nil || !reflect.DeepEqual(snapshot, want) {
		t.Fatalf("native names/counters changed: %+v, %v", snapshot, err)
	}
}

func TestRabbitQueueMetricsRejectIncompleteCounters(t *testing.T) {
	valid := `{"virtual_host":"/","name":"q","ready":1,"unacknowledged":2,"consumers":3}`
	rows := map[string]string{
		"missing vhost":          strings.Replace(valid, `"virtual_host":"/",`, "", 1),
		"missing name":           strings.Replace(valid, `"name":"q",`, "", 1),
		"missing ready":          strings.Replace(valid, `"ready":1,`, "", 1),
		"missing unacknowledged": strings.Replace(valid, `"unacknowledged":2,`, "", 1),
		"missing consumers":      strings.Replace(valid, `,"consumers":3`, "", 1),
		"null counter":           strings.Replace(valid, `"ready":1`, `"ready":null`, 1),
		"negative counter":       strings.Replace(valid, `"ready":1`, `"ready":-1`, 1),
		"fractional counter":     strings.Replace(valid, `"ready":1`, `"ready":1.5`, 1),
		"overflow counter":       strings.Replace(valid, `"ready":1`, `"ready":9223372036854775808`, 1),
		"unavailable counter":    strings.Replace(valid, `"ready":1`, `"ready":""`, 1),
		"duplicate queue":        valid + "," + valid,
	}
	for name, rows := range rows {
		t.Run(name, func(t *testing.T) {
			snapshot, err := parseRabbitQueueMetrics([]byte(`{"result":"ok","value":{"exchanges":7,"connections":1,"channels":1,"queues":[` + rows + `]}}`))
			if err == nil || !reflect.DeepEqual(snapshot, service.MetricSnapshot{}) {
				t.Fatalf("accepted incomplete native sample: %+v, %v", snapshot, err)
			}
		})
	}
}

func TestRabbitQueueMetricsRequireCompleteBoundedInventory(t *testing.T) {
	for _, data := range []string{
		`{}`, `null`, `{"result":"ok"}`, `{"result":"ok","value":{}}`,
		`{"result":"ok","value":{"exchanges":7,"connections":0,"channels":0}}`,
		`{"result":"ok","value":{"exchanges":7,"connections":0,"channels":0,"queues":null}}`,
		`{"result":"error","value":{"exchanges":7,"connections":0,"channels":0,"queues":[]}}`,
		`{"result":"ok","value":{"exchanges":7,"connections":0,"channels":0,"queues":[`,
		`{"result":"ok","value":{"exchanges":7,"connections":0,"channels":0,"queues":[]}} trailing`,
		`{"result":"ok","value":{"exchanges":7,"connections":0,"channels":0,"queues":[]},"node":"` + string([]byte{0xff}) + `"}`,
		strings.Repeat(" ", mqMetricReadBytes+1),
	} {
		if snapshot, err := parseRabbitQueueMetrics([]byte(data)); err == nil || !reflect.DeepEqual(snapshot, service.MetricSnapshot{}) {
			t.Fatalf("accepted invalid inventory (%d bytes): %+v, %v", len(data), snapshot, err)
		}
	}
	snapshot, err := parseRabbitQueueMetrics([]byte(`{"result":"ok","value":{"exchanges":0,"connections":0,"channels":0,"queues":[]}}`))
	if err != nil || !reflect.DeepEqual(snapshot, service.MetricSnapshot{RabbitMQ: &service.RabbitMQMetrics{Queues: []service.QueueMetrics{}}}) {
		t.Fatalf("rejected real empty inventory: %+v, %v", snapshot, err)
	}
}

func TestRabbitMetricsRequireMeasuredBrokerCounters(t *testing.T) {
	valid := `{"result":"ok","value":{"queues":[],"exchanges":7,"connections":2,"channels":3}}`
	for field, value := range map[string]string{"exchanges": "7", "connections": "2", "channels": "3"} {
		counter := `,"` + field + `":` + value
		t.Run(field, func(t *testing.T) {
			rows := map[string]string{
				"missing":     strings.Replace(valid, counter, "", 1),
				"null":        strings.Replace(valid, counter, `,"`+field+`":null`, 1),
				"negative":    strings.Replace(valid, counter, `,"`+field+`":-1`, 1),
				"fractional":  strings.Replace(valid, counter, `,"`+field+`":1.5`, 1),
				"overflow":    strings.Replace(valid, counter, `,"`+field+`":9223372036854775808`, 1),
				"unavailable": strings.Replace(valid, counter, `,"`+field+`":""`, 1),
			}
			for name, data := range rows {
				t.Run(name, func(t *testing.T) {
					snapshot, err := parseRabbitQueueMetrics([]byte(data))
					if err == nil || !reflect.DeepEqual(snapshot, service.MetricSnapshot{}) {
						t.Fatalf("accepted incomplete native broker sample: %+v, %v", snapshot, err)
					}
				})
			}
		})
	}
}

func TestRabbitMetricsPreserveLargestBrokerCounters(t *testing.T) {
	snapshot, err := parseRabbitQueueMetrics([]byte(`{"result":"ok","value":{"queues":[],"exchanges":9223372036854775807,"connections":9223372036854775807,"channels":9223372036854775807}}`))
	want := service.MetricSnapshot{RabbitMQ: &service.RabbitMQMetrics{
		Queues: []service.QueueMetrics{}, Exchanges: 9223372036854775807,
		Connections: 9223372036854775807, Channels: 9223372036854775807,
	}}
	if err != nil || !reflect.DeepEqual(snapshot, want) {
		t.Fatalf("lost integer counter precision: %+v, %v", snapshot, err)
	}
}
