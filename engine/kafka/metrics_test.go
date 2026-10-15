package kafka

import (
	"strings"
	"testing"
)

func TestMeasuredBrokerGaugesRequireEveryNativeCounter(t *testing.T) {
	var output strings.Builder
	output.WriteString("time\t1234\n")
	for _, name := range defaultBrokerGauges {
		output.WriteString("kafka.server:type=ReplicaManager,name=" + name + ":Value\t3\n")
	}
	metrics, err := parseBrokerGauges([]byte(output.String()), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != len(defaultBrokerGauges) {
		t.Fatal("native measurements were discarded")
	}
	for _, metric := range metrics {
		if metric.BrokerID != 2 || metric.Value != 3 || metric.Unit != "Count" {
			t.Fatalf("unexpected metric: %#v", metric)
		}
	}
	if _, err := parseBrokerGauges([]byte("time\t1234\n"), 2); err == nil {
		t.Fatal("absent native counters became synthetic zeros")
	}
	if _, err := parseBrokerGauges([]byte(output.String()+"kafka.server:type=ReplicaManager,name=PartitionCount:Value\t3\n"), 2); err == nil {
		t.Fatal("duplicate native counter was accepted")
	}
}
