package kafka

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	msk "stackd/internal/services/kafka"
)

var defaultBrokerGauges = [...]string{"PartitionCount", "LeaderCount", "UnderReplicatedPartitions", "UnderMinIsrPartitionCount"}

// ReadMetrics queries Kafka's actual ReplicaManager MBeans in the broker
// container. JMX/RMI bind container loopback only and are never published. These
// are the measured DEFAULT broker gauges, not a complete AWS metric catalogue.
// Kafka3.7.1 JmxTool source: https://github.com/apache/kafka/blob/3.7.1/tools/src/main/java/org/apache/kafka/tools/JmxTool.java
func (d *Docker) ReadMetrics(ctx context.Context, spec msk.Specification) ([]msk.BrokerMetric, error) {
	if !spec.DefaultMetrics {
		return nil, errors.New("native Kafka monitoring was not enabled")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()
	result := make([]msk.BrokerMetric, 0, int(spec.Brokers)*len(defaultBrokerGauges))
	command := []string{"/usr/bin/env", "-u", "JMX_PORT", "-u", "KAFKA_JMX_OPTS", "KAFKA_HEAP_OPTS=-Xms16m -Xmx64m", "/opt/kafka/bin/kafka-run-class.sh", "org.apache.kafka.tools.JmxTool", "--jmx-url", "service:jmx:rmi:///jndi/rmi://127.0.0.1:9010/jmxrmi", "--attributes", "Value", "--one-time", "--report-format", "tsv", "--wait"}
	for _, name := range defaultBrokerGauges {
		command = append(command, "--object-name", "kafka.server:type=ReplicaManager,name="+name)
	}
	for id := int32(1); id <= spec.Brokers; id++ {
		role := "broker-" + strconv.Itoa(int(id))
		state, err := d.inspect(ctx, resourceName(spec, role))
		if err != nil {
			return nil, err
		}
		if err = d.checkContainer(state, spec, role, nil); err != nil {
			return nil, err
		}
		if !state.State.Running {
			return nil, errors.New("native Kafka metrics broker is stopped")
		}
		output, err := d.execute(ctx, state.ID, command)
		if err != nil {
			return nil, err
		}
		measured, err := parseBrokerGauges(output, id)
		if err != nil {
			return nil, err
		}
		result = append(result, measured...)
	}
	return result, nil
}

func parseBrokerGauges(output []byte, id int32) ([]msk.BrokerMetric, error) {
	values := make(map[string]float64, len(defaultBrokerGauges))
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
		key, raw, ok := strings.Cut(line, "\t")
		if !ok || key == "time" {
			continue
		}
		for _, name := range defaultBrokerGauges {
			if key == "kafka.server:type=ReplicaManager,name="+name+":Value" {
				value, err := strconv.ParseFloat(raw, 64)
				if err != nil || value < 0 {
					return nil, fmt.Errorf("invalid native Kafka %s measurement %q", name, raw)
				}
				if _, duplicate := values[name]; duplicate {
					return nil, fmt.Errorf("duplicate native Kafka %s measurement", name)
				}
				values[name] = value
			}
		}
	}
	result := make([]msk.BrokerMetric, 0, len(defaultBrokerGauges))
	for _, name := range defaultBrokerGauges {
		value, exists := values[name]
		if !exists {
			return nil, fmt.Errorf("native Kafka JMX omitted %s; refusing a synthetic zero", name)
		}
		result = append(result, msk.BrokerMetric{BrokerID: id, Name: name, Unit: "Count", Value: value})
	}
	return result, nil
}
