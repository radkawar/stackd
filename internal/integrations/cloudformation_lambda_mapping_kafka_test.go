package integrations

import (
	"testing"

	"stackd/internal/services/cloudformation"
)

func TestKafkaMappingTopicChangePrecedesGroupReplacement(t *testing.T) {
	before := cloudformation.Properties{
		"FunctionName":                        "function",
		"EventSourceArn":                      "arn:aws:kafka:us-east-1:123456789012:cluster/source/id",
		"StartingPosition":                    "TRIM_HORIZON",
		"Topics":                              []any{"before"},
		"AmazonManagedKafkaEventSourceConfig": map[string]any{"ConsumerGroupId": "before"},
	}
	for _, row := range []struct {
		name, topic, position string
		want                  bool
	}{
		{"group alone replaces", "before", "TRIM_HORIZON", true},
		{"topic update fails before group replacement", "after", "TRIM_HORIZON", false},
		{"create-only position change takes precedence", "after", "LATEST", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			after := cloudformation.Properties{
				"FunctionName": "function", "EventSourceArn": before["EventSourceArn"],
				"StartingPosition": row.position, "Topics": []any{row.topic},
				"AmazonManagedKafkaEventSourceConfig": map[string]any{"ConsumerGroupId": "after"},
			}
			got, err := (cfnLambdaMapping{}).Replacement(before, after)
			if err != nil || got != row.want {
				t.Fatalf("replacement = %v, %v; want %v", got, err, row.want)
			}
		})
	}
}
