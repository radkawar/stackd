package stackd_test

import (
	"encoding/json"
	"os"
	"testing"
)

func TestEC2NativeInternetGatewaysAndRoutes(t *testing.T) {
	body, err := os.ReadFile("../testdata/aws/ec2/internet_gateways.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Calls      []ec2NetworkCapture
		CloudTrail struct{ Events []map[string]any }
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	events := make(map[string]map[string]any, len(fixture.CloudTrail.Events))
	for _, event := range fixture.CloudTrail.Events {
		events[event["requestID"].(string)] = event
	}
	for index := range fixture.Calls {
		fixture.Calls[index].Audit = events[fixture.Calls[index].RequestID]
	}
	// Replay every EC2 call, including unsuccessful mutations and the cleanup
	// absence checks. The shared runner reopens storage after each mutation and
	// independently decodes the retained AWS responses with the SDK.
	replayEC2NetworkRows(t, fixture.Calls)
}
