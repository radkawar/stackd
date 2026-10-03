package stackd_test

import (
	"encoding/json"
	"testing"

	"stackd/internal/awstest"
)

// DynamoDB fixtures share native union decoding with the other SDK consumers.
func dynamoSDKInput(t *testing.T, target any, raw json.RawMessage) {
	t.Helper()
	if err := awstest.DecodeSDK(raw, target); err != nil {
		t.Fatal(err)
	}
}
