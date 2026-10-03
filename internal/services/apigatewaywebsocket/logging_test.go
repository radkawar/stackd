package apigatewaywebsocket

import (
	"strings"
	"testing"
)

func TestExecutionLogTruncatesUnicodePayload(t *testing.T) {
	const requestID = "00000000-0000-4000-8000-000000000000"
	record := eventLog{info: true, requestID: requestID}
	record.information("Endpoint request body: %s", strings.Repeat("界", 1200))

	// AWS limits REST/WebSocket execution events to 1024 bytes, including
	// correlation text. A partial UTF-8 character must not reach Logs.
	prefix := "(" + requestID + ") Endpoint request body: "
	want := prefix + strings.Repeat("界", (1024-len(prefix))/len("界"))
	if len(record.execution) != 1 || record.execution[0] != want {
		t.Fatalf("execution event did not preserve the complete UTF-8 prefix at the byte limit: %q", record.execution)
	}
}
