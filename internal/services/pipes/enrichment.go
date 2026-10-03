package pipes

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// enrichmentPayloads preserves scalar results and the documented empty-response
// filters. Arrays become target records; [{}] is deliberately not an empty result.
// https://docs.aws.amazon.com/eventbridge/latest/userguide/pipes-enrichment.html
// Response I/O owners enforce their own bounds; compressed HTTP responses can
// expand beyond 6 MiB before a target template removes large fields.
func enrichmentPayloads(response []byte) ([][]byte, error) {
	response = bytes.TrimSpace(response)
	if len(response) == 0 {
		return nil, nil
	}
	if response[0] == '[' {
		var values []json.RawMessage
		if err := json.Unmarshal(response, &values); err != nil {
			return nil, fmt.Errorf("invalid enrichment JSON response: %w", err)
		}
		out := make([][]byte, len(values))
		for i := range values {
			out[i] = values[i]
		}
		return out, nil
	}
	if !json.Valid(response) {
		return nil, fmt.Errorf("enrichment response is not valid JSON")
	}
	if bytes.Equal(response, []byte("null")) || bytes.Equal(response, []byte(`""`)) || response[0] == '{' && len(bytes.TrimSpace(response[1:len(response)-1])) == 0 {
		return nil, nil
	}
	return [][]byte{response}, nil
}
