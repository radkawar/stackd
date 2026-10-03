package lambda

import (
	"bytes"
	"encoding/json"
	"errors"
	"hash/fnv"
	"time"

	"stackd/internal/services/eventbridge/eventpattern"
)

var errStreamSequence = errors.New("invalid batch item sequence")

func streamLaneFor(key string, n int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % uint32(n))
}
func compileStreamFilters(patterns []string) ([]*eventpattern.Pattern, error) {
	out := make([]*eventpattern.Pattern, 0, len(patterns))
	for _, text := range patterns {
		p, err := eventpattern.Compile([]byte(text))
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
func matchesStreamFilters(filters []*eventpattern.Pattern, payload []byte) (bool, error) {
	if len(filters) == 0 {
		return true, nil
	}
	for _, filter := range filters {
		match, err := filter.Match(payload)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

type streamWindowInfo struct {
	Window struct {
		Start string `json:"start"`
		End   string `json:"end"`
	} `json:"window"`
	IsFinal bool `json:"isFinalInvokeForWindow"`
	Early   bool `json:"isWindowTerminatedEarly"`
}

func streamWindowMetadata(lane StreamLane) streamWindowInfo {
	var result streamWindowInfo
	result.Window.Start = lane.WindowStart.UTC().Format(time.RFC3339Nano)
	result.Window.End = lane.WindowEnd.UTC().Format(time.RFC3339Nano)
	result.IsFinal = lane.WindowFinal
	result.Early = lane.WindowEarly
	return result
}

func streamPayload(records []StreamQueuedRecord, lane StreamLane, shard, sourceARN string, window bool) ([]byte, error) {
	native := make([]json.RawMessage, len(records))
	for i, v := range records {
		native[i] = v.Payload
	}
	if !window {
		return sourceJSON(struct {
			Records []json.RawMessage `json:"Records"`
		}{native})
	}
	state := lane.WindowState
	if len(state) == 0 {
		state = json.RawMessage(`{}`)
	}
	return sourceJSON(struct {
		streamWindowInfo
		Records        []json.RawMessage `json:"Records"`
		State          json.RawMessage   `json:"state"`
		ShardID        string            `json:"shardId"`
		EventSourceARN string            `json:"eventSourceARN,omitempty"`
	}{streamWindowInfo: streamWindowMetadata(lane), Records: native, State: state, ShardID: shard, EventSourceARN: sourceARN})
}

// Streams acknowledge only the prefix before the lowest failed sequence.
func streamBatchFailure(payload []byte, records []StreamQueuedRecord) (int, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return len(records), nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &root); err != nil {
		return 0, err
	}
	raw, ok := root["batchItemFailures"]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return len(records), nil
	}
	var failures []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &failures); err != nil {
		return 0, err
	}
	lowest := len(records)
	for _, failure := range failures {
		var id string
		if err := json.Unmarshal(failure["itemIdentifier"], &id); err != nil || id == "" {
			return 0, errStreamSequence
		}
		found := false
		for i, record := range records {
			if record.Sequence == id {
				lowest = min(lowest, i)
				found = true
				break
			}
		}
		if !found {
			return 0, errStreamSequence
		}
	}
	return lowest, nil
}
