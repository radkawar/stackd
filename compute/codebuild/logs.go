package codebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
)

func (e *dockerExecution) sensitiveValues(ctx context.Context, state containerState) ([]string, error) {
	names := map[string]bool{
		"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true, "AWS_CONTAINER_AUTHORIZATION_TOKEN": true,
		"GIT_SOURCE_USERNAME": true, "GIT_SOURCE_PASSWORD": true,
	}
	files, err := e.archive(ctx, "/codebuild/control")
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if file.Path != "spec.json" {
			continue
		}
		var retained retainedSpec
		if err := json.Unmarshal(file.Body, &retained); err != nil {
			return nil, err
		}
		for _, name := range retained.SensitiveEnvironment {
			names[name] = true
		}
		break
	}
	var values []string
	for _, entry := range state.Config.Env {
		name, value, ok := strings.Cut(entry, "=")
		if ok && names[name] && value != "" {
			values = append(values, value)
		}
	}
	// Match longer values first when one secret is a prefix of another.
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	return values, nil
}

// Offsets count native bytes rather than replacement bytes. While the process
// runs, a trailing prefix of a secret remains unread until its next output (or
// exit), so polling cannot publish a secret one fragment at a time.
func redactLogs(data []byte, secrets []string, running bool) ([]byte, int) {
	consumed := len(data)
	if running {
		for _, secret := range secrets {
			for size := min(len(secret)-1, len(data)); size > 0; size-- {
				if bytes.Equal(data[len(data)-size:], []byte(secret[:size])) {
					consumed = min(consumed, len(data)-size)
					break
				}
			}
		}
		// Holding a suffix must not split another already complete secret. Extend
		// the held region across all overlapping exact matches before publishing.
		changed := true
		for changed {
			changed = false
			for _, secret := range secrets {
				if secret == "" {
					continue
				}
				start := max(0, consumed-len(secret)+1)
				for start < consumed {
					relative := bytes.Index(data[start:], []byte(secret))
					if relative < 0 {
						break
					}
					index := start + relative
					if index >= consumed {
						break
					}
					if index+len(secret) > consumed {
						consumed = index
						changed = true
						break
					}
					start = index + 1
				}
			}
		}
	}
	masked := data[:consumed]
	for _, secret := range secrets {
		if secret != "" {
			masked = bytes.ReplaceAll(masked, []byte(secret), []byte("***"))
		}
	}
	return masked, consumed
}
