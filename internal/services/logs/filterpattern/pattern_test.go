package filterpattern

import (
	"encoding/json"
	"os"
	"testing"
)

func TestNativeFilterPatterns(t *testing.T) {
	data, err := os.ReadFile("../../../../testdata/aws/logs/filters.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Label     string `json:"label"`
			Operation string `json:"operation"`
			Input     struct {
				FilterPattern    string   `json:"filterPattern"`
				LogEventMessages []string `json:"logEventMessages"`
			} `json:"input"`
			Result struct {
				Code   string `json:"code"`
				Output struct {
					Matches []struct {
						EventNumber  int    `json:"eventNumber"`
						EventMessage string `json:"eventMessage"`
					} `json:"matches"`
				} `json:"output"`
			} `json:"result"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	cases := 0
	for _, observation := range fixture.Observations {
		if observation.Operation != "test-metric-filter" {
			continue
		}
		cases++
		t.Run(observation.Label, func(t *testing.T) {
			pattern, err := Compile(observation.Input.FilterPattern)
			switch observation.Result.Code {
			case "InvalidParameterException":
				if err == nil {
					t.Fatal("Compile accepted a pattern rejected by native AWS")
				}
				return
			case "Success":
				if err != nil {
					t.Fatalf("Compile rejected a native accepted pattern: %v", err)
				}
			default:
				t.Fatalf("unhandled native oracle result %s", observation.Result.Code)
			}
			messages := observation.Input.LogEventMessages
			want := make([]bool, len(messages))
			for _, match := range observation.Result.Output.Matches {
				index := match.EventNumber - 1 // Native event numbers are one-based.
				if index < 0 || index >= len(messages) || messages[index] != match.EventMessage {
					t.Fatal("native match does not identify its original input message")
				}
				want[index] = true
			}
			for i, message := range messages {
				if got := pattern.Match(message); got != want[i] {
					t.Errorf("message %d %q: Match = %v, native AWS = %v", i+1, message, got, want[i])
				}
			}
		})
	}
	if cases == 0 {
		t.Fatal("fixture contains no native filter oracle observations")
	}
}
