package eventpattern

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestNativePatterns(t *testing.T) {
	data, err := os.ReadFile("../../../../testdata/aws/eventbridge/patterns.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case    string                `json:"case"`
			Pattern string                `json:"pattern"`
			Event   string                `json:"event"`
			Code    string                `json:"code"`
			Output  struct{ Result bool } `json:"output"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Observations {
		if strings.HasPrefix(row.Case, "edge_envelope_") {
			// The EventBridge provider owns required fields and time syntax.
			continue
		}
		t.Run(row.Case, func(t *testing.T) {
			pattern, err := Compile([]byte(row.Pattern))
			if row.Code != "Success" {
				if err == nil {
					t.Fatalf("Compile accepted native %s rejection", row.Code)
				}
				if row.Code == "InternalFailure" && !errors.Is(err, ErrEmptyAnythingButList) {
					t.Fatalf("Compile error = %v, want empty-negation sentinel", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			matched, err := pattern.Match([]byte(row.Event))
			if err != nil {
				t.Fatal(err)
			}
			if matched != row.Output.Result {
				t.Fatalf("Match = %v, native AWS = %v", matched, row.Output.Result)
			}
		})
	}
}

func TestConcurrentPatternReuse(t *testing.T) {
	pattern, err := Compile([]byte(`{"detail":{"items":{"a":[1],"b":[2]},"$or":[{"state":["ready"]},{"pending":[{"exists":false}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	inputs := []struct {
		event string
		want  bool
	}{
		{`{"detail":{"items":[{"a":1,"b":0},{"a":1,"b":2}],"state":"ready"}}`, true},
		{`{"detail":{"items":[{"a":1,"b":0},{"a":0,"b":2}],"state":"ready"}}`, false},
		{`{"detail":{"items":[{"a":1,"b":2}],"state":"waiting","pending":true}}`, false},
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 50 {
				for _, input := range inputs {
					matched, err := pattern.Match([]byte(input.event))
					if err != nil || matched != input.want {
						t.Errorf("Match = %v, %v; want %v", matched, err, input.want)
					}
				}
			}
		})
	}
	workers.Wait()
}

func TestMalformedJSON(t *testing.T) {
	pattern, err := Compile([]byte(`{"source":["probe"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", "}", "[", `{"detail":`, `{"detail":NaN}`, `{"detail":{"v":[01]}}`, `{} {}`, `null`, `[]`} {
		if _, err := Compile([]byte(input)); err == nil {
			t.Errorf("Compile(%q) accepted invalid JSON object", input)
		}
		if _, err := pattern.Match([]byte(input)); err == nil {
			t.Errorf("Match(%q) accepted invalid JSON object", input)
		}
	}
}
