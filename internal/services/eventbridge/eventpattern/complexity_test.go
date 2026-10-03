package eventpattern

import (
	"encoding/json"
	"os"
	"testing"
)

func TestNativePatternAdmission(t *testing.T) {
	data, err := os.ReadFile("../../../../testdata/aws/eventbridge/pattern_admission.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Pattern, Event string
			Matching             struct {
				Code   string
				Output struct{ Result bool }
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Observations {
		t.Run(row.Case, func(t *testing.T) {
			pattern, err := Compile([]byte(row.Pattern))
			if row.Matching.Code != "Success" {
				if err == nil {
					t.Fatalf("Compile accepted native %s rejection", row.Matching.Code)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			matched, err := pattern.Match([]byte(row.Event))
			if err != nil || matched != row.Matching.Output.Result {
				t.Fatalf("Match = %v, %v; native %v", matched, err, row.Matching.Output.Result)
			}
		})
	}
}
