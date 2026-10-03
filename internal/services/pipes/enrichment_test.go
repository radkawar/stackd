package pipes

import (
	"reflect"
	"testing"
)

func TestEnrichmentResponseRecords(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
		want     []string
	}{
		{"object", `{"calculated":31}`, []string{`{"calculated":31}`}},
		{"array", `[{"calculated":31},{"calculated":38}]`, []string{`{"calculated":31}`, `{"calculated":38}`}},
		{"empty body", "", nil},
		{"empty array", "[ \n ]", nil},
		{"empty object", "{ \n }", nil},
		{"empty string", `""`, nil},
		{"null", " null ", nil},
		{"deliver empty object", `[{}]`, []string{`{}`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			out, err := enrichmentPayloads([]byte(test.response))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, record := range out {
				got = append(got, string(record))
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("delivered records = %q, want %q", got, test.want)
			}
		})
	}
}

func TestEnrichmentResponseInvalid(t *testing.T) {
	for _, response := range []string{`{"broken":`, `[{}] trailing`, "not-json"} {
		if out, err := enrichmentPayloads([]byte(response)); err == nil || out != nil {
			t.Fatalf("malformed response %q produced records %q: %v", response, out, err)
		}
	}
}
