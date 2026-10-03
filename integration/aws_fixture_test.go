package stackd_test

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

type awsNativeObservation struct {
	Label, Service, Operation string
	Region                    string
	Account                   string `json:"caller_account"`
	ActorARN                  string `json:"actor_arn"`
	Input                     json.RawMessage
	Started                   int64 `json:"request_started_ms"`
	Result                    struct {
		Code       string
		Output     json.RawMessage
		HTTPStatus int    `json:"http_status"`
		RequestID  string `json:"request_id"`
	}
}

func awsReadFixture(t *testing.T, path string, out any) {
	t.Helper()
	file, err := os.Open("../testdata/aws/" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var reader io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		compressed, err := gzip.NewReader(file)
		if err != nil {
			t.Fatal(err)
		}
		defer compressed.Close()
		reader = compressed
	}
	if err := json.NewDecoder(reader).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func awsFixtureField(object map[string]any, path string) any {
	var value any = object
	for _, part := range strings.Split(path, ".") {
		switch current := value.(type) {
		case map[string]any:
			value = current[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(current) {
				return nil
			}
			value = current[index]
		default:
			return nil
		}
	}
	return value
}

func awsDecodeJSON(t *testing.T, data json.RawMessage, into any) {
	t.Helper()
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatal(err)
	}
}

func awsNativeResult(t *testing.T, row awsNativeObservation, err error) {
	t.Helper()
	if row.Result.Code == "Success" {
		if err != nil {
			t.Fatalf("%s: %v", row.Label, err)
		}
		return
	}
	assertAPIError(t, err, row.Result.Code)
	var response interface{ HTTPStatusCode() int }
	if row.Result.HTTPStatus != 0 && (!errors.As(err, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus) {
		t.Fatalf("%s: expected native HTTP %d, got %v", row.Label, row.Result.HTTPStatus, err)
	}
}
