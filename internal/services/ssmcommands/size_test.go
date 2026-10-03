package ssmcommands

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awswire"
)

// Boundary pairs come from independent native zero-target admissions. These
// measure list/escaping/metadata overhead, not guessed per-document constants.
func TestNativeCommandSizeBoundaries(t *testing.T) {
	type nativeCall struct {
		Label, Code string
		Input       json.RawMessage
	}
	var builtin struct {
		Calls []struct {
			Label  string
			Output struct{ Content string }
		}
	}
	readSizeCapture(t, "managed_execution_admission_boundaries.json.gz", &builtin)
	content := ""
	for _, row := range builtin.Calls {
		if row.Label == "builtin-original-content" {
			content = row.Output.Content
		}
	}
	if content == "" {
		t.Fatal("native builtin source missing")
	}
	files := []struct {
		name  string
		pairs map[string][2]int
	}{
		{"managed_execution_admission_boundaries.json.gz", map[string][2]int{"single-ascii": {98883, 98884}, "empty-list": {32962, 32963}, "escaped-null": {16480, 16481}}},
		{"managed_execution_admission_fields.json.gz", map[string][2]int{"comment-100": {98883, 98884}, "s3-prefix-100": {98760, 98761}, "s3-bucket-10": {98849, 98850}, "cw-enabled-group10": {98874, 98875}, "working-directory-10": {98851, 98852}, "html-character": {16663, 16664}, "unicode-euro": {16480, 16481}}},
		{"managed_execution_admission_accounting.json.gz", map[string][2]int{"minimal": {99611, 99612}, "description-1000": {98594, 98595}, "two-steps": {99522, 99523}}},
	}
	for _, source := range files {
		t.Run(source.name, func(t *testing.T) {
			var fixture struct{ Calls []nativeCall }
			readSizeCapture(t, source.name, &fixture)
			documents := map[string]string{}
			for _, row := range fixture.Calls {
				if row.Label == "document-create" || strings.HasPrefix(row.Label, "document-update-") {
					var in struct{ Content, Name string }
					if err := json.Unmarshal(row.Input, &in); err != nil {
						t.Fatal(err)
					}
					documents[in.Name] = in.Content
				}
				for prefix, pair := range source.pairs {
					for i, n := range pair {
						if row.Label != prefix+"-"+strconv.Itoa(n) {
							continue
						}
						t.Run(row.Label, func(t *testing.T) {
							var in api.SendCommandRequest
							if err := json.Unmarshal(row.Input, &in); err != nil {
								t.Fatal(err)
							}
							doc := content
							if v, ok := documents[string(*in.DocumentName)]; ok {
								doc = v
							}
							cmd := Command{Key: Key{ID: "00000000-0000-0000-0000-000000000000"}, DocumentName: string(*in.DocumentName), Content: doc, Parameters: map[string][]string{}, OutputPrefix: value(in.OutputS3KeyPrefix), OutputBucket: value(in.OutputS3BucketName)}
							for k, values := range in.Parameters {
								for _, v := range values {
									cmd.Parameters[string(k)] = append(cmd.Parameters[string(k)], string(v))
								}
							}
							if in.CloudWatchOutputConfig != nil {
								cmd.CloudWatchEnabled = boolValue(in.CloudWatchOutputConfig.CloudWatchOutputEnabled)
								cmd.LogGroup = value(in.CloudWatchOutputConfig.CloudWatchLogGroupName)
							}
							err := validateCommandSize(cmd)
							if i == 0 {
								if row.Code != "Success" || err != nil {
									t.Fatalf("native accepted input rejected locally: native=%s local=%v", row.Code, err)
								}
							} else {
								var rejected *awswire.Error
								if row.Code != "MaxDocumentSizeExceeded" || !errors.As(err, &rejected) || rejected.Code != row.Code {
									t.Fatalf("native oversized input admitted/different failure: native=%s local=%v", row.Code, err)
								}
							}
						})
					}
				}
			}
		})
	}
}

func readSizeCapture(t *testing.T, name string, out any) {
	t.Helper()
	file, err := os.Open("../../../testdata/aws/ssm/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	if err := json.NewDecoder(compressed).Decode(out); err != nil {
		t.Fatal(err)
	}
}
