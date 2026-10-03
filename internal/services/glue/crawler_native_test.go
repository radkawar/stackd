package glue_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue"
	"stackd/storage/sqlite"
	gluesqlite "stackd/storage/sqlite/glue"
)

// Replay actual native replacement/failed-update/secret-projection transitions.
// AWS times, caller-specific attribution and incidental defaults are not pinned.
func TestCrawlerClassifierConnectionNativeControls(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "aws", "glue", "controls_native.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Observations []catalogNativeObservation }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := catalogTestContext("123456789012", "us-east-1")
			var repo glue.Repository
			closeDB := func() {}
			var reopen func() glue.Repository
			if backend == "memory" {
				repo = glue.NewMemoryRepository(nil)
				reopen = func() glue.Repository { return repo }
			} else {
				path := filepath.Join(t.TempDir(), "crawler.sqlite")
				reopen = func() glue.Repository {
					db, err := sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					closeDB = func() {
						if err := db.Close(); err != nil {
							t.Error(err)
						}
					}
					return gluesqlite.New(db)
				}
				repo = reopen()
			}
			source := &crawlerObjectFixture{buckets: map[string]bool{"stackd-controls-owned": true}}
			s := glue.New(glue.Config{Repository: repo, CrawlerSource: source})
			defer func() { _ = s.Close(); closeDB() }()
			for _, row := range fixture.Observations {
				if row.Service != "glue" {
					continue
				}
				switch row.Operation {
				case "create-classifier", "get-classifier", "update-classifier", "delete-classifier", "create-connection", "get-connection", "update-connection", "delete-connection", "create-crawler", "get-crawler", "update-crawler", "delete-crawler":
				default:
					continue
				}
				t.Run(row.Label, func(t *testing.T) {
					var action strings.Builder
					for _, part := range strings.Split(row.Operation, "-") {
						action.WriteString(strings.ToUpper(part[:1]))
						action.WriteString(part[1:])
					}
					input, err := api.NewInput(action.String())
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(row.Input, input); err != nil {
						t.Fatal(err)
					}
					out, rejected := catalogTestExecute(s, ctx, action.String(), input)
					code := "Success"
					if rejected != nil {
						code = rejected.Code
					}
					if code != row.Result.Code {
						t.Fatalf("native %s, local %s (%v)", row.Result.Code, code, rejected)
					}
					if rejected != nil {
						return
					}
					switch actual := out.(type) {
					case *api.GetClassifierOutput:
						var expected api.GetClassifierOutput
						if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
							t.Fatal(err)
						}
						normalizeNativeClassifier(actual.Classifier)
						normalizeNativeClassifier(expected.Classifier)
						if !reflect.DeepEqual(actual.Classifier, expected.Classifier) {
							t.Fatalf("classifier replacement differs: actual %+v native %+v", actual.Classifier, expected.Classifier)
						}
					case *api.GetConnectionOutput:
						var expected api.GetConnectionOutput
						if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(actual.Connection.ConnectionProperties, expected.Connection.ConnectionProperties) || catalogTestValue(actual.Connection.Description) != catalogTestValue(expected.Connection.Description) {
							t.Fatal("connection replacement or HidePassword projection differs from native")
						}
					case *api.GetCrawlerOutput:
						var expected api.GetCrawlerOutput
						if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
							t.Fatal(err)
						}
						a, b := actual.Crawler, expected.Crawler
						if catalogTestValue(a.Role) != catalogTestValue(b.Role) || catalogTestValue(a.Description) != catalogTestValue(b.Description) || catalogTestValue(a.State) != catalogTestValue(b.State) || !reflect.DeepEqual(a.Version, b.Version) || !reflect.DeepEqual(a.RecrawlPolicy, b.RecrawlPolicy) {
							t.Fatalf("crawler state differs: actual %+v native %+v", a, b)
						}
					}
				})
				if row.Label == "get-connection-hidden" {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					closeDB()
					repo = reopen()
					s = glue.New(glue.Config{Repository: repo, CrawlerSource: source})
				}
			}
		})
	}
}
func normalizeNativeClassifier(v *api.Classifier) {
	if v == nil {
		return
	}
	if c := v.CsvClassifier; c != nil {
		c.CreationTime = nil
		c.LastUpdated = nil
		c.Serde = nil
	}
	if c := v.JsonClassifier; c != nil {
		c.CreationTime = nil
		c.LastUpdated = nil
	}
}
