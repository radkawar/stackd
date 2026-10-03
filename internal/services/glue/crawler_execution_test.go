package glue_test

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"slices"
	"stackd/clock"
	"strconv"
	"strings"
	"testing"
	"time"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/glue"
	"stackd/storage/sqlite"
	gluesqlite "stackd/storage/sqlite/glue"
)

type crawlerObjectFixture struct {
	buckets     map[string]bool
	objects     map[string][]byte
	readStarted chan struct{}
	block       bool
}

func (f *crawlerObjectFixture) Validate(ctx context.Context, _ glue.Scope, _, _ string, targets api.CrawlerTargets) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, target := range targets.S3Targets {
		u, err := url.Parse(catalogTestValue(target.Path))
		if err != nil {
			return err
		}
		if !f.buckets[u.Host] {
			return &awswire.Error{Code: "NoSuchBucket", Message: "Fixture bucket does not exist.", StatusCode: 404}
		}
	}
	return nil
}
func (f *crawlerObjectFixture) RoleContext(ctx context.Context, scope glue.Scope, _, _ string) (context.Context, error) {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID}), nil
}
func (f *crawlerObjectFixture) List(ctx context.Context, _, prefix, token string) (glue.CrawlerObjectPage, error) {
	if err := ctx.Err(); err != nil {
		return glue.CrawlerObjectPage{}, err
	}
	keys := []string{}
	for key := range f.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	offset := 0
	if token != "" {
		var err error
		offset, err = strconv.Atoi(token)
		if err != nil {
			return glue.CrawlerObjectPage{}, err
		}
	}
	page := glue.CrawlerObjectPage{}
	if offset < len(keys) {
		key := keys[offset]
		page.Objects = []glue.CrawlerObject{{Key: key, Size: int64(len(f.objects[key]))}}
		if offset+1 < len(keys) {
			page.NextToken = strconv.Itoa(offset + 1)
		}
	}
	return page, nil
}
func (f *crawlerObjectFixture) Read(ctx context.Context, _, key string) ([]byte, error) {
	if f.readStarted != nil {
		select {
		case f.readStarted <- struct{}{}:
		default:
		}
	}
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.objects[key], nil
}

type crawlerTerminalEvents struct{ terminal chan string }

func (e crawlerTerminalEvents) Publish(_ context.Context, _ glue.CrawlerRecord, state, _ string) error {
	if state != "Started" {
		e.terminal <- state
	}
	return nil
}

func TestCrawlerActualObjectsRestartFailureAndCancellation(t *testing.T) {
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
				file := filepath.Join(t.TempDir(), "crawl.sqlite")
				reopen = func() glue.Repository {
					db, err := sqlite.Open(ctx, file)
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
			fixture := &crawlerObjectFixture{buckets: map[string]bool{"fixtures": true}, objects: map[string][]byte{"sales/day=2026-09-25/part.json": []byte("{\"category\":\"a\",\"amount\":7}\n"), "sales/day=2026-09-26/part.json": []byte("{\"category\":\"b\",\"amount\":9}\n"), "sales/day=2026-09-26/ignore.txt": []byte("must not become schema")}}
			events := crawlerTerminalEvents{terminal: make(chan string, 8)}
			config := glue.Config{Repository: repo, CrawlerSource: fixture, CrawlerEvents: events}
			s := glue.New(config)
			defer func() { _ = s.Close(); closeDB() }()
			catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("crawl"))}})
			catalogTestCall[api.CreateCrawlerOutput](t, s, ctx, "CreateCrawler", &api.CreateCrawlerInput{Name: new(api.NameString("discover")), Role: new(api.Role("crawler-role")), DatabaseName: new(api.DatabaseName("crawl")), Targets: &api.CrawlerTargets{S3Targets: api.S3TargetList{{Path: new(api.Path("s3://fixtures/sales/")), Exclusions: api.PathList{"**/ignore.txt"}}}}})
			catalogTestCall[api.StartCrawlerOutput](t, s, ctx, "StartCrawler", &api.StartCrawlerInput{Name: new(api.NameString("discover"))})
			catalogTestError(t, s, ctx, "StartCrawler", &api.StartCrawlerInput{Name: new(api.NameString("discover"))}, "CrawlerRunningException")
			// Reopen with admitted work still queued. No worker has executed yet.
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			closeDB()
			repo = reopen()
			config.Repository = repo
			s = glue.New(config)
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			select {
			case state := <-events.terminal:
				if state != "Succeeded" {
					t.Fatalf("state %s", state)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("crawler did not finish")
			}
			table := catalogTestCall[api.GetTableOutput](t, s, ctx, "GetTable", &api.GetTableInput{DatabaseName: new(api.NameString("crawl")), Name: new(api.NameString("sales"))}).Table
			if len(table.StorageDescriptor.Columns) != 2 || catalogTestValue(table.StorageDescriptor.Columns[0].Name) != "amount" || catalogTestValue(table.StorageDescriptor.Columns[0].Type) != "bigint" || catalogTestValue(table.StorageDescriptor.Location) != "s3://fixtures/sales/" {
				t.Fatalf("schema not derived from JSON objects: %+v", table.StorageDescriptor)
			}
			parts := catalogTestCall[api.GetPartitionsOutput](t, s, ctx, "GetPartitions", &api.GetPartitionsInput{DatabaseName: new(api.NameString("crawl")), TableName: new(api.NameString("sales"))}).Partitions
			if len(parts) != 2 || parts[0].Values[0] != "2026-09-25" || parts[1].Values[0] != "2026-09-26" {
				t.Fatalf("unexpected partitions %v", parts)
			}
			history := catalogTestCall[api.ListCrawlsOutput](t, s, ctx, "ListCrawls", &api.ListCrawlsInput{CrawlerName: new(api.NameString("discover"))})
			if len(history.Crawls) != 1 || catalogTestValue(history.Crawls[0].State) != "COMPLETED" || history.Crawls[0].EndTime == nil {
				t.Fatalf("unexpected crawl history %v", history.Crawls)
			}
			catalogTestError(t, s, catalogTestContext("123456789012", "us-west-2"), "GetCrawler", &api.GetCrawlerInput{Name: new(api.NameString("discover"))}, "EntityNotFoundException")
			// Retained stop interrupts the real object-read boundary and publishes no table.
			fixture.objects = map[string][]byte{"cancel/part.json": []byte("{\"x\":1}")}
			fixture.block = true
			fixture.readStarted = make(chan struct{}, 1)
			catalogTestCall[api.CreateCrawlerOutput](t, s, ctx, "CreateCrawler", &api.CreateCrawlerInput{Name: new(api.NameString("cancel")), Role: new(api.Role("crawler-role")), DatabaseName: new(api.DatabaseName("crawl")), Targets: &api.CrawlerTargets{S3Targets: api.S3TargetList{{Path: new(api.Path("s3://fixtures/cancel/"))}}}})
			catalogTestCall[api.StartCrawlerOutput](t, s, ctx, "StartCrawler", &api.StartCrawlerInput{Name: new(api.NameString("cancel"))})
			select {
			case <-fixture.readStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("source read not entered")
			}
			catalogTestCall[api.StopCrawlerOutput](t, s, ctx, "StopCrawler", &api.StopCrawlerInput{Name: new(api.NameString("cancel"))})
			select {
			case state := <-events.terminal:
				if state != "Cancelled" {
					t.Fatalf("state %s", state)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not finish")
			}
			catalogTestError(t, s, ctx, "GetTable", &api.GetTableInput{DatabaseName: new(api.NameString("crawl")), Name: new(api.NameString("cancel"))}, "EntityNotFoundException")
			fixture.block = false
			fixture.objects = map[string][]byte{"cancel/part.json": []byte{0, 1, 2, 3}}
			catalogTestCall[api.StartCrawlerOutput](t, s, ctx, "StartCrawler", &api.StartCrawlerInput{Name: new(api.NameString("cancel"))})
			select {
			case state := <-events.terminal:
				if state != "Failed" {
					t.Fatalf("state %s", state)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("invalid data did not fail")
			}
			if err := repo.View(ctx, func(r glue.Reader) error {
				row, err := r.Crawler(glue.ResourceKey{Scope: glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "cancel"})
				if err != nil {
					return err
				}
				if row.Crawler.LastCrawl == nil || catalogTestValue(row.Crawler.LastCrawl.Status) != "FAILED" {
					return errors.New("failure did not retain last crawl")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCrawlerSchedulePersistsAndStops(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	manual := clock.NewManual(time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	file := filepath.Join(t.TempDir(), "schedule.sqlite")
	db, err := sqlite.Open(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &crawlerObjectFixture{buckets: map[string]bool{"fixtures": true}, objects: map[string][]byte{"scheduled/part.json": []byte("{\"value\":3}")}}
	events := crawlerTerminalEvents{terminal: make(chan string, 4)}
	config := glue.Config{Repository: gluesqlite.New(db), Clock: manual, CrawlerSource: fixture, CrawlerEvents: events}
	s := glue.New(config)
	catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("crawl"))}})
	catalogTestCall[api.CreateCrawlerOutput](t, s, ctx, "CreateCrawler", &api.CreateCrawlerInput{Name: new(api.NameString("scheduled")), Role: new(api.Role("crawler-role")), DatabaseName: new(api.DatabaseName("crawl")), Schedule: new(api.CronExpression("cron(0/5 * * * ? *)")), Targets: &api.CrawlerTargets{S3Targets: api.S3TargetList{{Path: new(api.Path("s3://fixtures/scheduled/"))}}}})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	config.Repository = gluesqlite.New(db)
	s = glue.New(config)
	defer s.Close()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	manual.Advance(4 * time.Minute)
	if _, err := s.JobDriver().RunDue(ctx, 20); err != nil {
		t.Fatal(err)
	}
	before := catalogTestCall[api.ListCrawlsOutput](t, s, ctx, "ListCrawls", &api.ListCrawlsInput{CrawlerName: new(api.NameString("scheduled"))})
	if len(before.Crawls) != 0 {
		t.Fatal("schedule fired before its retained deadline")
	}
	manual.Advance(time.Minute)
	if _, err := s.JobDriver().RunDue(ctx, 20); err != nil {
		t.Fatal(err)
	}
	select {
	case state := <-events.terminal:
		if state != "Succeeded" {
			t.Fatal(state)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled crawler did not complete")
	}
	catalogTestCall[api.StopCrawlerScheduleOutput](t, s, ctx, "StopCrawlerSchedule", &api.StopCrawlerScheduleInput{CrawlerName: new(api.NameString("scheduled"))})
	manual.Advance(10 * time.Minute)
	if _, err := s.JobDriver().RunDue(ctx, 20); err != nil {
		t.Fatal(err)
	}
	after := catalogTestCall[api.ListCrawlsOutput](t, s, ctx, "ListCrawls", &api.ListCrawlsInput{CrawlerName: new(api.NameString("scheduled"))})
	if len(after.Crawls) != 1 || catalogTestValue(after.Crawls[0].State) != "COMPLETED" {
		t.Fatalf("stopped schedule admitted work: %v", after.Crawls)
	}
}
