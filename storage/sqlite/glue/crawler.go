package glue

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	api "stackd/internal/awsapi/glue"
	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
)

func crawlerMissing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func crawlerString[T ~string](v *T) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*v), Valid: true}
}
func crawlerPointer[T ~string](v sql.NullString) *T {
	if !v.Valid {
		return nil
	}
	return new(T(v.String))
}
func crawlerBool[T ~bool](v *T) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	out := sql.NullInt64{Valid: true}
	if bool(*v) {
		out.Int64 = 1
	}
	return out
}
func crawlerBoolPointer[T ~bool](v sql.NullInt64) *T {
	if !v.Valid {
		return nil
	}
	return new(T(v.Int64 != 0))
}
func crawlerJSON(v any) (string, error) { data, err := json.Marshal(v); return string(data), err }

func (r reader) Crawler(key domain.ResourceKey) (domain.CrawlerRecord, error) {
	v, err := r.q.GetGlueCrawler(r.ctx, sqlcgen.GetGlueCrawlerParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
	if err != nil {
		return domain.CrawlerRecord{}, crawlerMissing(err)
	}
	return decodeCrawler(v)
}
func (r reader) Crawlers(scope domain.Scope) ([]domain.CrawlerRecord, error) {
	rows, err := r.q.ListGlueCrawlers(r.ctx, sqlcgen.ListGlueCrawlersParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.CrawlerRecord, 0, len(rows))
	for _, v := range rows {
		row, err := decodeCrawler(v)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}
func (r reader) ScheduledCrawlers() ([]domain.CrawlerRecord, error) {
	rows, err := r.q.ScheduledGlueCrawlers(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.CrawlerRecord, 0, len(rows))
	for _, v := range rows {
		row, err := decodeCrawler(v)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}
func decodeCrawler(v sqlcgen.GlueCrawler) (domain.CrawlerRecord, error) {
	out := domain.CrawlerRecord{Key: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, RunID: v.RunID}
	out.CFNOwner = v.CfnOwner
	if v.NextScheduled.Valid {
		out.NextScheduled = new(time.Unix(0, v.NextScheduled.Int64).UTC())
	}
	out.Crawler = api.Crawler{Name: new(api.NameString(v.Name)), Role: new(api.Role(v.Role)), DatabaseName: new(api.DatabaseName(v.DatabaseName)), Description: crawlerPointer[api.DescriptionString](v.Description), TablePrefix: crawlerPointer[api.TablePrefix](v.TablePrefix), Configuration: crawlerPointer[api.CrawlerConfiguration](v.Configuration), CrawlerSecurityConfiguration: crawlerPointer[api.CrawlerSecurityConfiguration](v.SecurityConfiguration), State: new(api.CrawlerState(v.State)), Version: new(api.VersionId(v.Version)), CreationTime: new(time.Unix(0, v.CreatedAt).UTC()), LastUpdated: new(time.Unix(0, v.UpdatedAt).UTC())}
	out.Crawler.CrawlElapsedTime = new(api.MillisecondsCount(v.ElapsedMs))
	for _, field := range []struct {
		raw string
		dst any
	}{{v.Targets, &out.Crawler.Targets}, {v.Classifiers, &out.Crawler.Classifiers}, {v.SchemaChangePolicy, &out.Crawler.SchemaChangePolicy}, {v.RecrawlPolicy, &out.Crawler.RecrawlPolicy}, {v.LakeFormation, &out.Crawler.LakeFormationConfiguration}, {v.Lineage, &out.Crawler.LineageConfiguration}, {v.Schedule, &out.Crawler.Schedule}, {v.Tags, &out.Tags}, {v.LastCrawl, &out.Crawler.LastCrawl}} {
		if err := json.Unmarshal([]byte(field.raw), field.dst); err != nil {
			return domain.CrawlerRecord{}, err
		}
	}
	return out, nil
}
func (w writer) PutCrawler(row domain.CrawlerRecord) error {
	c := row.Crawler
	v := sqlcgen.PutGlueCrawlerParams{Partition: row.Key.Partition, AccountID: row.Key.AccountID, Region: row.Key.Region, Name: row.Key.Name, Role: string(*c.Role), Description: crawlerString(c.Description), TablePrefix: crawlerString(c.TablePrefix), Configuration: crawlerString(c.Configuration), SecurityConfiguration: crawlerString(c.CrawlerSecurityConfiguration), State: string(*c.State), Version: int64(*c.Version), CreatedAt: c.CreationTime.UnixNano(), UpdatedAt: c.LastUpdated.UnixNano(), RunID: row.RunID}
	v.CfnOwner = row.CFNOwner
	if c.DatabaseName != nil {
		v.DatabaseName = string(*c.DatabaseName)
	}
	if c.CrawlElapsedTime != nil {
		v.ElapsedMs = int64(*c.CrawlElapsedTime)
	}
	if row.NextScheduled != nil {
		v.NextScheduled = sql.NullInt64{Valid: true, Int64: row.NextScheduled.UnixNano()}
	}
	for _, field := range []struct {
		src any
		dst *string
	}{{c.Targets, &v.Targets}, {c.Classifiers, &v.Classifiers}, {c.SchemaChangePolicy, &v.SchemaChangePolicy}, {c.RecrawlPolicy, &v.RecrawlPolicy}, {c.LakeFormationConfiguration, &v.LakeFormation}, {c.LineageConfiguration, &v.Lineage}, {c.Schedule, &v.Schedule}, {row.Tags, &v.Tags}, {c.LastCrawl, &v.LastCrawl}} {
		encoded, err := crawlerJSON(field.src)
		if err != nil {
			return err
		}
		*field.dst = encoded
	}
	return w.q.PutGlueCrawler(w.ctx, v)
}
func (w writer) DeleteCrawler(key domain.ResourceKey) error {
	return w.q.DeleteGlueCrawler(w.ctx, sqlcgen.DeleteGlueCrawlerParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
}
func decodeCrawlerRun(v sqlcgen.GlueCrawlerRun) domain.CrawlRecord {
	out := domain.CrawlRecord{ID: v.ID, Crawler: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.CrawlerName}, State: v.State, Phase: v.Phase, Started: time.Unix(0, v.StartedAt).UTC(), ErrorMessage: v.ErrorMessage, TablesCreated: v.TablesCreated, TablesUpdated: v.TablesUpdated, PartitionsCreated: v.PartitionsCreated, ParentEventID: v.ParentEventID, TriggerName: v.TriggerName, WorkflowName: v.WorkflowName, WorkflowRunID: v.WorkflowRunID}
	if v.CompletedAt.Valid {
		out.Completed = new(time.Unix(0, v.CompletedAt.Int64).UTC())
	}
	return out
}
func (r reader) Crawl(id string) (domain.CrawlRecord, error) {
	v, err := r.q.GetGlueCrawlerRun(r.ctx, id)
	if err != nil {
		return domain.CrawlRecord{}, crawlerMissing(err)
	}
	return decodeCrawlerRun(v), nil
}
func (r reader) Crawls(key domain.ResourceKey) ([]domain.CrawlRecord, error) {
	rows, err := r.q.ListGlueCrawlerRuns(r.ctx, sqlcgen.ListGlueCrawlerRunsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, CrawlerName: key.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.CrawlRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, decodeCrawlerRun(v))
	}
	return out, nil
}
func (r reader) PendingCrawls() ([]domain.CrawlRecord, error) {
	rows, err := r.q.PendingGlueCrawlerRuns(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.CrawlRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, decodeCrawlerRun(v))
	}
	return out, nil
}
func (w writer) PutCrawl(row domain.CrawlRecord) error {
	v := sqlcgen.PutGlueCrawlerRunParams{ID: row.ID, Partition: row.Crawler.Partition, AccountID: row.Crawler.AccountID, Region: row.Crawler.Region, CrawlerName: row.Crawler.Name, State: row.State, Phase: row.Phase, StartedAt: row.Started.UnixNano(), ErrorMessage: row.ErrorMessage, TablesCreated: row.TablesCreated, TablesUpdated: row.TablesUpdated, PartitionsCreated: row.PartitionsCreated, ParentEventID: row.ParentEventID, TriggerName: row.TriggerName, WorkflowName: row.WorkflowName, WorkflowRunID: row.WorkflowRunID}
	if row.Completed != nil {
		v.CompletedAt = sql.NullInt64{Valid: true, Int64: row.Completed.UnixNano()}
	}
	return w.q.PutGlueCrawlerRun(w.ctx, v)
}
