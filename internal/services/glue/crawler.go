package glue

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
)

func registerCrawlers(s *Service) {
	registerClassifiers(s)
	registerConnections(s)
	registerConnectionEncryption(s)
	registerControl(s, "CreateCrawler", s.createCrawler)
	registerControl(s, "GetCrawler", s.getCrawler)
	registerControl(s, "GetCrawlers", s.getCrawlers)
	registerControl(s, "ListCrawlers", s.listCrawlers)
	registerControl(s, "UpdateCrawler", s.updateCrawler)
	registerControl(s, "DeleteCrawler", s.deleteCrawler)
	registerControl(s, "StartCrawler", s.startCrawler)
	registerControl(s, "StopCrawler", s.stopCrawler)
	registerControl(s, "ListCrawls", s.listCrawls)
	registerControl(s, "StartCrawlerSchedule", s.startCrawlerSchedule)
	registerControl(s, "StopCrawlerSchedule", s.stopCrawlerSchedule)
	registerControl(s, "UpdateCrawlerSchedule", s.updateCrawlerSchedule)
}

func validateCrawler(v api.Crawler) error {
	if value(v.Name) == "" || value(v.Role) == "" || v.Targets == nil {
		return failure("InvalidInputException", "Crawler name, role, and targets are required.")
	}
	t := v.Targets
	if len(t.CatalogTargets) == 0 && value(v.DatabaseName) == "" {
		return failure("InvalidInputException", "DatabaseName is required for non-catalog targets.")
	}
	if len(t.S3Targets)+len(t.JdbcTargets)+len(t.CatalogTargets)+len(t.DynamoDBTargets)+len(t.MongoDBTargets)+len(t.DeltaTargets)+len(t.HudiTargets)+len(t.IcebergTargets) == 0 {
		return failure("InvalidInputException", "Crawler must have at least one target.")
	}
	for _, target := range t.S3Targets {
		if _, _, err := crawlerS3Path(value(target.Path)); err != nil {
			return err
		}
		for _, pattern := range target.Exclusions {
			if _, err := crawlerGlob(string(pattern)); err != nil {
				return err
			}
		}
		if target.SampleSize != nil && (*target.SampleSize < 1 || *target.SampleSize > 249) {
			return failure("InvalidInputException", "Sample size must be between 1 and 249.")
		}
	}
	for _, target := range t.JdbcTargets {
		if value(target.ConnectionName) == "" || value(target.Path) == "" {
			return failure("InvalidInputException", "JDBC connection name and path are required.")
		}
	}
	if v.Configuration != nil && value(v.Configuration) != "" {
		var configuration map[string]json.RawMessage
		if err := json.Unmarshal([]byte(value(v.Configuration)), &configuration); err != nil {
			return failure("InvalidInputException", "Invalid crawler configuration JSON.")
		}
	}
	if v.RecrawlPolicy != nil && value(v.RecrawlPolicy.RecrawlBehavior) == "CRAWL_NEW_FOLDERS_ONLY" && (v.SchemaChangePolicy == nil || value(v.SchemaChangePolicy.UpdateBehavior) != "LOG" || value(v.SchemaChangePolicy.DeleteBehavior) != "LOG") {
		return failure("InvalidInputException", "New-folders-only crawling requires LOG update and delete behavior.")
	}
	if p := v.SchemaChangePolicy; p != nil {
		if value(p.UpdateBehavior) != "UPDATE_IN_DATABASE" && value(p.UpdateBehavior) != "LOG" {
			return failure("InvalidInputException", "Invalid schema update behavior.")
		}
		if value(p.DeleteBehavior) != "DEPRECATE_IN_DATABASE" && value(p.DeleteBehavior) != "DELETE_FROM_DATABASE" && value(p.DeleteBehavior) != "LOG" {
			return failure("InvalidInputException", "Invalid schema delete behavior.")
		}
	}
	return nil
}
func crawlerS3Path(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "s3" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", failure("InvalidInputException", "S3 target must be an s3://bucket/prefix path.")
	}
	return u.Host, strings.TrimPrefix(u.Path, "/"), nil
}
func crawlerRole(scope Scope, role string) string {
	if strings.HasPrefix(role, "arn:") {
		return role
	}
	return "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":role/" + role
}
func normalizeCrawler(scope Scope, v *api.Crawler) {
	v.Role = new(api.Role(strings.TrimPrefix(value(v.Role), "arn:"+scope.Partition+":iam::"+scope.AccountID+":role/")))
	if v.SchemaChangePolicy == nil {
		v.SchemaChangePolicy = &api.SchemaChangePolicy{UpdateBehavior: new(api.UpdateBehavior("UPDATE_IN_DATABASE")), DeleteBehavior: new(api.DeleteBehavior("DEPRECATE_IN_DATABASE"))}
	}
	if v.RecrawlPolicy == nil {
		v.RecrawlPolicy = &api.RecrawlPolicy{RecrawlBehavior: new(api.RecrawlBehavior("CRAWL_EVERYTHING"))}
	}
	if v.CrawlElapsedTime == nil {
		v.CrawlElapsedTime = new(api.MillisecondsCount(0))
	}
}
func (s *Service) createCrawler(ctx context.Context, tx Transaction, in *api.CreateCrawlerInput) (*api.CreateCrawlerOutput, error) {
	key := ResourceKey{Scope: scopeFor(ctx), Name: value(in.Name)}
	v := api.Crawler{Name: in.Name, Role: in.Role, Targets: in.Targets, Classifiers: in.Classifiers, Configuration: in.Configuration, DatabaseName: in.DatabaseName, Description: in.Description, TablePrefix: in.TablePrefix, SchemaChangePolicy: in.SchemaChangePolicy, RecrawlPolicy: in.RecrawlPolicy, LakeFormationConfiguration: in.LakeFormationConfiguration, LineageConfiguration: in.LineageConfiguration, CrawlerSecurityConfiguration: in.CrawlerSecurityConfiguration, State: new(api.CrawlerStateREADY), Version: new(api.VersionId(1))}
	normalizeCrawler(key.Scope, &v)
	if err := validateCrawler(v); err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for k, v := range in.Tags {
		tags[string(k)] = string(v)
	}
	if err := s.authorizeCreate(ctx, tx, "CreateCrawler", key.Scope, key.ARN("crawler"), tags); err != nil {
		return nil, err
	}
	if _, err := tx.Crawler(key); err == nil {
		return nil, failure("AlreadyExistsException", "Crawler already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err := s.passRole(ctx, crawlerRole(key.Scope, value(v.Role)), key.ARN("crawler")); err != nil {
		return nil, err
	}
	if err := s.validateCrawlerSources(ctx, key, v); err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	v.CreationTime, v.LastUpdated = &now, &now
	row := CrawlerRecord{Key: key, Crawler: v, Tags: tags}
	if in.Schedule != nil {
		if err := configureCrawlerSchedule(&row, value(in.Schedule), now); err != nil {
			return nil, err
		}
	}
	if err := tx.PutCrawler(row); err != nil {
		return nil, err
	}
	return &api.CreateCrawlerOutput{}, nil
}
func (s *Service) loadCrawler(ctx context.Context, tx Transaction, name, action string) (CrawlerRecord, error) {
	key := ResourceKey{Scope: scopeFor(ctx), Name: name}
	row, err := tx.Crawler(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return CrawlerRecord{}, err
	}
	if auth := s.authorize(ctx, tx, action, key.Scope, key.ARN("crawler"), row.Tags); auth != nil {
		return CrawlerRecord{}, auth
	}
	return row, err
}
func (s *Service) getCrawler(ctx context.Context, tx Transaction, in *api.GetCrawlerInput) (*api.GetCrawlerOutput, error) {
	row, err := s.loadCrawler(ctx, tx, value(in.Name), "GetCrawler")
	if err != nil {
		return nil, err
	}
	if value(row.Crawler.State) != "READY" && row.RunID != "" {
		run, err := tx.Crawl(row.RunID)
		if err != nil {
			return nil, err
		}
		row.Crawler.CrawlElapsedTime = new(api.MillisecondsCount(max(0, s.clock.Now().Sub(run.Started).Milliseconds())))
	}
	return &api.GetCrawlerOutput{Crawler: &row.Crawler}, nil
}
func (s *Service) getCrawlers(ctx context.Context, tx Transaction, in *api.GetCrawlersInput) (*api.GetCrawlersOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "GetCrawlers", scope, "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Crawlers(scope)
	if err != nil {
		return nil, err
	}
	start, end, next, err := crawlerPage(scope, "crawlers", "", in.NextToken, in.MaxResults, len(rows))
	if err != nil {
		return nil, err
	}
	out := &api.GetCrawlersOutput{Crawlers: api.CrawlerList{}, NextToken: next}
	for _, row := range rows[start:end] {
		out.Crawlers = append(out.Crawlers, row.Crawler)
	}
	return out, nil
}
func (s *Service) listCrawlers(ctx context.Context, tx Transaction, in *api.ListCrawlersInput) (*api.ListCrawlersOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "ListCrawlers", scope, "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Crawlers(scope)
	if err != nil {
		return nil, err
	}
	selected := rows[:0]
	for _, row := range rows {
		match := true
		for k, v := range in.Tags {
			if row.Tags[string(k)] != string(v) {
				match = false
				break
			}
		}
		if match {
			selected = append(selected, row)
		}
	}
	filter, _ := json.Marshal(in.Tags)
	start, end, next, err := crawlerPage(scope, "crawler-names", string(filter), in.NextToken, in.MaxResults, len(selected))
	if err != nil {
		return nil, err
	}
	out := &api.ListCrawlersOutput{CrawlerNames: api.CrawlerNameList{}, NextToken: next}
	for _, row := range selected[start:end] {
		out.CrawlerNames = append(out.CrawlerNames, api.NameString(row.Key.Name))
	}
	return out, nil
}
func (s *Service) updateCrawler(ctx context.Context, tx Transaction, in *api.UpdateCrawlerInput) (*api.UpdateCrawlerOutput, error) {
	row, err := s.loadCrawler(ctx, tx, value(in.Name), "UpdateCrawler")
	if err != nil {
		return nil, err
	}
	if value(row.Crawler.State) != "READY" {
		return nil, failure("CrawlerRunningException", "Crawler is running.")
	}
	v := &row.Crawler
	if in.Classifiers != nil {
		v.Classifiers = in.Classifiers
	}
	if in.Configuration != nil {
		v.Configuration = in.Configuration
	}
	if in.DatabaseName != nil {
		v.DatabaseName = in.DatabaseName
	}
	if in.Description != nil {
		v.Description = new(api.DescriptionString(*in.Description))
	}
	if in.TablePrefix != nil {
		v.TablePrefix = in.TablePrefix
	}
	if in.Targets != nil {
		v.Targets = in.Targets
	}
	if in.SchemaChangePolicy != nil {
		v.SchemaChangePolicy = in.SchemaChangePolicy
	}
	if in.RecrawlPolicy != nil {
		v.RecrawlPolicy = in.RecrawlPolicy
	}
	if in.LakeFormationConfiguration != nil {
		v.LakeFormationConfiguration = in.LakeFormationConfiguration
	}
	if in.LineageConfiguration != nil {
		v.LineageConfiguration = in.LineageConfiguration
	}
	if in.CrawlerSecurityConfiguration != nil {
		v.CrawlerSecurityConfiguration = in.CrawlerSecurityConfiguration
	}
	if in.Schedule != nil {
		if err := configureCrawlerSchedule(&row, value(in.Schedule), s.clock.Now()); err != nil {
			return nil, err
		}
	}
	if in.Role != nil {
		if err := s.passRole(ctx, crawlerRole(row.Key.Scope, value(in.Role)), row.Key.ARN("crawler")); err != nil {
			return nil, err
		}
		v.Role = in.Role
	}
	normalizeCrawler(row.Key.Scope, v)
	if err := validateCrawler(*v); err != nil {
		return nil, err
	}
	v.LastUpdated = new(s.clock.Now().UTC())
	v.Version = new(*v.Version + 1)
	if in.Targets != nil || in.Role != nil {
		if err := s.validateCrawlerSources(ctx, row.Key, *v); err != nil {
			return nil, err
		}
	}
	if err := tx.PutCrawler(row); err != nil {
		return nil, err
	}
	return &api.UpdateCrawlerOutput{}, nil
}
func (s *Service) deleteCrawler(ctx context.Context, tx Transaction, in *api.DeleteCrawlerInput) (*api.DeleteCrawlerOutput, error) {
	row, err := s.loadCrawler(ctx, tx, value(in.Name), "DeleteCrawler")
	if err != nil {
		return nil, err
	}
	if value(row.Crawler.State) != "READY" {
		return nil, failure("CrawlerRunningException", "Crawler is running.")
	}
	if err := tx.DeleteCrawler(row.Key); err != nil {
		return nil, err
	}
	return &api.DeleteCrawlerOutput{}, nil
}
func (s *Service) admitCrawl(ctx context.Context, tx Transaction, row CrawlerRecord, trigger, workflow, workflowRun string) (string, error) {
	if value(row.Crawler.State) == "STOPPING" {
		return "", failure("CrawlerStoppingException", "Crawler is stopping.")
	}
	if value(row.Crawler.State) != "READY" {
		return "", failure("CrawlerRunningException", "Crawler is running.")
	}
	if err := s.crawlerExecutionSupported(row.Crawler); err != nil {
		return "", err
	}
	id := uuid.NewString()
	row.RunID = id
	row.Crawler.State = new(api.CrawlerStateRUNNING)
	run := CrawlRecord{ID: id, Crawler: row.Key, State: "RUNNING", Phase: "QUEUED", Started: s.clock.Now().UTC(), ParentEventID: awsctx.FromContext(ctx).ParentEventID, TriggerName: trigger, WorkflowName: workflow, WorkflowRunID: workflowRun}
	if err := tx.PutCrawl(run); err != nil {
		return "", err
	}
	if err := tx.PutCrawler(row); err != nil {
		return "", err
	}
	if err := s.crawlerEvent(ctx, row, "Started", ""); err != nil {
		return "", err
	}
	return id, nil
}
func (s *Service) startCrawler(ctx context.Context, tx Transaction, in *api.StartCrawlerInput) (*api.StartCrawlerOutput, error) {
	row, err := s.loadCrawler(ctx, tx, value(in.Name), "StartCrawler")
	if err != nil {
		return nil, err
	}
	if _, err = s.admitCrawl(ctx, tx, row, "", "", ""); err != nil {
		return nil, err
	}
	return &api.StartCrawlerOutput{}, nil
}
func (s *Service) stopCrawl(tx Transaction, row CrawlerRecord) error {
	if value(row.Crawler.State) == "READY" {
		return failure("CrawlerNotRunningException", "Crawler is not running.")
	}
	if value(row.Crawler.State) == "STOPPING" {
		return failure("CrawlerStoppingException", "Crawler is stopping.")
	}
	run, err := tx.Crawl(row.RunID)
	if err != nil {
		return err
	}
	run.State = "CANCELLING"
	row.Crawler.State = new(api.CrawlerStateSTOPPING)
	if err := tx.PutCrawl(run); err != nil {
		return err
	}
	return tx.PutCrawler(row)
}
func (s *Service) stopCrawler(ctx context.Context, tx Transaction, in *api.StopCrawlerInput) (*api.StopCrawlerOutput, error) {
	row, err := s.loadCrawler(ctx, tx, value(in.Name), "StopCrawler")
	if err != nil {
		return nil, err
	}
	if err := s.stopCrawl(tx, row); err != nil {
		return nil, err
	}
	return &api.StopCrawlerOutput{}, nil
}
func crawlHistoryState(state string) string {
	switch state {
	case "SUCCEEDED":
		return "COMPLETED"
	case "CANCELLED":
		return "STOPPED"
	case "CANCELLING":
		return "RUNNING"
	default:
		return state
	}
}

type crawlerHistoryFilter struct {
	field, operator, value string
	stamp                  time.Time
}

func parseCrawlFilters(filters api.CrawlsFilterList) ([]crawlerHistoryFilter, error) {
	out := make([]crawlerHistoryFilter, len(filters))
	for i, filter := range filters {
		v := crawlerHistoryFilter{field: value(filter.FieldName), operator: value(filter.FilterOperator), value: value(filter.FieldValue)}
		switch v.operator {
		case "EQ", "NE", "GT", "GE", "LT", "LE":
		default:
			return nil, failure("InvalidInputException", "Invalid crawler history filter operator.")
		}
		switch v.field {
		case "CRAWL_ID", "STATE":
		case "START_TIME", "END_TIME":
			stamp, err := strconv.ParseInt(v.value, 10, 64)
			if err != nil {
				return nil, failure("InvalidInputException", "Timestamp filter requires epoch milliseconds.")
			}
			v.stamp = time.UnixMilli(stamp)
		case "DPU_HOUR":
			return nil, unsupported("Native DPU accounting is not available for local crawlers.")
		default:
			return nil, failure("InvalidInputException", "Invalid crawler history filter field.")
		}
		out[i] = v
	}
	return out, nil
}
func crawlMatches(row CrawlRecord, filters []crawlerHistoryFilter) bool {
	for _, filter := range filters {
		var comparison int
		switch filter.field {
		case "CRAWL_ID":
			comparison = strings.Compare(row.ID, filter.value)
		case "STATE":
			comparison = strings.Compare(crawlHistoryState(row.State), filter.value)
		case "START_TIME":
			comparison = row.Started.Compare(filter.stamp)
		case "END_TIME":
			if row.Completed == nil {
				return false
			}
			comparison = row.Completed.Compare(filter.stamp)
		}
		matched := false
		switch filter.operator {
		case "EQ":
			matched = comparison == 0
		case "NE":
			matched = comparison != 0
		case "GT":
			matched = comparison > 0
		case "GE":
			matched = comparison >= 0
		case "LT":
			matched = comparison < 0
		case "LE":
			matched = comparison <= 0
		}
		if !matched {
			return false
		}
	}
	return true
}
func (s *Service) listCrawls(ctx context.Context, tx Transaction, in *api.ListCrawlsInput) (*api.ListCrawlsOutput, error) {
	row, err := s.loadCrawler(ctx, tx, value(in.CrawlerName), "ListCrawls")
	if err != nil {
		return nil, err
	}
	filters, err := parseCrawlFilters(in.Filters)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Crawls(row.Key)
	if err != nil {
		return nil, err
	}
	selected := rows[:0]
	for _, run := range rows {
		if crawlMatches(run, filters) {
			selected = append(selected, run)
		}
	}
	filter, _ := json.Marshal(in.Filters)
	start, end, next, err := crawlerPage(row.Key.Scope, "crawl-history", row.Key.Name+string(filter), in.NextToken, in.MaxResults, len(selected))
	if err != nil {
		return nil, err
	}
	out := &api.ListCrawlsOutput{Crawls: api.CrawlerHistoryList{}, NextToken: next}
	for _, run := range selected[start:end] {
		v := api.CrawlerHistory{CrawlId: new(api.CrawlId(run.ID)), StartTime: &run.Started, EndTime: run.Completed, State: new(api.CrawlerHistoryState(crawlHistoryState(run.State)))}
		if run.ErrorMessage != "" {
			v.ErrorMessage = new(api.DescriptionString(run.ErrorMessage))
		}
		out.Crawls = append(out.Crawls, v)
	}
	return out, nil
}
func crawlerResourceTags(tx Reader, scope Scope, arn string) (map[string]string, error) {
	prefix := ResourceKey{Scope: scope}.ARN("crawler")
	if !strings.HasPrefix(arn, prefix) {
		return nil, ErrNotFound
	}
	row, err := tx.Crawler(ResourceKey{Scope: scope, Name: strings.TrimPrefix(arn, prefix)})
	if err != nil {
		return nil, err
	}
	return maps.Clone(row.Tags), nil
}
func tagCrawlerResource(tx Transaction, scope Scope, arn string, tags map[string]string) error {
	prefix := ResourceKey{Scope: scope}.ARN("crawler")
	if !strings.HasPrefix(arn, prefix) {
		return ErrNotFound
	}
	row, err := tx.Crawler(ResourceKey{Scope: scope, Name: strings.TrimPrefix(arn, prefix)})
	if err != nil {
		return err
	}
	row.Tags = maps.Clone(tags)
	return tx.PutCrawler(row)
}

func (s *Service) validateCrawlerSources(ctx context.Context, key ResourceKey, v api.Crawler) error {
	if len(v.Targets.S3Targets) == 0 {
		return nil
	}
	if s.crawlerSource == nil {
		return unsupported("Crawler source metadata adapter is not configured.")
	}
	err := s.crawlerSource.Validate(ctx, key.Scope, crawlerRole(key.Scope, value(v.Role)), key.ARN("crawler"), *v.Targets)
	if err == nil {
		return nil
	}
	rejected := wireError(err)
	if rejected.Code == "NoSuchBucket" || rejected.Code == "NotFound" || rejected.StatusCode == 404 {
		return failure("InvalidInputException", "Unable to validate the S3 crawler target because its bucket was not found.")
	}
	return err
}
