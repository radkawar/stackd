// Package eventbridge persists regional EventBridge state and delivery work.
package eventbridge

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/services/eventbridge/inputtransform"
	domain "stackd/storage/eventbridge"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/eventbridge/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func (r reader) Bus(k domain.BusKey) (domain.BusRecord, error) {
	v, err := r.q.GetBus(r.ctx, sqlcgen.GetBusParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.BusRecord{}, missing(err)
	}
	return r.bus(v)
}
func (r reader) bus(v sqlcgen.EventbridgeBus) (domain.BusRecord, error) {
	tags, err := r.q.GetBusTags(r.ctx, sqlcgen.GetBusTagsParams{Partition: v.Partition, Account: v.Account, Region: v.Region, BusName: v.Name})
	if err != nil {
		return domain.BusRecord{}, err
	}
	out := domain.BusRecord{Key: domain.BusKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.Name}, Description: v.Description, Created: v.Created, Modified: v.Modified, Tags: map[string]string{}, Policy: authorization.BoundPolicy{Document: v.Policy}}
	out.KmsKeyIdentifier, out.DeadLetterARN = v.KmsKeyIdentifier, v.DeadLetterArn
	out.ConfigurationDataKey, out.ConfigurationKeyARN = v.ConfigurationDataKey, v.ConfigurationKeyArn
	for _, tag := range tags {
		out.Tags[tag.Key] = tag.Value
	}
	principals, err := r.q.GetBusPolicyPrincipals(r.ctx, sqlcgen.GetBusPolicyPrincipalsParams{Partition: v.Partition, Account: v.Account, Region: v.Region, BusName: v.Name})
	if err != nil {
		return domain.BusRecord{}, err
	}
	if len(principals) > 0 {
		out.Policy.PrincipalIDs = make(map[string]string, len(principals))
		for _, principal := range principals {
			out.Policy.PrincipalIDs[principal.Arn] = principal.PrincipalID
		}
	}
	return out, nil
}
func (r reader) Buses(scope domain.Scope) ([]domain.BusRecord, error) {
	rows, err := r.q.ListBuses(r.ctx, sqlcgen.ListBusesParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.BusRecord, 0, len(rows))
	for _, v := range rows {
		bus, err := r.bus(v)
		if err != nil {
			return nil, err
		}
		out = append(out, bus)
	}
	return out, nil
}
func (r reader) Rule(k domain.RuleKey) (domain.RuleRecord, error) {
	v, err := r.q.GetRule(r.ctx, sqlcgen.GetRuleParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, Name: k.Name})
	if err != nil {
		return domain.RuleRecord{}, missing(err)
	}
	return r.rule(v)
}
func (r reader) rule(v sqlcgen.EventbridgeRule) (domain.RuleRecord, error) {
	tags, err := r.q.GetRuleTags(r.ctx, sqlcgen.GetRuleTagsParams{Partition: v.Partition, Account: v.Account, Region: v.Region, BusName: v.BusName, RuleName: v.Name})
	if err != nil {
		return domain.RuleRecord{}, err
	}
	out := domain.RuleRecord{Key: domain.RuleKey{Bus: domain.BusKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.BusName}, Name: v.Name}, ManagedBy: v.ManagedBy, ArchiveID: v.ArchiveID, Pattern: v.Pattern, Description: v.Description, State: v.State, CreatedBy: v.CreatedBy, RoleARN: v.RoleArn, HasPattern: v.HasPattern, HasDescription: v.HasDescription, ScheduleExpression: v.ScheduleExpression.String, HasScheduleExpression: v.ScheduleExpression.Valid, Tags: map[string]string{}}
	out.EncryptedPattern = v.EncryptedPattern
	if v.NextScheduleSeconds.Valid {
		due := time.Unix(v.NextScheduleSeconds.Int64, 0).UTC()
		out.NextSchedule = &due
	}
	for _, tag := range tags {
		out.Tags[tag.Key] = tag.Value
	}
	return out, nil
}
func (r reader) Rules(k domain.BusKey) ([]domain.RuleRecord, error) {
	rows, err := r.q.ListRules(r.ctx, sqlcgen.ListRulesParams{Partition: k.Partition, Account: k.Account, Region: k.Region, BusName: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.RuleRecord, 0, len(rows))
	for _, v := range rows {
		rule, err := r.rule(v)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}
func (r reader) NextScheduledRule() (domain.RuleRecord, bool, error) {
	v, err := r.q.NextScheduledRule(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.RuleRecord{}, false, nil
	}
	if err != nil {
		return domain.RuleRecord{}, false, err
	}
	out, err := r.rule(v)
	return out, err == nil, err
}
func (r reader) Targets(k domain.RuleKey) ([]domain.TargetRecord, error) {
	rows, err := r.q.ListTargets(r.ctx, sqlcgen.ListTargetsParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, RuleName: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.TargetRecord, 0, len(rows))
	for _, v := range rows {
		target := domain.TargetRecord{Rule: k, ID: v.ID, ARN: v.Arn, RoleARN: v.RoleArn, Input: inputtransform.Definition{Input: v.Input, InputPath: v.InputPath}, MessageGroupID: v.MessageGroupID, DeadLetterARN: v.DeadLetterArn, MaxRetries: int(v.MaxRetries), MaxAgeSeconds: int(v.MaxAgeSeconds), HasRetryPolicy: v.HasRetryPolicy, HasMaxRetries: v.HasMaxRetries, HasMaxAge: v.HasMaxAge}
		target.EncryptedConfiguration = v.EncryptedConfiguration
		target.KinesisParameters = decodeKinesisParameters(v.KinesisPartitionKeyPath)
		target.EcsParameters, err = decodeTargetECS(v)
		if err != nil {
			return nil, err
		}
		target.HttpParameters, err = decodeHTTPParameters(v.HttpPresent, v.HttpHeaders, v.HttpPaths, v.HttpQuery)
		if err != nil {
			return nil, err
		}
		if v.InputTemplate != nil {
			target.Input.Transformer = &inputtransform.Transformer{InputTemplate: *v.InputTemplate}
			paths, err := r.q.GetTargetInputPaths(r.ctx, sqlcgen.GetTargetInputPathsParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, RuleName: k.Name, TargetID: v.ID})
			if err != nil {
				return nil, err
			}
			if len(paths) > 0 {
				target.Input.Transformer.InputPathsMap = make(map[string]string, len(paths))
				for _, path := range paths {
					target.Input.Transformer.InputPathsMap[path.Key] = path.Path
				}
			}
		}
		out = append(out, target)
	}
	return out, nil
}
func (r reader) RuleNamesByTarget(bus domain.BusKey, arn string) ([]string, error) {
	return r.q.RuleNamesByTarget(r.ctx, sqlcgen.RuleNamesByTargetParams{
		Partition: bus.Partition, Account: bus.Account, Region: bus.Region, BusName: bus.Name, Arn: arn,
	})
}
func (r reader) Event(id string) (domain.EventRecord, error) {
	v, err := r.q.GetEvent(r.ctx, id)
	if err != nil {
		return domain.EventRecord{}, missing(err)
	}
	resources, err := r.q.GetEventResources(r.ctx, id)
	if err != nil {
		return domain.EventRecord{}, err
	}
	return domain.EventRecord{ID: v.ID, WireID: v.WireID, ReplayName: v.ReplayName, Bus: domain.BusKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.BusName}, Source: v.Source, DetailType: v.DetailType, Detail: v.Detail, Resources: resources, Time: v.EventTime, Accepted: v.Accepted, Account: v.ProducerAccount, Region: v.WireRegion, SameRegionHop: v.SameRegionHop, CrossRegionHop: v.CrossRegionHop, RequestID: v.RequestID, ActorARN: v.ActorArn, TraceHeader: v.TraceHeader, Payload: domain.ArchivePayload{Content: v.EncryptedContent, DataKey: v.EncryptedDataKey}, KeyARN: v.KeyArn, BusDeadLetterARN: v.BusDeadLetterArn, ConfigurationDataKey: v.ConfigurationDataKey, ConfigurationKeyARN: v.ConfigurationKeyArn}, nil
}
func (r reader) Delivery(id string) (domain.DeliveryRecord, error) {
	v, err := r.q.GetDelivery(r.ctx, id)
	if err != nil {
		return domain.DeliveryRecord{}, missing(err)
	}
	return delivery(v)
}
func (r reader) EventDeliveries(id string) ([]domain.DeliveryRecord, error) {
	rows, err := r.q.ListEventDeliveries(r.ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]domain.DeliveryRecord, 0, len(rows))
	for _, row := range rows {
		v, err := delivery(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) NextDelivery() (domain.DeliveryRecord, bool, error) {
	v, err := r.q.NextDelivery(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.DeliveryRecord{}, false, nil
	}
	if err != nil {
		return domain.DeliveryRecord{}, false, err
	}
	out, err := delivery(v)
	return out, err == nil, err
}
func delivery(v sqlcgen.EventbridgeDelivery) (domain.DeliveryRecord, error) {
	out := domain.DeliveryRecord{ID: v.ID, EventID: v.EventID, ArchiveID: v.ArchiveID, RuleARN: v.RuleArn, TargetID: v.TargetID, TargetARN: v.TargetArn, RoleARN: v.RoleArn, Input: v.Input, HasInput: v.HasInput, MessageGroupID: v.MessageGroupID, DeadLetterARN: v.DeadLetterArn, MaxRetries: int(v.MaxRetries), MaxAgeSeconds: int(v.MaxAgeSeconds), Attempts: int(v.Attempts), Due: v.Due, Version: uint64(v.Version), State: v.State, LastErrorCode: v.LastErrorCode, LastErrorMessage: v.LastErrorMessage, ExhaustedRetryCondition: v.ExhaustedRetryCondition}
	out.BusProcessing, out.RulePattern, out.TargetConfiguration = v.BusProcessing, v.RulePattern, v.TargetConfiguration
	out.RuleMatched, out.MatchOnly = v.RuleMatched, v.MatchOnly
	out.KinesisParameters = decodeKinesisParameters(v.KinesisPartitionKeyPath)
	var err error
	out.EcsParameters, err = decodeDeliveryECS(v)
	if err != nil {
		return out, err
	}
	out.HttpParameters, err = decodeHTTPParameters(v.HttpPresent, v.HttpHeaders, v.HttpPaths, v.HttpQuery)
	return out, err
}
func (w writer) PutBus(v domain.BusRecord) error {
	k := v.Key
	if err := w.q.PutBus(w.ctx, sqlcgen.PutBusParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name, Description: v.Description, Created: v.Created, Modified: v.Modified, Policy: v.Policy.Document, KmsKeyIdentifier: v.KmsKeyIdentifier, DeadLetterArn: v.DeadLetterARN, ConfigurationDataKey: archiveBytes(v.ConfigurationDataKey), ConfigurationKeyArn: v.ConfigurationKeyARN}); err != nil {
		return err
	}
	if err := w.q.DeleteBusTags(w.ctx, sqlcgen.DeleteBusTagsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, BusName: k.Name}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutBusTag(w.ctx, sqlcgen.PutBusTagParams{Partition: k.Partition, Account: k.Account, Region: k.Region, BusName: k.Name, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteBusPolicyPrincipals(w.ctx, sqlcgen.DeleteBusPolicyPrincipalsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, BusName: k.Name}); err != nil {
		return err
	}
	for arn, id := range v.Policy.PrincipalIDs {
		if err := w.q.PutBusPolicyPrincipal(w.ctx, sqlcgen.PutBusPolicyPrincipalParams{Partition: k.Partition, Account: k.Account, Region: k.Region, BusName: k.Name, Arn: arn, PrincipalID: id}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteBus(k domain.BusKey) error {
	return w.q.DeleteBus(w.ctx, sqlcgen.DeleteBusParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
}
func (w writer) PutRule(v domain.RuleRecord) error {
	k := v.Key
	if err := w.q.PutRule(w.ctx, sqlcgen.PutRuleParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, Name: k.Name, ManagedBy: v.ManagedBy, ArchiveID: v.ArchiveID, Pattern: v.Pattern, Description: v.Description, State: v.State, CreatedBy: v.CreatedBy, RoleArn: v.RoleARN, HasPattern: v.HasPattern, HasDescription: v.HasDescription, ScheduleExpression: sql.NullString{String: v.ScheduleExpression, Valid: v.HasScheduleExpression}, NextScheduleSeconds: scheduleSeconds(v.NextSchedule), EncryptedPattern: archiveBytes(v.EncryptedPattern)}); err != nil {
		return err
	}
	if err := w.q.DeleteRuleTags(w.ctx, sqlcgen.DeleteRuleTagsParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, RuleName: k.Name}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutRuleTag(w.ctx, sqlcgen.PutRuleTagParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, RuleName: k.Name, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) UpdateRuleSchedule(k domain.RuleKey, due *time.Time) error {
	n, err := w.q.UpdateRuleSchedule(w.ctx, sqlcgen.UpdateRuleScheduleParams{NextScheduleSeconds: scheduleSeconds(due), Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, Name: k.Name})
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func scheduleSeconds(due *time.Time) sql.NullInt64 {
	if due == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: due.Unix(), Valid: true}
}

func (w writer) DeleteRule(k domain.RuleKey) error {
	return w.q.DeleteRule(w.ctx, sqlcgen.DeleteRuleParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, Name: k.Name})
}
func (w writer) PutTarget(v domain.TargetRecord) error {
	k := v.Rule
	var template *string
	if v.Input.Transformer != nil {
		template = &v.Input.Transformer.InputTemplate
	}
	row := sqlcgen.PutTargetParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, RuleName: k.Name, ID: v.ID, Arn: v.ARN, RoleArn: v.RoleARN, Input: v.Input.Input, InputPath: v.Input.InputPath, InputTemplate: template, MessageGroupID: v.MessageGroupID, DeadLetterArn: v.DeadLetterARN, MaxRetries: int64(v.MaxRetries), MaxAgeSeconds: int64(v.MaxAgeSeconds), HasRetryPolicy: v.HasRetryPolicy, HasMaxRetries: v.HasMaxRetries, HasMaxAge: v.HasMaxAge}
	row.EncryptedConfiguration = archiveBytes(v.EncryptedConfiguration)
	row.KinesisPartitionKeyPath = encodeKinesisParameters(v.KinesisParameters)
	if err := encodeTargetECS(&row, v.EcsParameters); err != nil {
		return err
	}
	row.HttpPresent = v.HttpParameters != nil
	var err error
	row.HttpHeaders, row.HttpPaths, row.HttpQuery, err = encodeHTTPParameters(v.HttpParameters)
	if err != nil {
		return err
	}
	if err := w.q.PutTarget(w.ctx, row); err != nil {
		return err
	}
	if err := w.q.DeleteTargetInputPaths(w.ctx, sqlcgen.DeleteTargetInputPathsParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, RuleName: k.Name, TargetID: v.ID}); err != nil {
		return err
	}
	if v.Input.Transformer != nil {
		for key, path := range v.Input.Transformer.InputPathsMap {
			if err := w.q.PutTargetInputPath(w.ctx, sqlcgen.PutTargetInputPathParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, RuleName: k.Name, TargetID: v.ID, Key: key, Path: path}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) DeleteTarget(k domain.RuleKey, id string) error {
	return w.q.DeleteTarget(w.ctx, sqlcgen.DeleteTargetParams{Partition: k.Bus.Partition, Account: k.Bus.Account, Region: k.Bus.Region, BusName: k.Bus.Name, RuleName: k.Name, ID: id})
}
func (w writer) PutEvent(v domain.EventRecord) error {
	k := v.Bus
	if err := w.q.PutEvent(w.ctx, sqlcgen.PutEventParams{ID: v.ID, WireID: v.WireID, ReplayName: v.ReplayName, Partition: k.Partition, Account: k.Account, Region: k.Region, BusName: k.Name, Source: v.Source, DetailType: v.DetailType, Detail: v.Detail, EventTime: v.Time, Accepted: v.Accepted, ProducerAccount: v.Account, WireRegion: v.Region, SameRegionHop: v.SameRegionHop, CrossRegionHop: v.CrossRegionHop, RequestID: v.RequestID, ActorArn: v.ActorARN, TraceHeader: v.TraceHeader, EncryptedContent: archiveBytes(v.Payload.Content), EncryptedDataKey: archiveBytes(v.Payload.DataKey), KeyArn: v.KeyARN, BusDeadLetterArn: v.BusDeadLetterARN, ConfigurationDataKey: archiveBytes(v.ConfigurationDataKey), ConfigurationKeyArn: v.ConfigurationKeyARN}); err != nil {
		return err
	}
	for i, arn := range v.Resources {
		if err := w.q.PutEventResource(w.ctx, sqlcgen.PutEventResourceParams{EventID: v.ID, Position: int64(i), Arn: arn}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) PutDelivery(v domain.DeliveryRecord) error {
	row := sqlcgen.PutDeliveryParams{ID: v.ID, EventID: v.EventID, ArchiveID: v.ArchiveID, RuleArn: v.RuleARN, TargetID: v.TargetID, TargetArn: v.TargetARN, RoleArn: v.RoleARN, Input: v.Input, HasInput: v.HasInput, MessageGroupID: v.MessageGroupID, DeadLetterArn: v.DeadLetterARN, MaxRetries: int64(v.MaxRetries), MaxAgeSeconds: int64(v.MaxAgeSeconds), Attempts: int64(v.Attempts), Due: v.Due, Version: int64(v.Version), State: v.State, LastErrorCode: v.LastErrorCode, LastErrorMessage: v.LastErrorMessage, ExhaustedRetryCondition: v.ExhaustedRetryCondition}
	row.BusProcessing, row.RulePattern, row.TargetConfiguration = v.BusProcessing, archiveBytes(v.RulePattern), archiveBytes(v.TargetConfiguration)
	row.RuleMatched, row.MatchOnly = v.RuleMatched, v.MatchOnly
	row.KinesisPartitionKeyPath = encodeKinesisParameters(v.KinesisParameters)
	if err := encodeDeliveryECS(&row, v.EcsParameters); err != nil {
		return err
	}
	row.HttpPresent = v.HttpParameters != nil
	var err error
	row.HttpHeaders, row.HttpPaths, row.HttpQuery, err = encodeHTTPParameters(v.HttpParameters)
	if err != nil {
		return err
	}
	return w.q.PutDelivery(w.ctx, row)
}
