package lambda

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) EventSourceMapping(k domain.EventSourceMappingKey) (domain.EventSourceMappingRecord, error) {
	v, err := r.q.GetEventSourceMapping(r.ctx, sqlcgen.GetEventSourceMappingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.EventSourceMappingRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.EventSourceMappingRecord{}, err
	}
	return r.eventSourceMappingRecord(v)
}
func (r reader) EventSourceMappings(k domain.Scope) ([]domain.EventSourceMappingRecord, error) {
	rows, err := r.q.ListEventSourceMappings(r.ctx, sqlcgen.ListEventSourceMappingsParams{Partition: k.Partition, Account: k.Account, Region: k.Region})
	if err != nil {
		return nil, err
	}
	return r.eventSourceMappingRecords(rows)
}
func (r reader) AllEventSourceMappings() ([]domain.EventSourceMappingRecord, error) {
	rows, err := r.q.AllEventSourceMappings(r.ctx)
	if err != nil {
		return nil, err
	}
	return r.eventSourceMappingRecords(rows)
}
func (r reader) eventSourceMappingRecords(rows []sqlcgen.LambdaEventSourceMapping) ([]domain.EventSourceMappingRecord, error) {
	out := make([]domain.EventSourceMappingRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.eventSourceMappingRecord(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) eventSourceMappingRecord(v sqlcgen.LambdaEventSourceMapping) (domain.EventSourceMappingRecord, error) {
	k := domain.EventSourceMappingKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, UUID: v.Uuid}
	out := domain.EventSourceMappingRecord{
		Key: k, Function: domain.FunctionReference{FunctionKey: domain.FunctionKey{Scope: domain.Scope{Partition: v.FunctionPartition, Account: v.FunctionAccount, Region: v.FunctionRegion}, Name: v.FunctionName}, Qualifier: v.FunctionQualifier},
		Owner:          domain.MappingOwner{StackID: v.OwnerStackID, LogicalID: v.OwnerLogicalID, Token: v.OwnerToken},
		EventSourceARN: v.EventSourceArn, Version: uint64(v.Version), State: v.State, StateTransitionReason: v.StateTransitionReason,
		LastModified: v.LastModified, TransitionAt: v.TransitionAt, TransitionState: v.TransitionState, LastProcessingResult: v.LastProcessingResult.String,
		Settings: domain.EventSourceMappingSettings{BatchSize: int(v.BatchSize), BatchingWindow: time.Duration(v.BatchingWindowSeconds) * time.Second, ReportBatchItemFailures: v.ReportBatchItemFailures},
		Tags:     map[string]string{},
	}
	if v.MaximumConcurrency.Valid {
		out.Settings.MaximumConcurrency = new(int(v.MaximumConcurrency.Int64))
	}
	if v.MinimumPollers.Valid {
		out.Settings.ProvisionedPollers = &domain.SQSProvisionedPollers{Minimum: int(v.MinimumPollers.Int64), Maximum: int(v.MaximumPollers.Int64)}
	}
	if v.StreamStartingPosition.Valid {
		out.Settings.Stream = &domain.StreamMappingSettings{
			StartingPosition:           v.StreamStartingPosition.String,
			StartingPositionTimestamp:  v.StreamStartingPositionTimestamp.Time,
			ParallelizationFactor:      int(v.StreamParallelizationFactor.Int64),
			MaximumRetryAttempts:       int(v.StreamMaximumRetryAttempts.Int64),
			MaximumRecordAge:           time.Duration(v.StreamMaximumRecordAgeSeconds.Int64) * time.Second,
			BisectBatchOnFunctionError: v.StreamBisectBatchOnFunctionError.Bool,
			TumblingWindow:             time.Duration(v.StreamTumblingWindowSeconds.Int64) * time.Second,
			OnFailure:                  v.StreamOnFailure.String,
		}
	}
	kafka, err := r.q.GetKafkaMapping(r.ctx, sqlcgen.GetKafkaMappingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
	if err == nil {
		out.Settings.Kafka = &domain.KafkaMappingSettings{Topic: kafka.Topic, ConsumerGroupID: kafka.ConsumerGroupID, StartingPosition: kafka.StartingPosition, StartingPositionTimestamp: kafka.StartingPositionTimestamp, Authentication: kafka.Authentication, SecretARN: kafka.SecretArn, Identity: domain.KafkaIdentity{ClusterID: kafka.ClusterID, TopicID: kafka.TopicID}}
		out.Settings.BatchingWindow = time.Duration(kafka.BatchingWindowNs)
		out.Settings.Kafka.RootCASecretARN = kafka.RootCaSecretArn
		out.Settings.Kafka.NetworkRoleARN = kafka.NetworkRoleArn
		out.Settings.Kafka.BootstrapServers, err = r.q.ListKafkaBootstrapServers(r.ctx, sqlcgen.ListKafkaBootstrapServersParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
		if err != nil {
			return out, err
		}
		components, err := r.q.ListKafkaNetworkComponents(r.ctx, sqlcgen.ListKafkaNetworkComponentsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
		if err != nil {
			return out, err
		}
		for _, component := range components {
			if component.Kind == "subnet" {
				out.Settings.Kafka.Network.SubnetIDs = append(out.Settings.Kafka.Network.SubnetIDs, component.ResourceID)
			} else {
				out.Settings.Kafka.Network.SecurityGroupIDs = append(out.Settings.Kafka.Network.SecurityGroupIDs, component.ResourceID)
			}
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	if err := r.loadDocumentDBMapping(&out); err != nil {
		return out, err
	}
	if err := r.loadMQMapping(&out); err != nil {
		return out, err
	}
	out.Settings.Filters, err = r.q.ListEventSourceMappingFilters(r.ctx, sqlcgen.ListEventSourceMappingFiltersParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
	if err != nil {
		return out, err
	}
	encrypted, err := r.q.GetEventSourceFilterEncryption(r.ctx, sqlcgen.GetEventSourceFilterEncryptionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
	if err == nil {
		out.Settings.KMSKeyARN = encrypted.KeyArn
		out.Settings.EncryptedFilters = &domain.EncryptedMappingFilters{Content: encrypted.Content, DataKey: encrypted.DataKey, FunctionARN: encrypted.FunctionArn, Format: encrypted.Format}
		out.Settings.Filters = nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	out.Settings.Metrics, err = r.q.ListEventSourceMappingMetrics(r.ctx, sqlcgen.ListEventSourceMappingMetricsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
	if err != nil {
		return out, err
	}
	tags, err := r.q.ListEventSourceMappingTags(r.ctx, sqlcgen.ListEventSourceMappingTagsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
	if err != nil {
		return out, err
	}
	for _, tag := range tags {
		out.Tags[tag.Key] = tag.Value
	}
	return out, nil
}
func (w writer) PutEventSourceMapping(v domain.EventSourceMappingRecord) error {
	k := v.Key
	params := sqlcgen.PutEventSourceMappingParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID,
		FunctionPartition: v.Function.Partition, FunctionAccount: v.Function.Account, FunctionRegion: v.Function.Region, FunctionName: v.Function.Name, FunctionQualifier: v.Function.Qualifier,
		OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token,
		EventSourceArn: v.EventSourceARN, Version: sqlite.Uint64(v.Version), State: v.State, StateTransitionReason: v.StateTransitionReason,
		LastModified: v.LastModified, TransitionAt: v.TransitionAt, TransitionState: v.TransitionState,
		BatchSize: int64(v.Settings.BatchSize), BatchingWindowSeconds: int64(v.Settings.BatchingWindow / time.Second), ReportBatchItemFailures: v.Settings.ReportBatchItemFailures,
	}
	if v.Settings.MaximumConcurrency != nil {
		params.MaximumConcurrency = sql.NullInt64{Int64: int64(*v.Settings.MaximumConcurrency), Valid: true}
	}
	if p := v.Settings.ProvisionedPollers; p != nil {
		params.MinimumPollers = sql.NullInt64{Int64: int64(p.Minimum), Valid: true}
		params.MaximumPollers = sql.NullInt64{Int64: int64(p.Maximum), Valid: true}
	}
	if d := v.Settings.Stream; d != nil {
		params.LastProcessingResult = sql.NullString{String: v.LastProcessingResult, Valid: true}
		params.StreamStartingPosition = sql.NullString{String: d.StartingPosition, Valid: true}
		params.StreamStartingPositionTimestamp = sql.NullTime{Time: d.StartingPositionTimestamp, Valid: !d.StartingPositionTimestamp.IsZero()}
		params.StreamParallelizationFactor = sql.NullInt64{Int64: int64(d.ParallelizationFactor), Valid: true}
		params.StreamMaximumRetryAttempts = sql.NullInt64{Int64: int64(d.MaximumRetryAttempts), Valid: true}
		params.StreamMaximumRecordAgeSeconds = sql.NullInt64{Int64: int64(d.MaximumRecordAge / time.Second), Valid: true}
		params.StreamBisectBatchOnFunctionError = sql.NullBool{Bool: d.BisectBatchOnFunctionError, Valid: true}
		params.StreamTumblingWindowSeconds = sql.NullInt64{Int64: int64(d.TumblingWindow / time.Second), Valid: true}
		params.StreamOnFailure = sql.NullString{String: d.OnFailure, Valid: true}
	}
	if v.Settings.Kafka != nil || v.Settings.DocumentDB != nil || v.Settings.MQ != nil {
		params.LastProcessingResult = sql.NullString{String: v.LastProcessingResult, Valid: true}
	}
	if err := w.q.PutEventSourceMapping(w.ctx, params); err != nil {
		return err
	}
	if d := v.Settings.Kafka; d != nil {
		if err := w.q.PutKafkaMapping(w.ctx, sqlcgen.PutKafkaMappingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID, Topic: d.Topic, ConsumerGroupID: d.ConsumerGroupID, StartingPosition: d.StartingPosition, StartingPositionTimestamp: d.StartingPositionTimestamp, BatchingWindowNs: int64(v.Settings.BatchingWindow), Authentication: d.Authentication, SecretArn: d.SecretARN, ClusterID: d.Identity.ClusterID, TopicID: d.Identity.TopicID, RootCaSecretArn: d.RootCASecretARN, NetworkRoleArn: d.NetworkRoleARN}); err != nil {
			return err
		}
		if err := w.q.DeleteKafkaBootstrapServers(w.ctx, sqlcgen.DeleteKafkaBootstrapServersParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID}); err != nil {
			return err
		}
		for i, endpoint := range d.BootstrapServers {
			if err := w.q.PutKafkaBootstrapServer(w.ctx, sqlcgen.PutKafkaBootstrapServerParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID, Position: int64(i), Endpoint: endpoint}); err != nil {
				return err
			}
		}
		if err := w.q.DeleteKafkaNetworkComponents(w.ctx, sqlcgen.DeleteKafkaNetworkComponentsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID}); err != nil {
			return err
		}
		for _, component := range [2]struct {
			kind      string
			resources []string
		}{{"subnet", d.Network.SubnetIDs}, {"security_group", d.Network.SecurityGroupIDs}} {
			for _, resource := range component.resources {
				if err := w.q.PutKafkaNetworkComponent(w.ctx, sqlcgen.PutKafkaNetworkComponentParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID, Kind: component.kind, ResourceID: resource}); err != nil {
					return err
				}
			}
		}
	}
	if err := w.putDocumentDBMapping(v); err != nil {
		return err
	}
	if err := w.putMQMapping(v); err != nil {
		return err
	}
	if encrypted := v.Settings.EncryptedFilters; encrypted != nil {
		if err := w.q.PutEventSourceFilterEncryption(w.ctx, sqlcgen.PutEventSourceFilterEncryptionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID, KeyArn: v.Settings.KMSKeyARN, FunctionArn: encrypted.FunctionARN, Content: encrypted.Content, DataKey: encrypted.DataKey, Format: encrypted.Format}); err != nil {
			return err
		}
		v.Settings.Filters = nil
	} else if err := w.q.DeleteEventSourceFilterEncryption(w.ctx, sqlcgen.DeleteEventSourceFilterEncryptionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID}); err != nil {
		return err
	}
	if err := w.q.DeleteEventSourceMappingFilters(w.ctx, sqlcgen.DeleteEventSourceMappingFiltersParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID}); err != nil {
		return err
	}
	for i, pattern := range v.Settings.Filters {
		if err := w.q.PutEventSourceMappingFilter(w.ctx, sqlcgen.PutEventSourceMappingFilterParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID, Position: int64(i), Pattern: pattern}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteEventSourceMappingMetrics(w.ctx, sqlcgen.DeleteEventSourceMappingMetricsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID}); err != nil {
		return err
	}
	for i, metric := range v.Settings.Metrics {
		if err := w.q.PutEventSourceMappingMetric(w.ctx, sqlcgen.PutEventSourceMappingMetricParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID, Position: int64(i), Metric: metric}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteEventSourceMappingTags(w.ctx, sqlcgen.DeleteEventSourceMappingTagsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutEventSourceMappingTag(w.ctx, sqlcgen.PutEventSourceMappingTagParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteEventSourceMapping(k domain.EventSourceMappingKey) error {
	if err := w.q.DeleteStreamShards(w.ctx, k.ARN()); err != nil {
		return err
	}
	return w.q.DeleteEventSourceMapping(w.ctx, sqlcgen.DeleteEventSourceMappingParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID})
}

func (w writer) SetEventSourceMappingProcessingResult(k domain.EventSourceMappingKey, result string) error {
	count, err := w.q.SetEventSourceMappingProcessingResult(w.ctx, sqlcgen.SetEventSourceMappingProcessingResultParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID,
		LastProcessingResult: sql.NullString{String: result, Valid: true},
	})
	if err == nil && count == 0 {
		return domain.ErrNotFound
	}
	return err
}
