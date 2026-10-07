package kinesis

import (
	"database/sql"
	"errors"
	api "stackd/internal/awsapi/kinesis"
	domain "stackd/storage/kinesis"
	"stackd/storage/sqlite/kinesis/internal/sqlcgen"
	"time"
)

func (r reader) Stream(k domain.StreamKey) (domain.StreamRecord, error) {
	row, err := r.q.GetStream(r.ctx, sqlcgen.GetStreamParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.StreamRecord{}, missing(err)
	}
	return r.stream(row)
}
func (r reader) Streams(q domain.StreamQuery) ([]domain.StreamRecord, error) {
	rows, err := r.q.ListStreams(r.ctx, sqlcgen.ListStreamsParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, AfterName: q.After, RowLimit: rowLimit(q.Limit)})
	if err != nil {
		return nil, err
	}
	return r.streams(rows)
}
func (r reader) AllStreams() ([]domain.StreamRecord, error) {
	rows, err := r.q.AllStreams(r.ctx)
	if err != nil {
		return nil, err
	}
	return r.streams(rows)
}
func (r reader) streams(rows []sqlcgen.KinesisStream) ([]domain.StreamRecord, error) {
	out := make([]domain.StreamRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.stream(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) stream(row sqlcgen.KinesisStream) (domain.StreamRecord, error) {
	k := domain.StreamKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name}
	out := domain.StreamRecord{Key: k, EngineID: row.EngineID, NextPartition: int32(row.NextPartition), RetentionNextAt: row.RetentionNextAt.UTC()}
	out.Owner = domain.ResourceOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}
	out.Data = api.StreamDescriptionSummary{
		ChannelCount:            integerPointer[api.ChannelCountObject](row.ChannelCount),
		ConsumerCount:           integerPointer[api.ConsumerCountObject](row.ConsumerCount),
		EncryptionType:          stringPointer[api.EncryptionType](row.EncryptionType),
		KeyId:                   stringPointer[api.KeyId](row.KeyID),
		MaxRecordSizeInKiB:      integerPointer[api.MaxRecordSizeInKiB](row.MaxRecordSizeKib),
		OpenShardCount:          integerPointer[api.ShardCountObject](row.OpenShardCount),
		RetentionPeriodHours:    integerPointer[api.RetentionPeriodHours](row.RetentionHours),
		StreamARN:               stringPointer[api.StreamARN](row.StreamArn),
		StreamCreationTimestamp: timePointer(row.CreatedAt),
		StreamId:                stringPointer[api.StreamId](row.StreamID),
		StreamName:              stringPointer[api.StreamName](row.StreamName),
		StreamStatus:            stringPointer[api.StreamStatus](row.Status),
	}
	if row.ModePresent {
		out.Data.StreamModeDetails = &api.StreamModeDetails{StreamMode: stringPointer[api.StreamMode](row.Mode)}
	}
	if row.WarmPresent {
		out.Data.WarmThroughput = &api.WarmThroughputObject{CurrentMiBps: integerPointer[api.NaturalIntegerObject](row.WarmCurrent), TargetMiBps: integerPointer[api.NaturalIntegerObject](row.WarmTarget)}
	}
	if row.MonitoringPresent {
		groups, err := r.q.ListMonitoringGroups(r.ctx, sqlcgen.ListMonitoringGroupsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
		if err != nil {
			return out, err
		}
		out.Data.EnhancedMonitoring = make(api.EnhancedMonitoringList, len(groups))
		for i, g := range groups {
			if g.MetricsPresent {
				out.Data.EnhancedMonitoring[i].ShardLevelMetrics = api.MetricsNameList{}
			}
		}
		metrics, err := r.q.ListMonitoringMetrics(r.ctx, sqlcgen.ListMonitoringMetricsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
		if err != nil {
			return out, err
		}
		for _, m := range metrics {
			out.Data.EnhancedMonitoring[m.GroupPosition].ShardLevelMetrics = append(out.Data.EnhancedMonitoring[m.GroupPosition].ShardLevelMetrics, api.MetricsName(m.Metric))
		}
	}
	if row.ShardUpdatesPresent {
		rows, err := r.q.ListShardUpdates(r.ctx, sqlcgen.ListShardUpdatesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
		if err != nil {
			return out, err
		}
		out.ShardCountUpdates = make([]time.Time, len(rows))
		for i, v := range rows {
			out.ShardCountUpdates[i] = v.At.UTC()
		}
	}
	if row.EncryptionUpdatesPresent {
		rows, err := r.q.ListEncryptionUpdates(r.ctx, sqlcgen.ListEncryptionUpdatesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
		if err != nil {
			return out, err
		}
		out.EncryptionUpdates = make([]domain.EncryptionUpdate, len(rows))
		for i, v := range rows {
			out.EncryptionUpdates[i] = domain.EncryptionUpdate{At: v.At.UTC(), Enabled: v.Enabled}
		}
	}
	p, err := r.q.GetPendingUpdate(r.ctx, sqlcgen.GetPendingUpdateParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err == nil {
		out.Pending = &domain.StreamUpdate{AcceptedAt: p.AcceptedAt.UTC(), RetentionHours: int32(p.RetentionHours), Mode: api.StreamMode(p.Mode), MaxRecordSizeKiB: int32(p.MaxRecordSizeKib), EncryptionType: api.EncryptionType(p.EncryptionType), KeyID: p.KeyID, WarmMiBps: integerPointer[int32](p.WarmMibps), PeakShardCount: int32(p.PeakShardCount)}
		if p.MonitoringPresent {
			rows, err := r.q.ListPendingMetrics(r.ctx, sqlcgen.ListPendingMetricsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
			if err != nil {
				return out, err
			}
			out.Pending.Monitoring = make([]api.MetricsName, len(rows))
			for i, v := range rows {
				out.Pending.Monitoring[i] = api.MetricsName(v.Metric)
			}
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	return out, nil
}
func (w writer) PutStream(v domain.StreamRecord) error {
	k, d := v.Key, &v.Data
	p := sqlcgen.PutStreamParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, EngineID: v.EngineID, NextPartition: int64(v.NextPartition), RetentionNextAt: v.RetentionNextAt.UTC(),
		MonitoringPresent: d.EnhancedMonitoring != nil, ModePresent: d.StreamModeDetails != nil, WarmPresent: d.WarmThroughput != nil, ShardUpdatesPresent: v.ShardCountUpdates != nil, EncryptionUpdatesPresent: v.EncryptionUpdates != nil,
		ChannelCount:     nullableInteger(d.ChannelCount),
		ConsumerCount:    nullableInteger(d.ConsumerCount),
		EncryptionType:   nullableString(d.EncryptionType),
		KeyID:            nullableString(d.KeyId),
		MaxRecordSizeKib: nullableInteger(d.MaxRecordSizeInKiB),
		OpenShardCount:   nullableInteger(d.OpenShardCount),
		RetentionHours:   nullableInteger(d.RetentionPeriodHours),
		StreamArn:        nullableString(d.StreamARN),
		CreatedAt:        nullableTime(d.StreamCreationTimestamp),
		StreamID:         nullableString(d.StreamId),
		StreamName:       nullableString(d.StreamName),
		Status:           nullableString(d.StreamStatus),
	}
	if d.StreamModeDetails != nil {
		p.Mode = nullableString(d.StreamModeDetails.StreamMode)
	}
	if d.WarmThroughput != nil {
		p.WarmCurrent = nullableInteger(d.WarmThroughput.CurrentMiBps)
		p.WarmTarget = nullableInteger(d.WarmThroughput.TargetMiBps)
	}
	if err := w.q.PutStream(w.ctx, p); err != nil {
		return err
	}
	if err := w.q.SetStreamOwner(w.ctx, sqlcgen.SetStreamOwnerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token}); err != nil {
		return err
	}
	if err := w.q.DeleteMonitoringMetrics(w.ctx, sqlcgen.DeleteMonitoringMetricsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteMonitoringGroups(w.ctx, sqlcgen.DeleteMonitoringGroupsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteShardUpdates(w.ctx, sqlcgen.DeleteShardUpdatesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteEncryptionUpdates(w.ctx, sqlcgen.DeleteEncryptionUpdatesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeletePendingMetrics(w.ctx, sqlcgen.DeletePendingMetricsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeletePendingUpdate(w.ctx, sqlcgen.DeletePendingUpdateParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for i, g := range d.EnhancedMonitoring {
		if err := w.q.PutMonitoringGroup(w.ctx, sqlcgen.PutMonitoringGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Position: int64(i), MetricsPresent: g.ShardLevelMetrics != nil}); err != nil {
			return err
		}
		for j, m := range g.ShardLevelMetrics {
			if err := w.q.PutMonitoringMetric(w.ctx, sqlcgen.PutMonitoringMetricParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, GroupPosition: int64(i), Position: int64(j), Metric: string(m)}); err != nil {
				return err
			}
		}
	}
	for i, at := range v.ShardCountUpdates {
		if err := w.q.PutShardUpdate(w.ctx, sqlcgen.PutShardUpdateParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Position: int64(i), At: at.UTC()}); err != nil {
			return err
		}
	}
	for i, h := range v.EncryptionUpdates {
		if err := w.q.PutEncryptionUpdate(w.ctx, sqlcgen.PutEncryptionUpdateParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Position: int64(i), At: h.At.UTC(), Enabled: h.Enabled}); err != nil {
			return err
		}
	}
	if u := v.Pending; u != nil {
		if err := w.q.PutPendingUpdate(w.ctx, sqlcgen.PutPendingUpdateParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, AcceptedAt: u.AcceptedAt.UTC(), RetentionHours: int64(u.RetentionHours), Mode: string(u.Mode), MaxRecordSizeKib: int64(u.MaxRecordSizeKiB), EncryptionType: string(u.EncryptionType), KeyID: u.KeyID, MonitoringPresent: u.Monitoring != nil, WarmMibps: nullableInteger(u.WarmMiBps), PeakShardCount: int64(u.PeakShardCount)}); err != nil {
			return err
		}
		for i, m := range u.Monitoring {
			if err := w.q.PutPendingMetric(w.ctx, sqlcgen.PutPendingMetricParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Position: int64(i), Metric: string(m)}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) DeleteStream(k domain.StreamKey) error {
	consumers, err := w.Consumers(k)
	if err != nil {
		return err
	}
	for _, v := range consumers {
		if err := w.DeleteConsumer(v.Key); err != nil {
			return err
		}
	}
	if err := w.deleteResource(domain.ResourceKey{Scope: k.Scope, ARN: k.ARN()}); err != nil {
		return err
	}
	return w.q.DeleteStream(w.ctx, sqlcgen.DeleteStreamParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
