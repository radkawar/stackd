package xray

import (
	"database/sql"
	"errors"
	"time"

	api "stackd/internal/awsapi/xray"
	"stackd/storage/sqlite/xray/internal/sqlcgen"
	domain "stackd/storage/xray"
)

func samplingRuleRecord(row sqlcgen.XraySamplingRule) domain.SamplingRuleRecord {
	v := domain.SamplingRuleRecord{
		Key:      domain.SamplingRuleKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
		Priority: int32(row.Priority), FixedRate: row.FixedRate, ReservoirSize: int32(row.ReservoirSize),
		Host: row.Host, HTTPMethod: row.HttpMethod, ResourceARN: row.ResourceArn,
		ServiceName: row.ServiceName, ServiceType: row.ServiceType, URLPath: row.UrlPath,
		Attributes: map[string]string{}, Tags: map[string]string{}, Created: row.Created, Modified: row.Modified,
		CFNOwner: row.CfnOwner,
	}
	if row.BoostMaxRate.Valid {
		v.RateBoost = &api.SamplingRateBoost{MaxRate: new(api.MaxRate(row.BoostMaxRate.Float64)), CooldownWindowMinutes: new(api.CooldownWindowMinutes(row.BoostCooldownMinutes.Int64))}
	}
	return v
}

func (r reader) SamplingRule(k domain.SamplingRuleKey) (domain.SamplingRuleRecord, error) {
	row, err := r.q.GetSamplingRule(r.ctx, sqlcgen.GetSamplingRuleParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.SamplingRuleRecord{}, missing(err)
	}
	v := samplingRuleRecord(row)
	attributes, err := r.q.ListSamplingAttributes(r.ctx, sqlcgen.ListSamplingAttributesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name})
	if err != nil {
		return v, err
	}
	for _, item := range attributes {
		v.Attributes[item.Key] = item.Value
	}
	tags, err := r.q.ListSamplingTags(r.ctx, sqlcgen.ListSamplingTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name})
	if err != nil {
		return v, err
	}
	for _, item := range tags {
		v.Tags[item.Key] = item.Value
	}
	return v, nil
}

func (r reader) SamplingRules(scope domain.Scope) ([]domain.SamplingRuleRecord, error) {
	rows, err := r.q.ListSamplingRules(r.ctx, sqlcgen.ListSamplingRulesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	result := make([]domain.SamplingRuleRecord, len(rows))
	positions := make(map[string]int, len(rows))
	for i, row := range rows {
		result[i] = samplingRuleRecord(row)
		positions[row.Name] = i
	}
	attributes, err := r.q.ListScopeSamplingAttributes(r.ctx, sqlcgen.ListScopeSamplingAttributesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	for _, item := range attributes {
		result[positions[item.RuleName]].Attributes[item.Key] = item.Value
	}
	tags, err := r.q.ListScopeSamplingTags(r.ctx, sqlcgen.ListScopeSamplingTagsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	for _, item := range tags {
		result[positions[item.RuleName]].Tags[item.Key] = item.Value
	}
	return result, nil
}

func (w writer) PutSamplingRule(v domain.SamplingRuleRecord) error {
	k := v.Key
	p := sqlcgen.PutSamplingRuleParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		Priority: int64(v.Priority), FixedRate: v.FixedRate, ReservoirSize: int64(v.ReservoirSize), Host: v.Host,
		HttpMethod: v.HTTPMethod, ResourceArn: v.ResourceARN, ServiceName: v.ServiceName, ServiceType: v.ServiceType,
		UrlPath: v.URLPath, Created: v.Created, Modified: v.Modified, CfnOwner: v.CFNOwner}
	if v.RateBoost != nil {
		p.BoostMaxRate = sql.NullFloat64{Float64: float64(*v.RateBoost.MaxRate), Valid: true}
		p.BoostCooldownMinutes = sql.NullInt64{Int64: int64(*v.RateBoost.CooldownWindowMinutes), Valid: true}
	}
	if err := w.q.PutSamplingRule(w.ctx, p); err != nil {
		return err
	}
	if err := w.q.DeleteSamplingAttributes(w.ctx, sqlcgen.DeleteSamplingAttributesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name}); err != nil {
		return err
	}
	for key, value := range v.Attributes {
		if err := w.q.PutSamplingAttribute(w.ctx, sqlcgen.PutSamplingAttributeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteSamplingTags(w.ctx, sqlcgen.DeleteSamplingTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutSamplingTag(w.ctx, sqlcgen.PutSamplingTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteSamplingRule(k domain.SamplingRuleKey) error {
	if err := w.q.DeleteSamplingRule(w.ctx, sqlcgen.DeleteSamplingRuleParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteSamplingClients(w.ctx, sqlcgen.DeleteSamplingClientsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteSamplingStatistics(w.ctx, sqlcgen.DeleteSamplingStatisticsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteSamplingBoostStatistics(w.ctx, sqlcgen.DeleteSamplingBoostStatisticsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name}); err != nil {
		return err
	}
	return w.q.DeleteSamplingBoost(w.ctx, sqlcgen.DeleteSamplingBoostParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name})
}

func (r reader) SamplingClients(k domain.SamplingRuleKey) ([]domain.SamplingClientRecord, error) {
	rows, err := r.q.ListSamplingClients(r.ctx, sqlcgen.ListSamplingClientsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name})
	if err != nil {
		return nil, err
	}
	result := make([]domain.SamplingClientRecord, len(rows))
	for i, row := range rows {
		result[i] = domain.SamplingClientRecord{Key: domain.SamplingClientKey{Rule: k, ID: row.ClientID}, FirstSeen: row.FirstSeen, LastSeen: row.LastSeen, Quota: int32(row.Quota), QuotaExpires: row.QuotaExpires}
	}
	return result, nil
}

func (w writer) PutSamplingClient(v domain.SamplingClientRecord) error {
	k := v.Key.Rule
	return w.q.PutSamplingClient(w.ctx, sqlcgen.PutSamplingClientParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name, ClientID: v.Key.ID, FirstSeen: v.FirstSeen, LastSeen: v.LastSeen, Quota: int64(v.Quota), QuotaExpires: v.QuotaExpires})
}

func (r reader) SamplingStatistics(k domain.SamplingRuleKey) ([]domain.SamplingStatisticRecord, error) {
	rows, err := r.q.ListSamplingStatistics(r.ctx, sqlcgen.ListSamplingStatisticsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name})
	if err != nil {
		return nil, err
	}
	result := make([]domain.SamplingStatisticRecord, len(rows))
	for i, row := range rows {
		result[i] = domain.SamplingStatisticRecord{Key: domain.SamplingStatisticKey{Rule: k, ClientID: row.ClientID, Window: row.Window}, Timestamp: row.Timestamp, Received: row.Received, RequestCount: row.RequestCount, SampledCount: row.SampledCount, BorrowCount: row.BorrowCount}
	}
	return result, nil
}

func (w writer) PutSamplingStatistic(v domain.SamplingStatisticRecord) error {
	k := v.Key.Rule
	return w.q.PutSamplingStatistic(w.ctx, sqlcgen.PutSamplingStatisticParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name, ClientID: v.Key.ClientID, Window: v.Key.Window, Timestamp: v.Timestamp, Received: v.Received, RequestCount: v.RequestCount, SampledCount: v.SampledCount, BorrowCount: v.BorrowCount})
}

func (r reader) SamplingBoostStatistics(k domain.SamplingRuleKey) ([]domain.SamplingBoostStatisticRecord, error) {
	rows, err := r.q.ListSamplingBoostStatistics(r.ctx, sqlcgen.ListSamplingBoostStatisticsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name})
	if err != nil {
		return nil, err
	}
	result := make([]domain.SamplingBoostStatisticRecord, len(rows))
	for i, row := range rows {
		result[i] = domain.SamplingBoostStatisticRecord{Key: domain.SamplingBoostStatisticKey{Rule: k, ServiceName: row.ServiceName, Window: row.Window}, Timestamp: row.Timestamp, Received: row.Received, TotalCount: row.TotalCount, AnomalyCount: row.AnomalyCount, SampledAnomalyCount: row.SampledAnomalyCount}
	}
	return result, nil
}

func (w writer) PutSamplingBoostStatistic(v domain.SamplingBoostStatisticRecord) error {
	k := v.Key.Rule
	return w.q.PutSamplingBoostStatistic(w.ctx, sqlcgen.PutSamplingBoostStatisticParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name, ServiceName: v.Key.ServiceName, Window: v.Key.Window, Timestamp: v.Timestamp, Received: v.Received, TotalCount: v.TotalCount, AnomalyCount: v.AnomalyCount, SampledAnomalyCount: v.SampledAnomalyCount})
}

func (r reader) SamplingBoost(k domain.SamplingRuleKey) (domain.SamplingBoostRecord, error) {
	row, err := r.q.GetSamplingBoost(r.ctx, sqlcgen.GetSamplingBoostParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name})
	if err != nil {
		return domain.SamplingBoostRecord{}, missing(err)
	}
	return domain.SamplingBoostRecord{Key: k, Rate: row.Rate, Expires: row.Expires, Triggered: row.Triggered}, nil
}

func (w writer) PutSamplingBoost(v domain.SamplingBoostRecord) error {
	k := v.Key
	return w.q.PutSamplingBoost(w.ctx, sqlcgen.PutSamplingBoostParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, RuleName: k.Name, Rate: v.Rate, Expires: v.Expires, Triggered: v.Triggered})
}

func (r reader) SamplingModified(scope domain.Scope) (time.Time, error) {
	when, err := r.q.GetSamplingModified(r.ctx, sqlcgen.GetSamplingModifiedParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if errors.Is(err, sql.ErrNoRows) {
		return time.Unix(0, 0).UTC(), nil
	}
	return when, err
}

func (w writer) SetSamplingModified(scope domain.Scope, when time.Time) error {
	return w.q.SetSamplingModified(w.ctx, sqlcgen.SetSamplingModifiedParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Modified: when})
}

func (r reader) EarliestSamplingReceipt() (time.Time, bool, error) {
	when, err := r.q.EarliestSamplingReceipt(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	return when, err == nil, err
}

func (w writer) DeleteExpiredSamplingState(cutoff time.Time) error {
	if err := w.q.DeleteExpiredSamplingClients(w.ctx, cutoff); err != nil {
		return err
	}
	if err := w.q.DeleteExpiredSamplingStatistics(w.ctx, cutoff); err != nil {
		return err
	}
	return w.q.DeleteExpiredSamplingBoostStatistics(w.ctx, cutoff)
}
