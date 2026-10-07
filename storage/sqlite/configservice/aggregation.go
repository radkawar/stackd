package configservice

import (
	domain "stackd/storage/configservice"
	"stackd/storage/sqlite/configservice/internal/sqlcgen"
)

func (r reader) loadAggregator(v sqlcgen.ConfigAggregator) (domain.Aggregator, error) {
	out := domain.Aggregator{CFNOwnership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}, Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name, ARN: v.ARN, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
	sources, err := r.q.ListAggregatorSources(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	for _, s := range sources {
		out.Sources = append(out.Sources, domain.AggregationSource{AccountID: s.SourceAccountID, Region: s.SourceRegion})
	}
	return out, nil
}

func (r reader) Aggregators(s domain.Scope) ([]domain.Aggregator, error) {
	rows, err := r.q.ListAggregators(r.ctx, sqlcgen.ListAggregatorsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Aggregator, 0, len(rows))
	for _, v := range rows {
		record, err := r.loadAggregator(v)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) PutAggregator(v domain.Aggregator) error {
	id, err := w.q.PutAggregator(w.ctx, sqlcgen.PutAggregatorParams{CfnOwner: v.CFNOwnership.Owner, CfnToken: v.CFNOwnership.Token, Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, Name: v.Name, ARN: v.ARN, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt})
	if err != nil {
		return err
	}
	if err = w.q.ClearAggregatorSources(w.ctx, id); err != nil {
		return err
	}
	for ordinal, s := range v.Sources {
		if err = w.q.InsertAggregatorSource(w.ctx, sqlcgen.InsertAggregatorSourceParams{ParentID: id, Ordinal: int64(ordinal), SourceAccountID: s.AccountID, SourceRegion: s.Region}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteAggregator(s domain.Scope, name string) error {
	return w.q.DeleteAggregator(w.ctx, sqlcgen.DeleteAggregatorParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Name: name})
}

func (r reader) loadAggregationAuthorization(v sqlcgen.ConfigAggregationAuthorization) (domain.AggregationAuthorization, error) {
	out := domain.AggregationAuthorization{CFNOwnership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}, Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, AccountID: v.AuthorizedAccountID, Region: v.AuthorizedRegion, ARN: v.ARN, CreatedAt: v.CreatedAt}
	return out, nil
}

func (r reader) AggregationAuthorizations(s domain.Scope) ([]domain.AggregationAuthorization, error) {
	rows, err := r.q.ListAggregationAuthorizations(r.ctx, sqlcgen.ListAggregationAuthorizationsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.AggregationAuthorization, 0, len(rows))
	for _, v := range rows {
		record, err := r.loadAggregationAuthorization(v)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) PutAggregationAuthorization(v domain.AggregationAuthorization) error {
	return w.q.PutAggregationAuthorization(w.ctx, sqlcgen.PutAggregationAuthorizationParams{CfnOwner: v.CFNOwnership.Owner, CfnToken: v.CFNOwnership.Token, Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, AuthorizedAccountID: v.AccountID, AuthorizedRegion: v.Region, ARN: v.ARN, CreatedAt: v.CreatedAt})
}

func (w writer) DeleteAggregationAuthorization(s domain.Scope, account, region string) error {
	return w.q.DeleteAggregationAuthorization(w.ctx, sqlcgen.DeleteAggregationAuthorizationParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, AuthorizedAccountID: account, AuthorizedRegion: region})
}
