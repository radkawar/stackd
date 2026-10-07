package wafv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"stackd/storage/sqlite"
	"stackd/storage/sqlite/wafv2/internal/sqlcgen"
	domain "stackd/storage/wafv2"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, f func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, t *sql.Tx) error { return f(reader{ctx, sqlcgen.New(t)}) })
}
func (r *Repository) Update(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
}
func (r *Repository) Attempt(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func missing(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return e
}

type tagRow struct{ key, value string }

func tagMap(rows []tagRow) map[string]string {
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.key] = row.value
	}
	return out
}

func (r reader) webACL(v sqlcgen.Wafv2WebAcl) (domain.WebACL, error) {
	out := domain.WebACL{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name, ID: v.ID, ARN: v.Arn, Description: v.Description, LockToken: v.LockToken, Capacity: v.Capacity, Created: v.Created, Updated: v.Updated, Owner: domain.ResourceOwner{StackID: v.OwnerStackID, LogicalID: v.OwnerLogicalID, Token: v.OwnerToken}}
	if err := json.Unmarshal(v.Definition, &out.Definition); err != nil {
		return out, err
	}
	rows, err := r.q.ListWebACLTags(r.ctx, sqlcgen.ListWebACLTagsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.Arn})
	if err != nil {
		return out, err
	}
	tags := make([]tagRow, 0, len(rows))
	for _, row := range rows {
		tags = append(tags, tagRow{row.TagKey, row.TagValue})
	}
	out.Tags = tagMap(tags)
	return out, nil
}
func (r reader) WebACL(sc domain.Scope, arn string) (domain.WebACL, error) {
	v, err := r.q.GetWebACL(r.ctx, sqlcgen.GetWebACLParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: arn})
	if err != nil {
		return domain.WebACL{}, missing(err)
	}
	return r.webACL(v)
}
func (r reader) WebACLs(sc domain.Scope) ([]domain.WebACL, error) {
	rows, err := r.q.ListWebACLs(r.ctx, sqlcgen.ListWebACLsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.WebACL, 0, len(rows))
	for _, row := range rows {
		v, err := r.webACL(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutWebACL(v domain.WebACL) error {
	definition, err := json.Marshal(v.Definition)
	if err != nil {
		return err
	}
	if err := w.q.PutWebACL(w.ctx, sqlcgen.PutWebACLParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.ARN, Name: v.Name, ID: v.ID, Description: v.Description, LockToken: v.LockToken, Definition: definition, Capacity: v.Capacity, Created: v.Created, Updated: v.Updated, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token}); err != nil {
		return err
	}
	if err := w.q.DeleteWebACLTags(w.ctx, sqlcgen.DeleteWebACLTagsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.ARN}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutWebACLTag(w.ctx, sqlcgen.PutWebACLTagParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteWebACL(sc domain.Scope, arn string) error {
	return w.q.DeleteWebACL(w.ctx, sqlcgen.DeleteWebACLParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: arn})
}

func (r reader) ipSet(v sqlcgen.Wafv2IpSet) (domain.IPSet, error) {
	out := domain.IPSet{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name, ID: v.ID, ARN: v.Arn, Description: v.Description, LockToken: v.LockToken, IPAddressVersion: v.IpAddressVersion, Created: v.Created, Updated: v.Updated, Owner: domain.ResourceOwner{StackID: v.OwnerStackID, LogicalID: v.OwnerLogicalID, Token: v.OwnerToken}}
	if err := json.Unmarshal(v.Addresses, &out.Addresses); err != nil {
		return out, err
	}
	rows, err := r.q.ListIPSetTags(r.ctx, sqlcgen.ListIPSetTagsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.Arn})
	if err != nil {
		return out, err
	}
	tags := make([]tagRow, 0, len(rows))
	for _, row := range rows {
		tags = append(tags, tagRow{row.TagKey, row.TagValue})
	}
	out.Tags = tagMap(tags)
	return out, nil
}
func (r reader) IPSet(sc domain.Scope, arn string) (domain.IPSet, error) {
	v, err := r.q.GetIPSet(r.ctx, sqlcgen.GetIPSetParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: arn})
	if err != nil {
		return domain.IPSet{}, missing(err)
	}
	return r.ipSet(v)
}
func (r reader) IPSets(sc domain.Scope) ([]domain.IPSet, error) {
	rows, err := r.q.ListIPSets(r.ctx, sqlcgen.ListIPSetsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.IPSet, 0, len(rows))
	for _, row := range rows {
		v, err := r.ipSet(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutIPSet(v domain.IPSet) error {
	addresses, err := json.Marshal(v.Addresses)
	if err != nil {
		return err
	}
	if err := w.q.PutIPSet(w.ctx, sqlcgen.PutIPSetParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.ARN, Name: v.Name, ID: v.ID, Description: v.Description, LockToken: v.LockToken, IpAddressVersion: v.IPAddressVersion, Addresses: addresses, Created: v.Created, Updated: v.Updated, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token}); err != nil {
		return err
	}
	if err := w.q.DeleteIPSetTags(w.ctx, sqlcgen.DeleteIPSetTagsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.ARN}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutIPSetTag(w.ctx, sqlcgen.PutIPSetTagParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteIPSet(sc domain.Scope, arn string) error {
	return w.q.DeleteIPSet(w.ctx, sqlcgen.DeleteIPSetParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: arn})
}

func association(v sqlcgen.Wafv2Association) domain.Association {
	return domain.Association{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ResourceARN: v.ResourceArn, WebACLARN: v.WebAclArn, ResourceIncarnation: v.ResourceIncarnation, Owner: domain.AssociationOwner{StackID: v.OwnerStackID, LogicalID: v.OwnerLogicalID, Token: v.OwnerToken}, Created: v.Created}
}
func (r reader) Association(sc domain.Scope, resource string) (domain.Association, error) {
	v, err := r.q.GetAssociation(r.ctx, sqlcgen.GetAssociationParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ResourceArn: resource})
	if err != nil {
		return domain.Association{}, missing(err)
	}
	return association(v), nil
}
func (r reader) Associations(sc domain.Scope, webACL string) ([]domain.Association, error) {
	rows, err := r.q.ListAssociations(r.ctx, sqlcgen.ListAssociationsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, WebAclArn: webACL})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Association, 0, len(rows))
	for _, row := range rows {
		out = append(out, association(row))
	}
	return out, nil
}
func (w writer) PutAssociation(v domain.Association) error {
	return w.q.PutAssociation(w.ctx, sqlcgen.PutAssociationParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ResourceArn: v.ResourceARN, WebAclArn: v.WebACLARN, ResourceIncarnation: v.ResourceIncarnation, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token, Created: v.Created})
}
func (w writer) DeleteAssociation(sc domain.Scope, resource string) error {
	return w.q.DeleteAssociation(w.ctx, sqlcgen.DeleteAssociationParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ResourceArn: resource})
}

func (r reader) NextMetricPublication() (domain.MetricKey, error) {
	v, err := r.q.NextMetricPublication(r.ctx)
	if err != nil {
		return domain.MetricKey{}, missing(err)
	}
	return domain.MetricKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, WebACL: v.WebAcl, Rule: v.Rule, Minute: v.Minute.UTC()}, nil
}
func (r reader) MetricSamples(key domain.MetricKey) ([]domain.MetricSample, error) {
	rows, err := r.q.ListMetricSamples(r.ctx, sqlcgen.ListMetricSamplesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, WebAcl: key.WebACL, Rule: key.Rule, Minute: key.Minute})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricSample, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.MetricSample{Name: row.MetricName, Count: row.Count})
	}
	return out, nil
}
func (w writer) AddMetricSample(key domain.MetricKey, sample domain.MetricSample) error {
	return w.q.AddMetricSample(w.ctx, sqlcgen.AddMetricSampleParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, WebAcl: key.WebACL, Rule: key.Rule, Minute: key.Minute, MetricName: sample.Name, Count: sample.Count})
}
func (w writer) DeleteMetricPublication(key domain.MetricKey) error {
	return w.q.DeleteMetricPublication(w.ctx, sqlcgen.DeleteMetricPublicationParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, WebAcl: key.WebACL, Rule: key.Rule, Minute: key.Minute})
}

func (r reader) SampledRequests(sc domain.Scope, webACL, metric string, from, to time.Time, limit int) ([]domain.SampledRequest, error) {
	rows, err := r.q.ListSampledRequests(r.ctx, sqlcgen.ListSampledRequestsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, WebAclArn: webACL, MetricName: metric, StartAt: from, EndAt: to, MaxItems: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SampledRequest, 0, len(rows))
	for _, row := range rows {
		v := domain.SampledRequest{Scope: sc, WebACLARN: row.WebAclArn, MetricName: row.MetricName, At: row.At.UTC(), Sequence: row.Sequence}
		if err := json.Unmarshal(row.Sample, &v.Sample); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) SamplePopulation(sc domain.Scope, webACL, metric string, from, to time.Time) (int64, error) {
	return r.q.SumSamplePopulation(r.ctx, sqlcgen.SumSamplePopulationParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, WebAclArn: webACL, MetricName: metric, StartMinute: from.Truncate(time.Minute), EndAt: to})
}
func (r reader) SampleCount(sc domain.Scope, webACL, metric string, since time.Time) (int64, error) {
	return r.q.CountSampledRequests(r.ctx, sqlcgen.CountSampledRequestsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, WebAclArn: webACL, MetricName: metric, Since: since})
}
func (w writer) PutSampledRequest(v domain.SampledRequest) error {
	sample, err := json.Marshal(v.Sample)
	if err != nil {
		return err
	}
	return w.q.PutSampledRequest(w.ctx, sqlcgen.PutSampledRequestParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, WebAclArn: v.WebACLARN, MetricName: v.MetricName, At: v.At, Sequence: v.Sequence, Sample: sample})
}
func (w writer) AddSamplePopulation(sc domain.Scope, webACL, metric string, minute time.Time, n int64) error {
	return w.q.AddSamplePopulation(w.ctx, sqlcgen.AddSamplePopulationParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, WebAclArn: webACL, MetricName: metric, Minute: minute, Population: n})
}
func (w writer) PruneSamples(before time.Time) error {
	if err := w.q.PruneSampledRequests(w.ctx, before); err != nil {
		return err
	}
	return w.q.PruneSamplePopulation(w.ctx, before.Truncate(time.Minute))
}

var _ domain.Repository = (*Repository)(nil)
