package kinesis

import (
	"database/sql"
	"errors"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/kinesis"
	domain "stackd/storage/kinesis"
	"stackd/storage/sqlite/kinesis/internal/sqlcgen"
	"time"
)

func (r reader) Tags(k domain.ResourceKey) (domain.TagRecord, error) {
	out := domain.TagRecord{Key: k}
	row, err := r.q.GetTagSet(r.ctx, sqlcgen.GetTagSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN})
	if err != nil {
		return out, missing(err)
	}
	if row.TagsPresent {
		rows, err := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN})
		if err != nil {
			return out, err
		}
		out.Tags = make(api.TagList, len(rows))
		for i, v := range rows {
			out.Tags[i] = api.Tag{Key: stringPointer[api.TagKey](v.Key), Value: stringPointer[api.TagValue](v.Value)}
		}
	}
	return out, nil
}
func (w writer) PutTags(v domain.TagRecord) error {
	k := v.Key
	if err := w.q.PutTagSet(w.ctx, sqlcgen.PutTagSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN, TagsPresent: v.Tags != nil}); err != nil {
		return err
	}
	if err := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN}); err != nil {
		return err
	}
	for i, t := range v.Tags {
		if err := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN, Position: int64(i), Key: nullableString(t.Key), Value: nullableString(t.Value)}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) deleteResource(k domain.ResourceKey) error {
	if err := w.q.DeleteTagSet(w.ctx, sqlcgen.DeleteTagSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN}); err != nil {
		return err
	}
	return w.DeletePolicy(k)
}
func (r reader) Policy(k domain.ResourceKey) (domain.PolicyRecord, error) {
	row, err := r.q.GetPolicy(r.ctx, sqlcgen.GetPolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN})
	if err != nil {
		return domain.PolicyRecord{}, missing(err)
	}
	out := domain.PolicyRecord{Key: k, Policy: authorization.BoundPolicy{Document: row.Document, TrustPolicy: row.TrustPolicy}, Effective: authorization.BoundPolicy{Document: row.EffectiveDocument, TrustPolicy: row.EffectiveTrustPolicy}, PublishAt: row.PublishAt.UTC()}
	if row.PrincipalsPresent {
		out.Policy.PrincipalIDs = map[string]string{}
	}
	if row.EffectivePrincipalsPresent {
		out.Effective.PrincipalIDs = map[string]string{}
	}
	bindings, err := r.q.ListPolicyPrincipals(r.ctx, sqlcgen.ListPolicyPrincipalsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN})
	if err != nil {
		return out, err
	}
	for _, p := range bindings {
		if p.Effective {
			out.Effective.PrincipalIDs[p.Principal] = p.PrincipalID
		} else {
			out.Policy.PrincipalIDs[p.Principal] = p.PrincipalID
		}
	}
	return out, nil
}
func (w writer) PutPolicy(v domain.PolicyRecord) error {
	k := v.Key
	if err := w.q.PutPolicy(w.ctx, sqlcgen.PutPolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN, Document: v.Policy.Document, TrustPolicy: v.Policy.TrustPolicy, PrincipalsPresent: v.Policy.PrincipalIDs != nil, EffectiveDocument: v.Effective.Document, EffectiveTrustPolicy: v.Effective.TrustPolicy, EffectivePrincipalsPresent: v.Effective.PrincipalIDs != nil, PublishAt: v.PublishAt.UTC()}); err != nil {
		return err
	}
	if err := w.q.DeletePolicyPrincipals(w.ctx, sqlcgen.DeletePolicyPrincipalsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN}); err != nil {
		return err
	}
	for principal, id := range v.Policy.PrincipalIDs {
		if err := w.q.PutPolicyPrincipal(w.ctx, sqlcgen.PutPolicyPrincipalParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN, Effective: false, Principal: principal, PrincipalID: id}); err != nil {
			return err
		}
	}
	for principal, id := range v.Effective.PrincipalIDs {
		if err := w.q.PutPolicyPrincipal(w.ctx, sqlcgen.PutPolicyPrincipalParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN, Effective: true, Principal: principal, PrincipalID: id}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeletePolicy(k domain.ResourceKey) error {
	return w.q.DeletePolicy(w.ctx, sqlcgen.DeletePolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Arn: k.ARN})
}
func (r reader) Account(k domain.Scope) (domain.AccountRecord, error) {
	row, err := r.q.GetAccount(r.ctx, sqlcgen.GetAccountParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return domain.AccountRecord{}, missing(err)
	}
	return domain.AccountRecord{Scope: k, Commitment: api.MinimumThroughputBillingCommitmentOutput{EarliestAllowedEndAt: timePointer(row.EarliestAllowedEndAt), EndedAt: timePointer(row.EndedAt), StartedAt: timePointer(row.StartedAt), Status: stringPointer[api.MinimumThroughputBillingCommitmentOutputStatus](row.Status)}}, nil
}
func (w writer) PutAccount(v domain.AccountRecord) error {
	k, d := v.Scope, &v.Commitment
	return w.q.PutAccount(w.ctx, sqlcgen.PutAccountParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, EarliestAllowedEndAt: nullableTime(d.EarliestAllowedEndAt), EndedAt: nullableTime(d.EndedAt), StartedAt: nullableTime(d.StartedAt), Status: nullableString(d.Status)})
}
func (r reader) ModeSwitches(k domain.StreamKey) ([]time.Time, error) {
	set, err := r.q.GetModeSwitchSet(r.ctx, sqlcgen.GetModeSwitchSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !set.TimesPresent {
		return nil, nil
	}
	rows, err := r.q.ListModeSwitches(r.ctx, sqlcgen.ListModeSwitchesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]time.Time, len(rows))
	for i, v := range rows {
		out[i] = v.At.UTC()
	}
	return out, nil
}
func (w writer) PutModeSwitches(k domain.StreamKey, times []time.Time) error {
	if err := w.q.PutModeSwitchSet(w.ctx, sqlcgen.PutModeSwitchSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, TimesPresent: times != nil}); err != nil {
		return err
	}
	if err := w.q.DeleteModeSwitches(w.ctx, sqlcgen.DeleteModeSwitchesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for i, at := range times {
		if err := w.q.PutModeSwitch(w.ctx, sqlcgen.PutModeSwitchParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Position: int64(i), At: at.UTC()}); err != nil {
			return err
		}
	}
	return nil
}
