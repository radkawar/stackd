package glue

import (
	"database/sql"
	"errors"
	api "stackd/internal/awsapi/glue"
	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
	"time"
)

func wfMissing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func wfString[T ~string](p *T) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*p), Valid: true}
}
func wfStringPtr[T ~string](v sql.NullString) *T {
	if !v.Valid {
		return nil
	}
	return new(T(v.String))
}
func wfInt[T ~int32](p *T) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*p), Valid: true}
}
func wfIntPtr[T ~int32](v sql.NullInt64) *T {
	if !v.Valid {
		return nil
	}
	return new(T(v.Int64))
}
func wfTime(p *time.Time) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: p.UnixNano(), Valid: true}
}
func wfTimePtr(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	return new(time.Unix(0, v.Int64).UTC())
}
func wfTimestamp(v int64) *api.TimestampValue { return new(api.TimestampValue(time.Unix(0, v).UTC())) }
func wfTimestampN(v *api.TimestampValue) int64 {
	if v == nil {
		return 0
	}
	return time.Time(*v).UnixNano()
}
func wfKey(partition, account, region, name string) domain.ResourceKey {
	return domain.ResourceKey{Scope: domain.Scope{Partition: partition, AccountID: account, Region: region}, Name: name}
}
func (r reader) Workflow(k domain.ResourceKey) (domain.WorkflowRecord, error) {
	row, err := r.q.WFWorkflowGet(r.ctx, sqlcgen.WFWorkflowGetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.WorkflowRecord{}, wfMissing(err)
	}
	return r.wfWorkflow(row)
}
func (r reader) wfWorkflow(row sqlcgen.GlueWorkflow) (domain.WorkflowRecord, error) {
	k := wfKey(row.Partition, row.AccountID, row.Region, row.Name)
	v := domain.WorkflowRecord{Key: k, Workflow: api.Workflow{Name: new(api.NameString(k.Name)), Description: wfStringPtr[api.GenericString](row.Description), CreatedOn: wfTimestamp(row.Created), LastModifiedOn: wfTimestamp(row.Modified), MaxConcurrentRuns: wfIntPtr[api.NullableInteger](row.MaxConcurrent), DefaultRunProperties: api.WorkflowRunProperties{}}, Tags: map[string]string{}}
	tags, err := r.q.WFWorkflowTagList(r.ctx, sqlcgen.WFWorkflowTagListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return v, err
	}
	for _, t := range tags {
		v.Tags[t.ItemKey] = t.ItemValue
	}
	props, err := r.q.WFWorkflowPropertyList(r.ctx, sqlcgen.WFWorkflowPropertyListParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return v, err
	}
	for _, p := range props {
		v.Workflow.DefaultRunProperties[api.IdString(p.ItemKey)] = api.GenericString(p.ItemValue)
	}
	return v, nil
}
func (r reader) Workflows(s domain.Scope) ([]domain.WorkflowRecord, error) {
	rows, err := r.q.WFWorkflowList(r.ctx, sqlcgen.WFWorkflowListParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.WorkflowRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.wfWorkflow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutWorkflow(v domain.WorkflowRecord) error {
	k := v.Key
	if err := w.q.WFWorkflowPut(w.ctx, sqlcgen.WFWorkflowPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Description: wfString(v.Workflow.Description), Created: wfTimestampN(v.Workflow.CreatedOn), Modified: wfTimestampN(v.Workflow.LastModifiedOn), MaxConcurrent: wfInt(v.Workflow.MaxConcurrentRuns)}); err != nil {
		return err
	}
	if err := w.q.WFWorkflowTagDelete(w.ctx, sqlcgen.WFWorkflowTagDeleteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for key, val := range v.Tags {
		if err := w.q.WFWorkflowTagPut(w.ctx, sqlcgen.WFWorkflowTagPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ItemKey: key, ItemValue: val}); err != nil {
			return err
		}
	}
	if err := w.q.WFWorkflowPropertyDelete(w.ctx, sqlcgen.WFWorkflowPropertyDeleteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for key, val := range v.Workflow.DefaultRunProperties {
		if err := w.q.WFWorkflowPropertyPut(w.ctx, sqlcgen.WFWorkflowPropertyPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ItemKey: string(key), ItemValue: string(val)}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteWorkflow(k domain.ResourceKey) error {
	return w.q.WFWorkflowDelete(w.ctx, sqlcgen.WFWorkflowDeleteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
func (r reader) SecurityConfiguration(k domain.ResourceKey) (domain.SecurityConfigurationRecord, error) {
	row, err := r.q.WFSecurityConfigurationGet(r.ctx, sqlcgen.WFSecurityConfigurationGetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.SecurityConfigurationRecord{}, wfMissing(err)
	}
	return wfSecurity(row), nil
}
func wfSecurity(row sqlcgen.GlueSecurityConfiguration) domain.SecurityConfigurationRecord {
	c := api.EncryptionConfiguration{}
	if row.S3Mode.Valid {
		c.S3Encryption = api.S3EncryptionList{{S3EncryptionMode: wfStringPtr[api.S3EncryptionMode](row.S3Mode), KmsKeyArn: wfStringPtr[api.KmsKeyArn](row.S3Key)}}
	}
	if row.LogsMode.Valid {
		c.CloudWatchEncryption = &api.CloudWatchEncryption{CloudWatchEncryptionMode: wfStringPtr[api.CloudWatchEncryptionMode](row.LogsMode), KmsKeyArn: wfStringPtr[api.KmsKeyArn](row.LogsKey)}
	}
	if row.BookmarksMode.Valid {
		c.JobBookmarksEncryption = &api.JobBookmarksEncryption{JobBookmarksEncryptionMode: wfStringPtr[api.JobBookmarksEncryptionMode](row.BookmarksMode), KmsKeyArn: wfStringPtr[api.KmsKeyArn](row.BookmarksKey)}
	}
	return domain.SecurityConfigurationRecord{Key: wfKey(row.Partition, row.AccountID, row.Region, row.Name), Configuration: api.SecurityConfiguration{Name: new(api.NameString(row.Name)), CreatedTimeStamp: wfTimestamp(row.Created), EncryptionConfiguration: &c}}
}
func (r reader) SecurityConfigurations(s domain.Scope) ([]domain.SecurityConfigurationRecord, error) {
	rows, err := r.q.WFSecurityConfigurationList(r.ctx, sqlcgen.WFSecurityConfigurationListParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SecurityConfigurationRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, wfSecurity(row))
	}
	return out, nil
}
func (w writer) PutSecurityConfiguration(v domain.SecurityConfigurationRecord) error {
	k := v.Key
	p := sqlcgen.WFSecurityConfigurationPutParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Created: wfTimestampN(v.Configuration.CreatedTimeStamp)}
	if c := v.Configuration.EncryptionConfiguration; c != nil {
		if len(c.S3Encryption) > 0 {
			p.S3Mode = wfString(c.S3Encryption[0].S3EncryptionMode)
			p.S3Key = wfString(c.S3Encryption[0].KmsKeyArn)
		}
		if c.CloudWatchEncryption != nil {
			p.LogsMode = wfString(c.CloudWatchEncryption.CloudWatchEncryptionMode)
			p.LogsKey = wfString(c.CloudWatchEncryption.KmsKeyArn)
		}
		if c.JobBookmarksEncryption != nil {
			p.BookmarksMode = wfString(c.JobBookmarksEncryption.JobBookmarksEncryptionMode)
			p.BookmarksKey = wfString(c.JobBookmarksEncryption.KmsKeyArn)
		}
	}
	return w.q.WFSecurityConfigurationPut(w.ctx, p)
}
func (w writer) DeleteSecurityConfiguration(k domain.ResourceKey) error {
	return w.q.WFSecurityConfigurationDelete(w.ctx, sqlcgen.WFSecurityConfigurationDeleteParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
