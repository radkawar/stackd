package lambda

import (
	"database/sql"
	"errors"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) CodeSigningConfig(k domain.CodeSigningConfigKey) (domain.CodeSigningConfigRecord, error) {
	row, err := r.q.GetCodeSigningConfig(r.ctx, sqlcgen.GetCodeSigningConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ID: k.ID})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CodeSigningConfigRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.CodeSigningConfigRecord{}, err
	}
	return r.codeSigningConfig(row)
}

func (r reader) codeSigningConfig(row sqlcgen.LambdaCodeSigningConfig) (domain.CodeSigningConfigRecord, error) {
	v := domain.CodeSigningConfigRecord{Key: domain.CodeSigningConfigKey{Scope: domain.Scope{Partition: row.Partition, Account: row.Account, Region: row.Region}, ID: row.ID}, Description: row.Description, Policy: row.Policy, Modified: row.Modified, Tags: map[string]string{}}
	v.Owner = domain.AdditionalOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}
	var err error
	v.Publishers, err = r.q.GetCodeSigningPublishers(r.ctx, sqlcgen.GetCodeSigningPublishersParams{Partition: row.Partition, Account: row.Account, Region: row.Region, ConfigID: row.ID})
	if err != nil {
		return v, err
	}
	tags, err := r.q.GetCodeSigningTags(r.ctx, sqlcgen.GetCodeSigningTagsParams{Partition: row.Partition, Account: row.Account, Region: row.Region, ConfigID: row.ID})
	if err != nil {
		return v, err
	}
	for _, tag := range tags {
		v.Tags[tag.Key] = tag.Value
	}
	return v, nil
}

func (r reader) CodeSigningConfigs(scope domain.Scope) ([]domain.CodeSigningConfigRecord, error) {
	rows, err := r.q.ListCodeSigningConfigs(r.ctx, sqlcgen.ListCodeSigningConfigsParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.CodeSigningConfigRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.codeSigningConfig(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) FunctionCodeSigningConfig(k domain.FunctionKey) (domain.CodeSigningConfigKey, error) {
	id, err := r.q.GetFunctionCodeSigningConfig(r.ctx, sqlcgen.GetFunctionCodeSigningConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CodeSigningConfigKey{}, domain.ErrNotFound
	}
	return domain.CodeSigningConfigKey{Scope: k.Scope, ID: id}, err
}

func (r reader) FunctionsByCodeSigningConfig(k domain.CodeSigningConfigKey) ([]domain.FunctionKey, error) {
	names, err := r.q.ListFunctionsByCodeSigningConfig(r.ctx, sqlcgen.ListFunctionsByCodeSigningConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ConfigID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.FunctionKey, len(names))
	for i, name := range names {
		out[i] = domain.FunctionKey{Scope: k.Scope, Name: name}
	}
	return out, nil
}

func (w writer) PutCodeSigningConfig(v domain.CodeSigningConfigRecord) error {
	k := v.Key
	if err := w.q.PutCodeSigningConfig(w.ctx, sqlcgen.PutCodeSigningConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ID: k.ID, Description: v.Description, Policy: v.Policy, Modified: v.Modified, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token}); err != nil {
		return err
	}
	if err := w.q.DeleteCodeSigningPublishers(w.ctx, sqlcgen.DeleteCodeSigningPublishersParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ConfigID: k.ID}); err != nil {
		return err
	}
	for i, arn := range v.Publishers {
		if err := w.q.PutCodeSigningPublisher(w.ctx, sqlcgen.PutCodeSigningPublisherParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ConfigID: k.ID, Position: int64(i), ProfileVersionArn: arn}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCodeSigningTags(w.ctx, sqlcgen.DeleteCodeSigningTagsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ConfigID: k.ID}); err != nil {
		return err
	}
	for key, val := range v.Tags {
		if err := w.q.PutCodeSigningTag(w.ctx, sqlcgen.PutCodeSigningTagParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ConfigID: k.ID, Key: key, Value: val}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteCodeSigningConfig(k domain.CodeSigningConfigKey) error {
	return w.q.DeleteCodeSigningConfig(w.ctx, sqlcgen.DeleteCodeSigningConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, ID: k.ID})
}

func (w writer) PutFunctionCodeSigningConfig(k domain.FunctionKey, config domain.CodeSigningConfigKey) error {
	if k.Scope != config.Scope {
		return errors.New("code signing configuration must share the function scope")
	}
	return w.q.PutFunctionCodeSigningConfig(w.ctx, sqlcgen.PutFunctionCodeSigningConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, ConfigID: config.ID})
}

func (w writer) DeleteFunctionCodeSigningConfig(k domain.FunctionKey) error {
	return w.q.DeleteFunctionCodeSigningConfig(w.ctx, sqlcgen.DeleteFunctionCodeSigningConfigParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name})
}
