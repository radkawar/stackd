package iam

import (
	"database/sql"
	"errors"
	"strings"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) Role(scope domain.Scope, key string) (domain.Role, error) {
	var result domain.Role
	row, err := r.q.GetRole(r.ctx, sqlcgen.GetRoleParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.Role
	record.CloudFormationOwner = row.CfnOwner
	record.Path = row.Path
	record.RoleName = row.RoleName
	record.RoleId = row.RoleID
	record.Arn = row.Arn
	record.AssumeRolePolicyDocument = row.AssumeRolePolicyDocument
	record.Description = row.Description
	record.ServiceLinkedService = row.ServiceLinkedService
	record.IdentityCenterInstanceARN = row.IdentityCenterInstanceArn
	record.IdentityCenterPermissionSetARN = row.IdentityCenterPermissionSetArn
	record.LastUsed.Region = row.LastUsedRegion
	record.CreateDate = row.CreateDate
	record.LastUsed.Date = row.LastUsedDate
	record.MaxSessionDuration = int(row.MaxSessionDuration)
	{
		child, err := r.readRolePermissionsBoundary(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.PermissionsBoundary = child
	}
	{
		child, err := r.readRoleTags(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Tags = child
	}
	{
		child, err := r.readRoleTrustPrincipalIDs(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.TrustPrincipalIDs = child
	}
	{
		child, err := r.readRoleSourceRoleTemplate(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.SourceRoleTemplate = child
	}
	{
		child, err := r.readRoleInline(row.Partition, row.Account, row.ResourceKey, &record.InlineOwners)
		if err != nil {
			return result, err
		}
		record.Inline = child
	}
	{
		child, err := r.readRoleAttached(row.Partition, row.Account, row.ResourceKey, &record.AttachedOwners)
		if err != nil {
			return result, err
		}
		record.Attached = child
	}
	return record, nil
}

func (r reader) Roles(scope domain.Scope) ([]domain.Role, error) {
	rows, err := r.q.ListRoleKeys(r.ctx, sqlcgen.ListRoleKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.Role
	for _, row := range rows {
		record, err := r.Role(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutRole(scope domain.Scope, record domain.Role) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteRole(w.ctx, sqlcgen.DeleteRoleParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.RoleName)}); err != nil {
		return err
	}
	if err := w.q.InsertRole(w.ctx, sqlcgen.InsertRoleParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.RoleName), Path: record.Path, RoleName: record.RoleName, RoleID: record.RoleId, Arn: record.Arn, AssumeRolePolicyDocument: record.AssumeRolePolicyDocument, Description: record.Description, ServiceLinkedService: record.ServiceLinkedService, LastUsedRegion: record.LastUsed.Region, CreateDate: record.CreateDate, LastUsedDate: record.LastUsed.Date, MaxSessionDuration: int64(record.MaxSessionDuration), IdentityCenterInstanceArn: record.IdentityCenterInstanceARN, IdentityCenterPermissionSetArn: record.IdentityCenterPermissionSetARN, CfnOwner: record.CloudFormationOwner}); err != nil {
		return err
	}
	if err := w.writeRolePermissionsBoundary(scope.Partition, scope.AccountID, strings.ToLower(record.RoleName), record.PermissionsBoundary); err != nil {
		return err
	}
	if err := w.writeRoleTags(scope.Partition, scope.AccountID, strings.ToLower(record.RoleName), record.Tags); err != nil {
		return err
	}
	if err := w.writeRoleTrustPrincipalIDs(scope.Partition, scope.AccountID, strings.ToLower(record.RoleName), record.TrustPrincipalIDs); err != nil {
		return err
	}
	if err := w.writeRoleSourceRoleTemplate(scope.Partition, scope.AccountID, strings.ToLower(record.RoleName), record.SourceRoleTemplate); err != nil {
		return err
	}
	if err := w.writeRoleInline(scope.Partition, scope.AccountID, strings.ToLower(record.RoleName), record.Inline, record.InlineOwners); err != nil {
		return err
	}
	if err := w.writeRoleAttached(scope.Partition, scope.AccountID, strings.ToLower(record.RoleName), record.Attached, record.AttachedOwners); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteRole(scope domain.Scope, key string) error {
	count, err := w.q.DeleteRole(w.ctx, sqlcgen.DeleteRoleParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}

func (r reader) readRolePermissionsBoundary(partition string, account string, resourceKey string) (*domain.Boundary, error) {
	var result *domain.Boundary
	row, err := r.q.GetRolePermissionsBoundary(r.ctx, sqlcgen.GetRolePermissionsBoundaryParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.Boundary{}
	record.PermissionsBoundaryType = row.PermissionsBoundaryType
	record.PermissionsBoundaryArn = row.PermissionsBoundaryArn
	return record, nil
}

func (r reader) readRoleTags(partition string, account string, resourceKey string) ([]domain.Tag, error) {
	var result []domain.Tag
	rows, err := r.q.ListRoleTags(r.ctx, sqlcgen.ListRoleTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.Tag
		record.Key = row.Key
		record.Value = row.Value
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readRoleTrustPrincipalIDs(partition string, account string, resourceKey string) (map[string]string, error) {
	var result map[string]string
	rows, err := r.q.ListRoleTrustPrincipalIDs(r.ctx, sqlcgen.ListRoleTrustPrincipalIDsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	result = make(map[string]string, len(rows))
	for _, row := range rows {
		record := row.Value
		result[row.Entry1] = record
	}
	return result, nil
}

func (r reader) readRoleSourceRoleTemplate(partition string, account string, resourceKey string) (*domain.RoleTemplateSource, error) {
	var result *domain.RoleTemplateSource
	row, err := r.q.GetRoleSourceRoleTemplate(r.ctx, sqlcgen.GetRoleSourceRoleTemplateParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.RoleTemplateSource{}
	record.ARN = row.Arn
	record.MinorVersion = int32(row.MinorVersion)
	{
		child, err := r.readRoleSourceRoleTemplateParameters(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Parameters = child
	}
	return record, nil
}

func (r reader) readRoleSourceRoleTemplateParameters(partition string, account string, resourceKey string) (map[string][]string, error) {
	var result map[string][]string
	rows, err := r.q.ListRoleSourceRoleTemplateParameters(r.ctx, sqlcgen.ListRoleSourceRoleTemplateParametersParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	result = make(map[string][]string, len(rows))
	for _, row := range rows {
		var record []string
		{
			child, err := r.readRoleSourceRoleTemplateParametersValues(row.Partition, row.Account, row.ResourceKey, row.Entry2)
			if err != nil {
				return result, err
			}
			record = child
		}
		result[row.Entry2] = record
	}
	return result, nil
}

func (r reader) readRoleSourceRoleTemplateParametersValues(partition string, account string, resourceKey string, entry2 string) ([]string, error) {
	var result []string
	rows, err := r.q.ListRoleSourceRoleTemplateParametersValues(r.ctx, sqlcgen.ListRoleSourceRoleTemplateParametersValuesParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry2: entry2})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		record := row.Value
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readRoleInline(partition string, account string, resourceKey string, owners *map[string]string) (map[string]string, error) {
	rows, err := r.q.ListRoleInline(r.ctx, sqlcgen.ListRoleInlineParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(rows))
	for _, row := range rows {
		result[row.Entry1] = row.Value
		if row.CfnOwner != "" {
			if *owners == nil {
				*owners = make(map[string]string)
			}
			(*owners)[row.Entry1] = row.CfnOwner
		}
	}
	return result, nil
}

func (r reader) readRoleAttached(partition string, account string, resourceKey string, owners *map[string]string) (map[string]struct{}, error) {
	rows, err := r.q.ListRoleAttached(r.ctx, sqlcgen.ListRoleAttachedParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return nil, err
	}
	result := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		result[row.Entry1] = struct{}{}
		if row.CfnOwner != "" {
			if *owners == nil {
				*owners = make(map[string]string)
			}
			(*owners)[row.Entry1] = row.CfnOwner
		}
	}
	return result, nil
}

func (w writer) writeRolePermissionsBoundary(partition string, account string, resourceKey string, record *domain.Boundary) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertRolePermissionsBoundary(w.ctx, sqlcgen.InsertRolePermissionsBoundaryParams{Partition: partition, Account: account, ResourceKey: resourceKey, PermissionsBoundaryType: record.PermissionsBoundaryType, PermissionsBoundaryArn: record.PermissionsBoundaryArn}); err != nil {
		return err
	}
	return nil
}

func (w writer) writeRoleTags(partition string, account string, resourceKey string, value []domain.Tag) error {
	for position1, record := range value {
		if err := w.q.InsertRoleTags(w.ctx, sqlcgen.InsertRoleTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Key: record.Key, Value: record.Value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeRoleTrustPrincipalIDs(partition string, account string, resourceKey string, value map[string]string) error {
	for entry1, record := range value {
		if err := w.q.InsertRoleTrustPrincipalIDs(w.ctx, sqlcgen.InsertRoleTrustPrincipalIDsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry1: entry1, Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeRoleSourceRoleTemplate(partition string, account string, resourceKey string, record *domain.RoleTemplateSource) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertRoleSourceRoleTemplate(w.ctx, sqlcgen.InsertRoleSourceRoleTemplateParams{Partition: partition, Account: account, ResourceKey: resourceKey, Arn: record.ARN, MinorVersion: int64(record.MinorVersion)}); err != nil {
		return err
	}
	if err := w.writeRoleSourceRoleTemplateParameters(partition, account, resourceKey, record.Parameters); err != nil {
		return err
	}
	return nil
}

func (w writer) writeRoleSourceRoleTemplateParameters(partition string, account string, resourceKey string, value map[string][]string) error {
	for entry2, record := range value {
		if err := w.q.InsertRoleSourceRoleTemplateParameters(w.ctx, sqlcgen.InsertRoleSourceRoleTemplateParametersParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry2: entry2}); err != nil {
			return err
		}
		if err := w.writeRoleSourceRoleTemplateParametersValues(partition, account, resourceKey, entry2, record); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeRoleSourceRoleTemplateParametersValues(partition string, account string, resourceKey string, entry2 string, value []string) error {
	for position3, record := range value {
		if err := w.q.InsertRoleSourceRoleTemplateParametersValues(w.ctx, sqlcgen.InsertRoleSourceRoleTemplateParametersValuesParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry2: entry2, Position3: int64(position3), Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeRoleInline(partition string, account string, resourceKey string, value map[string]string, owners map[string]string) error {
	for entry1, record := range value {
		if err := w.q.InsertRoleInline(w.ctx, sqlcgen.InsertRoleInlineParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry1: entry1, Value: record, CfnOwner: owners[entry1]}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeRoleAttached(partition string, account string, resourceKey string, value map[string]struct{}, owners map[string]string) error {
	for entry1 := range value {
		if err := w.q.InsertRoleAttached(w.ctx, sqlcgen.InsertRoleAttachedParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry1: entry1, CfnOwner: owners[entry1]}); err != nil {
			return err
		}
	}
	return nil
}
