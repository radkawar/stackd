package glue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
)

func (s *Service) policyScope(ctx context.Context, tx Reader, action string, resource *api.GlueResourceArn) (Scope, error) {
	key := catalogKey(ctx, nil)
	if resource != nil && value(resource) != key.ARN() {
		return Scope{}, failure("InvalidInputException", "ResourceArn is reserved for internal use.")
	}
	if err := s.authorizeCatalog(ctx, tx, action, key); err != nil {
		return Scope{}, err
	}
	return key.Scope, nil
}
func (s *Service) putResourcePolicy(ctx context.Context, tx Transaction, in *api.PutResourcePolicyInput) (*api.PutResourcePolicyOutput, error) {
	scope, err := s.policyScope(ctx, tx, "PutResourcePolicy", in.ResourceArn)
	if err != nil {
		return nil, err
	}
	record, err := tx.ResourcePolicy(scope)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	condition := value(in.PolicyExistsCondition)
	if condition != "" && condition != "NONE" && condition != "MUST_EXIST" && condition != "NOT_EXIST" {
		return nil, failure("InvalidInputException", "Invalid policy existence condition.")
	}
	if condition == "MUST_EXIST" && !exists || condition == "NOT_EXIST" && exists {
		return nil, failure("ConditionCheckFailureException", "Policy existence condition was not satisfied.")
	}
	if in.PolicyHashCondition != nil && (!exists || value(in.PolicyHashCondition) != record.Hash) {
		return nil, failure("ConditionCheckFailureException", "Policy hash condition was not satisfied.")
	}
	if s.binder == nil {
		return nil, failure("InternalServiceException", "Resource policy principal binding is not configured.", 500)
	}
	document := value(in.PolicyInJson)
	if len(document) > 10240 {
		return nil, failure("InvalidInputException", "Resource policy exceeds the 10 KB limit.")
	}
	bound, err := s.binder.BindResourcePolicy(ctx, document, authorization.ResourcePolicyOptions{})
	if err != nil {
		return nil, failure("InvalidInputException", err.Error())
	}
	now := s.clock.Now().UTC()
	if !exists {
		record = ResourcePolicyRecord{Scope: scope, Created: now}
	}
	hash := sha256.Sum256([]byte(document))
	record.Policy = bound
	record.Hash = hex.EncodeToString(hash[:])
	record.Updated = now
	if err := tx.PutResourcePolicy(record); err != nil {
		return nil, err
	}
	return &api.PutResourcePolicyOutput{PolicyHash: new(api.HashString(record.Hash))}, nil
}
func (s *Service) getResourcePolicy(ctx context.Context, tx Transaction, in *api.GetResourcePolicyInput) (*api.GetResourcePolicyOutput, error) {
	scope, err := s.policyScope(ctx, tx, "GetResourcePolicy", in.ResourceArn)
	if err != nil {
		return nil, err
	}
	record, err := tx.ResourcePolicy(scope)
	if err != nil {
		return nil, err
	}
	if s.binder == nil {
		return nil, failure("InternalServiceException", "Resource policy principal binding is not configured.", 500)
	}
	document, err := s.binder.RenderResourcePolicy(ctx, record.Policy)
	if err != nil {
		return nil, err
	}
	return &api.GetResourcePolicyOutput{PolicyHash: new(api.HashString(record.Hash)), PolicyInJson: new(api.PolicyJsonString(document)), CreateTime: &record.Created, UpdateTime: &record.Updated}, nil
}
func (s *Service) deleteResourcePolicy(ctx context.Context, tx Transaction, in *api.DeleteResourcePolicyInput) (*api.DeleteResourcePolicyOutput, error) {
	scope, err := s.policyScope(ctx, tx, "DeleteResourcePolicy", in.ResourceArn)
	if err != nil {
		return nil, err
	}
	record, err := tx.ResourcePolicy(scope)
	if err != nil {
		return nil, err
	}
	if in.PolicyHashCondition != nil && value(in.PolicyHashCondition) != record.Hash {
		return nil, failure("ConditionCheckFailureException", "Policy hash condition was not satisfied.")
	}
	return &api.DeleteResourcePolicyOutput{}, tx.DeleteResourcePolicy(scope)
}
func (s *Service) importCatalogToGlue(ctx context.Context, tx Transaction, in *api.ImportCatalogToGlueInput) (*api.ImportCatalogToGlueOutput, error) {
	key := catalogKey(ctx, in.CatalogId)
	if err := s.authorizeCatalog(ctx, tx, "ImportCatalogToGlue", key); err != nil {
		return nil, err
	}
	if err := s.requireCatalog(tx, key); err != nil {
		return nil, err
	}
	// Athena and Glue already use this one catalog authority. Import marks that
	// shared catalog as migrated; it must never manufacture copied table entries.
	if _, err := tx.CatalogImport(key); err == nil {
		return &api.ImportCatalogToGlueOutput{}, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	status := api.CatalogImportStatus{ImportCompleted: new(api.Boolean(true)), ImportTime: new(s.clock.Now().UTC()), ImportedBy: new(api.NameString(awsctx.FromContext(ctx).PrincipalARN))}
	return &api.ImportCatalogToGlueOutput{}, tx.PutCatalogImport(CatalogImportRecord{Key: key, Status: status})
}
func (s *Service) getCatalogImportStatus(ctx context.Context, tx Transaction, in *api.GetCatalogImportStatusInput) (*api.GetCatalogImportStatusOutput, error) {
	key := catalogKey(ctx, in.CatalogId)
	if err := s.authorizeCatalog(ctx, tx, "GetCatalogImportStatus", key); err != nil {
		return nil, err
	}
	if err := s.requireCatalog(tx, key); err != nil {
		return nil, err
	}
	record, err := tx.CatalogImport(key)
	if errors.Is(err, ErrNotFound) {
		return &api.GetCatalogImportStatusOutput{ImportStatus: &api.CatalogImportStatus{ImportCompleted: new(api.Boolean(false))}}, nil
	}
	if err != nil {
		return nil, err
	}
	return &api.GetCatalogImportStatusOutput{ImportStatus: &record.Status}, nil
}
