package lambda

import (
	"database/sql"
	"errors"
	"math"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) LayerVersion(k domain.LayerVersionKey) (domain.LayerVersionRecord, error) {
	if k.Version == 0 || k.Version > math.MaxInt64 {
		return domain.LayerVersionRecord{}, domain.ErrNotFound
	}
	v, err := r.q.GetLayerVersion(r.ctx, sqlcgen.GetLayerVersionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version)})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.LayerVersionRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.LayerVersionRecord{}, err
	}
	return r.layerVersion(v)
}

func (r reader) OwnedLayerVersion(k domain.LayerKey, owner domain.LayerVersionOwner) (domain.LayerVersionRecord, error) {
	if owner.StackID == "" || owner.LogicalID == "" || owner.Token == "" {
		return domain.LayerVersionRecord{}, domain.ErrNotFound
	}
	v, err := r.q.GetOwnedLayerVersion(r.ctx, sqlcgen.GetOwnedLayerVersionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, OwnerStackID: owner.StackID, OwnerLogicalID: owner.LogicalID, OwnerToken: owner.Token})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.LayerVersionRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.LayerVersionRecord{}, err
	}
	return r.layerVersion(v)
}

func (r reader) LayerVersions(k domain.LayerKey) ([]domain.LayerVersionRecord, error) {
	rows, err := r.q.ListLayerVersions(r.ctx, sqlcgen.ListLayerVersionsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name})
	if err != nil {
		return nil, err
	}
	return r.layerVersions(rows)
}

func (r reader) Layers(scope domain.Scope) ([]domain.LayerVersionRecord, error) {
	rows, err := r.q.ListLayers(r.ctx, sqlcgen.ListLayersParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return r.layerVersions(rows)
}

func (r reader) layerVersions(rows []sqlcgen.LambdaLayerVersion) ([]domain.LayerVersionRecord, error) {
	out := make([]domain.LayerVersionRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.layerVersion(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) layerVersion(v sqlcgen.LambdaLayerVersion) (domain.LayerVersionRecord, error) {
	out := domain.LayerVersionRecord{
		Key:        domain.LayerVersionKey{LayerKey: domain.LayerKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.LayerName}, Version: uint64(v.Version)},
		Owner:      domain.LayerVersionOwner{StackID: v.OwnerStackID, LogicalID: v.OwnerLogicalID, Token: v.OwnerToken},
		CodeSHA256: v.CodeSha256, CodeSize: v.CodeSize, Description: v.Description, LicenseInfo: v.LicenseInfo, Created: v.Created,
		SigningProfileVersionARN: v.SigningProfileVersionArn, SigningJobARN: v.SigningJobArn,
	}
	if v.HasReference {
		out.Reference = &domain.S3ObjectReference{Bucket: v.ReferenceBucket, Key: v.ReferenceKey, VersionID: v.ReferenceVersionID}
	}
	if v.HasCompatibleRuntimes {
		runtimes, err := r.q.GetLayerCompatibleRuntimes(r.ctx, sqlcgen.GetLayerCompatibleRuntimesParams{Partition: v.Partition, Account: v.Account, Region: v.Region, LayerName: v.LayerName, Version: v.Version})
		if err != nil {
			return domain.LayerVersionRecord{}, err
		}
		if runtimes == nil {
			runtimes = []string{}
		}
		out.CompatibleRuntimes = runtimes
	}
	if v.HasCompatibleArchitectures {
		architectures, err := r.q.GetLayerCompatibleArchitectures(r.ctx, sqlcgen.GetLayerCompatibleArchitecturesParams{Partition: v.Partition, Account: v.Account, Region: v.Region, LayerName: v.LayerName, Version: v.Version})
		if err != nil {
			return domain.LayerVersionRecord{}, err
		}
		if architectures == nil {
			architectures = []string{}
		}
		out.CompatibleArchitectures = architectures
	}
	return out, nil
}

func (w writer) AllocateLayerVersion(k domain.LayerKey) (uint64, error) {
	v, err := w.q.AllocateLayerVersion(w.ctx, sqlcgen.AllocateLayerVersionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("layer version allocation exhausted")
	}
	return uint64(v), err
}

func (w writer) PutLayerVersion(v domain.LayerVersionRecord) error {
	k := v.Key
	if k.Version == 0 || k.Version > math.MaxInt64 {
		return errors.New("invalid Lambda layer version")
	}
	if v.Owner != (domain.LayerVersionOwner{}) && (v.Owner.StackID == "" || v.Owner.LogicalID == "" || v.Owner.Token == "") {
		return errors.New("incomplete Lambda layer version owner")
	}
	params := sqlcgen.PutLayerVersionParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version),
		CodeSha256: v.CodeSHA256, CodeSize: v.CodeSize, Description: v.Description, LicenseInfo: v.LicenseInfo, Created: v.Created.UTC(),
		HasCompatibleRuntimes: v.CompatibleRuntimes != nil, HasCompatibleArchitectures: v.CompatibleArchitectures != nil,
		HasReference:             v.Reference != nil,
		SigningProfileVersionArn: v.SigningProfileVersionARN, SigningJobArn: v.SigningJobARN,
		OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token,
	}
	if v.Reference != nil {
		params.ReferenceBucket = v.Reference.Bucket
		params.ReferenceKey = v.Reference.Key
		params.ReferenceVersionID = v.Reference.VersionID
	}
	changed, err := w.q.PutLayerVersion(w.ctx, params)
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("lambda layer version already exists")
	}
	for position, runtime := range v.CompatibleRuntimes {
		if err := w.q.PutLayerCompatibleRuntime(w.ctx, sqlcgen.PutLayerCompatibleRuntimeParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version), Position: int64(position), Runtime: runtime}); err != nil {
			return err
		}
	}
	for position, architecture := range v.CompatibleArchitectures {
		if err := w.q.PutLayerCompatibleArchitecture(w.ctx, sqlcgen.PutLayerCompatibleArchitectureParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version), Position: int64(position), Architecture: architecture}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteLayerVersion(k domain.LayerVersionKey) error {
	if k.Version == 0 || k.Version > math.MaxInt64 {
		return nil
	}
	return w.q.DeleteLayerVersion(w.ctx, sqlcgen.DeleteLayerVersionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version)})
}

func (r reader) LayerPolicy(k domain.LayerVersionKey) (domain.LayerPolicy, error) {
	if k.Version == 0 || k.Version > math.MaxInt64 {
		return domain.LayerPolicy{}, domain.ErrNotFound
	}
	row, err := r.q.GetLayerPolicy(r.ctx, sqlcgen.GetLayerPolicyParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version)})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.LayerPolicy{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.LayerPolicy{}, err
	}
	principals, err := r.q.GetLayerPolicyPrincipals(r.ctx, sqlcgen.GetLayerPolicyPrincipalsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version)})
	if err != nil {
		return domain.LayerPolicy{}, err
	}
	out := domain.LayerPolicy{Key: k, Document: row.Document, Revision: row.Revision, PrincipalIDs: make(map[string]string, len(principals))}
	for _, principal := range principals {
		out.PrincipalIDs[principal.Principal] = principal.PrincipalID
	}
	return out, nil
}

func (w writer) PutLayerPolicy(v domain.LayerPolicy) error {
	k := v.Key
	if k.Version == 0 || k.Version > math.MaxInt64 {
		return errors.New("invalid Lambda layer version")
	}
	if err := w.q.PutLayerPolicy(w.ctx, sqlcgen.PutLayerPolicyParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version), Document: v.Document, Revision: v.Revision}); err != nil {
		return err
	}
	if err := w.q.DeleteLayerPolicyPrincipals(w.ctx, sqlcgen.DeleteLayerPolicyPrincipalsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version)}); err != nil {
		return err
	}
	for principal, id := range v.PrincipalIDs {
		if err := w.q.PutLayerPolicyPrincipal(w.ctx, sqlcgen.PutLayerPolicyPrincipalParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version), Principal: principal, PrincipalID: id}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteLayerPolicy(k domain.LayerVersionKey) error {
	if k.Version == 0 || k.Version > math.MaxInt64 {
		return nil
	}
	return w.q.DeleteLayerPolicy(w.ctx, sqlcgen.DeleteLayerPolicyParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version)})
}

func (r reader) LayerPermissionOwner(k domain.LayerPermissionKey) (domain.LayerPermissionOwner, error) {
	if k.Version == 0 || k.Version > math.MaxInt64 {
		return domain.LayerPermissionOwner{}, domain.ErrNotFound
	}
	row, err := r.q.GetLayerPermissionOwner(r.ctx, sqlcgen.GetLayerPermissionOwnerParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version), StatementID: k.StatementID})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.LayerPermissionOwner{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.LayerPermissionOwner{}, err
	}
	return domain.LayerPermissionOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}, nil
}

func (w writer) PutLayerPermissionOwner(k domain.LayerPermissionKey, owner domain.LayerPermissionOwner) error {
	if k.Version == 0 || k.Version > math.MaxInt64 {
		return errors.New("invalid Lambda layer version")
	}
	if k.StatementID == "" || owner.StackID == "" || owner.LogicalID == "" || owner.Token == "" {
		return errors.New("incomplete Lambda layer permission owner")
	}
	return w.q.PutLayerPermissionOwner(w.ctx, sqlcgen.PutLayerPermissionOwnerParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version), StatementID: k.StatementID, OwnerStackID: owner.StackID, OwnerLogicalID: owner.LogicalID, OwnerToken: owner.Token})
}

func (w writer) DeleteLayerPermissionOwner(k domain.LayerPermissionKey) error {
	if k.Version == 0 || k.Version > math.MaxInt64 {
		return nil
	}
	return w.q.DeleteLayerPermissionOwner(w.ctx, sqlcgen.DeleteLayerPermissionOwnerParams{Partition: k.Partition, Account: k.Account, Region: k.Region, LayerName: k.Name, Version: int64(k.Version), StatementID: k.StatementID})
}
