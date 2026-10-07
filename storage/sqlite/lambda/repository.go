// Package lambda persists regional Lambda deployments.
package lambda

import (
	"context"
	"database/sql"
	"errors"
	"math"

	runtime "stackd/compute/lambda"
	domain "stackd/storage/lambda"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func (r reader) Function(k domain.FunctionKey) (domain.FunctionRecord, error) {
	return r.getFunction(k, false)
}
func (r reader) PendingFunction(k domain.FunctionKey) (domain.FunctionRecord, error) {
	return r.getFunction(k, true)
}
func (r reader) getFunction(k domain.FunctionKey, pending bool) (domain.FunctionRecord, error) {
	v, err := r.q.GetFunction(r.ctx, sqlcgen.GetFunctionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name, Pending: pending})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.FunctionRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	return r.function(v)
}
func (r reader) function(v sqlcgen.LambdaFunction) (domain.FunctionRecord, error) {
	variables, err := r.q.GetFunctionVariables(r.ctx, sqlcgen.GetFunctionVariablesParams{Partition: v.Partition, Account: v.Account, Region: v.Region, FunctionName: v.Name, Pending: v.Pending, Version: v.Version})
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	var tags []sqlcgen.GetFunctionTagsRow
	if v.Version == 0 {
		tags, err = r.q.GetFunctionTags(r.ctx, sqlcgen.GetFunctionTagsParams{Partition: v.Partition, Account: v.Account, Region: v.Region, FunctionName: v.Name, Pending: v.Pending})
		if err != nil {
			return domain.FunctionRecord{}, err
		}
	}
	out := domain.FunctionRecord{
		Key:     domain.FunctionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.Name},
		Version: uint64(v.Version),
		Runtime: v.Runtime, Handler: v.Handler, Role: v.Role, Description: v.Description, Architecture: v.Architecture,
		CodeSize: v.CodeSize, CodeSHA256: v.CodeSha256, Timeout: int(v.Timeout), MemoryMB: int(v.MemoryMb), EphemeralMB: int(v.EphemeralMb),
		Revision: v.Revision, DeploymentRevision: v.DeploymentRevision, Modified: v.Modified, State: v.State, StateReason: v.StateReason, StateReasonCode: v.StateReasonCode,
		UpdateStatus: v.UpdateStatus, UpdateReason: v.UpdateReason,
		DeadLetterARN:            v.DeadLetterArn,
		LogGroup:                 v.LogGroup,
		Logging:                  runtime.LoggingConfig{Format: v.LogFormat, ApplicationLevel: v.ApplicationLogLevel, SystemLevel: v.SystemLogLevel},
		SigningProfileVersionARN: v.SigningProfileVersionArn, SigningJobARN: v.SigningJobArn,
	}
	if len(variables) > 0 {
		out.Variables = make(map[string]string, len(variables))
		for _, variable := range variables {
			out.Variables[variable.Key] = variable.Value
		}
	}
	if len(tags) > 0 {
		out.Tags = make(map[string]string, len(tags))
		for _, tag := range tags {
			out.Tags[tag.Key] = tag.Value
		}
	}
	layers, err := r.q.GetFunctionLayers(r.ctx, sqlcgen.GetFunctionLayersParams{Partition: v.Partition, Account: v.Account, Region: v.Region, FunctionName: v.Name, Pending: v.Pending, Version: v.Version})
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	if len(layers) > 0 {
		out.Layers = make([]domain.LayerAttachment, len(layers))
		for i, layer := range layers {
			out.Layers[i] = domain.LayerAttachment{
				Key:        domain.LayerVersionKey{LayerKey: domain.LayerKey{Scope: domain.Scope{Partition: layer.LayerPartition, Account: layer.LayerAccount, Region: layer.LayerRegion}, Name: layer.LayerName}, Version: uint64(layer.LayerVersion)},
				CodeSHA256: layer.CodeSha256, CodeSize: layer.CodeSize,
				SigningProfileVersionARN: layer.SigningProfileVersionArn, SigningJobARN: layer.SigningJobArn,
			}
		}
	}
	out.Reference, out.CodeSourceCheckAt, err = r.functionS3Source(out.Key, v.Pending, out.Version)
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	out.Durable, err = r.functionDurableConfig(out.Key, v.Pending, out.Version)
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	out.Capacity, err = r.functionCapacityConfig(out.Key, v.Pending, out.Version)
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	out.Image, out.ImageConfig, err = r.functionImage(out.Key, v.Pending, out.Version)
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	out.VpcConfig, out.NetworkIncarnation, err = r.functionNetwork(out.Key, v.Pending, out.Version)
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	out.Owner, err = r.functionOwner(out.Key, v.Pending, out.Version)
	if err != nil {
		return domain.FunctionRecord{}, err
	}
	return out, nil
}
func (r reader) Functions(scope domain.Scope) ([]domain.FunctionRecord, error) {
	rows, err := r.q.ListFunctions(r.ctx, sqlcgen.ListFunctionsParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return r.functions(rows)
}
func (r reader) AllFunctions() ([]domain.FunctionRecord, error) {
	return r.allFunctions(false)
}
func (r reader) PendingFunctions() ([]domain.FunctionRecord, error) {
	return r.allFunctions(true)
}
func (r reader) allFunctions(pending bool) ([]domain.FunctionRecord, error) {
	rows, err := r.q.ListAllFunctions(r.ctx, pending)
	if err != nil {
		return nil, err
	}
	return r.functions(rows)
}
func (r reader) functions(rows []sqlcgen.LambdaFunction) ([]domain.FunctionRecord, error) {
	out := make([]domain.FunctionRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.function(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutFunction(v domain.FunctionRecord) error {
	v.Version = 0
	return w.putFunction(v, false)
}
func (w writer) PutPendingFunction(v domain.FunctionRecord) error {
	v.Version = 0
	return w.putFunction(v, true)
}
func (w writer) putFunction(v domain.FunctionRecord, pending bool) error {
	k := v.Key
	for _, layer := range v.Layers {
		if layer.Key.Version == 0 || layer.Key.Version > math.MaxInt64 {
			return errors.New("invalid attached Lambda layer version")
		}
	}
	changed, err := w.q.PutFunction(w.ctx, sqlcgen.PutFunctionParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name, Pending: pending, Version: int64(v.Version),
		Runtime: v.Runtime, Handler: v.Handler, Role: v.Role, Description: v.Description, Architecture: v.Architecture,
		CodeSize: v.CodeSize, CodeSha256: v.CodeSHA256, Timeout: int64(v.Timeout), MemoryMb: int64(v.MemoryMB), EphemeralMb: int64(v.EphemeralMB),
		Revision: v.Revision, DeploymentRevision: v.DeploymentRevision, Modified: v.Modified, State: v.State, StateReason: v.StateReason, StateReasonCode: v.StateReasonCode,
		UpdateStatus: v.UpdateStatus, UpdateReason: v.UpdateReason,
		DeadLetterArn: v.DeadLetterARN,
		LogGroup:      v.LogGroup,
		LogFormat:     v.Logging.Format, ApplicationLogLevel: v.Logging.ApplicationLevel, SystemLogLevel: v.Logging.SystemLevel,
		SigningProfileVersionArn: v.SigningProfileVersionARN, SigningJobArn: v.SigningJobARN,
	})
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("published Lambda version already exists")
	}
	if err := w.q.DeleteFunctionVariables(w.ctx, sqlcgen.DeleteFunctionVariablesParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version)}); err != nil {
		return err
	}
	for key, value := range v.Variables {
		if err := w.q.PutFunctionVariable(w.ctx, sqlcgen.PutFunctionVariableParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version), Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteFunctionLayers(w.ctx, sqlcgen.DeleteFunctionLayersParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version)}); err != nil {
		return err
	}
	for position, layer := range v.Layers {
		if err := w.q.PutFunctionLayer(w.ctx, sqlcgen.PutFunctionLayerParams{
			Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version), Position: int64(position),
			LayerPartition: layer.Key.Partition, LayerAccount: layer.Key.Account, LayerRegion: layer.Key.Region, LayerName: layer.Key.Name, LayerVersion: int64(layer.Key.Version),
			CodeSha256: layer.CodeSHA256, CodeSize: layer.CodeSize,
			SigningProfileVersionArn: layer.SigningProfileVersionARN, SigningJobArn: layer.SigningJobARN,
		}); err != nil {
			return err
		}
	}
	if err := w.putFunctionS3Source(v, pending); err != nil {
		return err
	}
	if err := w.putFunctionDurableConfig(v, pending); err != nil {
		return err
	}
	if err := w.putFunctionCapacityConfig(v, pending); err != nil {
		return err
	}
	if err := w.putFunctionImage(v, pending); err != nil {
		return err
	}
	if err := w.putFunctionNetwork(v, pending); err != nil {
		return err
	}
	if err := w.putFunctionOwner(v, pending); err != nil {
		return err
	}
	if v.Version != 0 {
		return nil
	}
	if err := w.q.DeleteFunctionTags(w.ctx, sqlcgen.DeleteFunctionTagsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutFunctionTag(w.ctx, sqlcgen.PutFunctionTagParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) ReplaceCapacityPublishedFunction(v domain.FunctionRecord) error {
	if v.Version != domain.LatestPublishedVersion || v.Capacity == nil {
		return errors.New("managed publication requires the independent $LATEST.PUBLISHED snapshot")
	}
	return w.putFunction(v, false)
}

func (w writer) DeleteFunction(k domain.FunctionKey) error {
	if err := w.q.DetachFunctionInvocationSettings(w.ctx, sqlcgen.DetachFunctionInvocationSettingsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name}); err != nil {
		return err
	}
	if err := w.DeleteFunctionCodeSigningConfig(k); err != nil {
		return err
	}
	return w.q.DeleteFunction(w.ctx, sqlcgen.DeleteFunctionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
}
func (w writer) DeletePendingFunction(k domain.FunctionKey) error {
	return w.q.DeletePendingFunction(w.ctx, sqlcgen.DeletePendingFunctionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
}
