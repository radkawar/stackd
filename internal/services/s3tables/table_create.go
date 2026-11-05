package s3tables

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awswire"
)

// PreparedTableCreate keeps an allocated table and typed schema private until
// admission. Physical metadata preparation occurs outside resource transactions.
type PreparedTableCreate struct {
	mu        sync.Mutex
	owner     *Service
	candidate Table
	binding   [sha256.Size]byte
	columns   []Column
	key       string
	discarded bool
}

func createTableBinding(in *api.CreateTableInput) ([sha256.Size]byte, error) {
	data, err := json.Marshal(in)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// PrepareTableCreate authorizes and materializes initial metadata without
// retaining a resource transaction. The returned candidate is not yet visible.
func (s *Service) PrepareTableCreate(ctx context.Context, in *api.CreateTableInput) (*PreparedTableCreate, *awswire.Error) {
	candidate := s.newTable(ctx, in)
	if err := s.repository.View(ctx, func(r Reader) error { return s.admitCreate(r.Context(), r, in, candidate) }); err != nil {
		return nil, wireError(err)
	}
	binding, err := createTableBinding(in)
	if err != nil {
		return nil, wireError(err)
	}
	prepared := &PreparedTableCreate{owner: s, candidate: candidate, binding: binding}
	if in.Metadata == nil {
		return prepared, nil
	}
	metadata, err := s.initialMetadata(in, candidate)
	if err != nil {
		return nil, wireError(err)
	}
	prepared.columns, err = metadataColumns(metadata)
	if err != nil {
		return nil, wireError(err)
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return nil, wireError(err)
	}
	if s.objects == nil {
		return nil, failure("InternalServerErrorException", "Table warehouse storage is unavailable", 503)
	}
	prepared.key = "metadata/00000-" + uuid.NewString() + ".metadata.json"
	prepared.candidate.MetadataLocation = candidate.Warehouse + "/" + prepared.key
	if err = s.objects.Write(ctx, candidate.Warehouse, prepared.key, data, s.clock.Now().UTC()); err != nil {
		return nil, wireError(err)
	}
	return prepared, nil
}

// PublishTableCreate admits the exact prepared request and publishes its schema,
// metadata pointer, version token and journal together. It performs no object IO.
func (s *Service) PublishTableCreate(ctx context.Context, in *api.CreateTableInput, prepared *PreparedTableCreate) (*api.CreateTableOutput, *awswire.Error) {
	if prepared != nil {
		prepared.mu.Lock()
		defer prepared.mu.Unlock()
	}
	return command(s, ctx, "CreateTable", in, func(ctx context.Context, tx Transaction, in *api.CreateTableInput) (*api.CreateTableOutput, error) {
		if prepared == nil || prepared.owner != s || prepared.discarded || prepared.candidate.Scope != scopeFor(ctx) {
			return nil, invalid("Prepared metadata does not match this table creation")
		}
		binding, err := createTableBinding(in)
		if err != nil {
			return nil, err
		}
		if binding != prepared.binding {
			return nil, invalid("Prepared metadata does not match this table creation")
		}
		candidate := prepared.candidate
		if err = s.admitCreate(ctx, tx, in, candidate); err != nil {
			return nil, err
		}
		if err = tx.PutTable(candidate); err != nil {
			return nil, err
		}
		if err = tx.PutTableColumns(candidate.Scope, candidate.ARN, prepared.columns); err != nil {
			return nil, err
		}
		out := &api.CreateTableOutput{}
		text(&out.TableARN, candidate.ARN)
		text(&out.VersionToken, candidate.VersionToken)
		return out, nil
	})
}

// DiscardTableCreate removes only unadmitted candidate bytes. Invoke it outside
// resource transactions after a failed publication or an outer rollback.
func (s *Service) DiscardTableCreate(ctx context.Context, prepared *PreparedTableCreate) error {
	if prepared == nil || prepared.owner != s {
		return nil
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.discarded {
		return nil
	}
	ctx, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	err := s.repository.View(ctx, func(r Reader) error {
		_, err := r.Warehouse(prepared.candidate.Scope, prepared.candidate.Warehouse)
		return err
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	if prepared.key != "" {
		if err = s.objects.Delete(ctx, prepared.candidate.Warehouse, prepared.key); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	prepared.discarded = true
	return nil
}

// CreateTable keeps external metadata IO outside the resource transaction, then
// atomically publishes the prepared typed schema and catalog authority.
func (s *Service) CreateTable(ctx context.Context, in *api.CreateTableInput) (*api.CreateTableOutput, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	prepared, rejected := s.PrepareTableCreate(ctx, in)
	if rejected != nil {
		return s.rejectCreate(ctx, in, rejected)
	}
	out, rejected := s.PublishTableCreate(ctx, in, prepared)
	if rejected != nil {
		if err = s.DiscardTableCreate(ctx, prepared); err != nil {
			return nil, wireError(err)
		}
	}
	return out, rejected
}
