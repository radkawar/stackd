package rds

import (
	"context"
	"slices"
	"stackd/internal/awsapi"
	"stackd/internal/awswire"
)

// DocumentDB supplies the other authoritative owner of the shared RDS Query
// namespace. Lists are projections, not retained copies of DocumentDB state.
type DocumentDB interface {
	ExecuteRDS(context.Context, awsapi.DecodedRequest) (any, bool, *awswire.Error)
	CheckCreate(context.Context, any) error
	Databases(context.Context) ([]Database, error)
	Snapshots(context.Context) ([]Snapshot, error)
	CloudFormationRequestedPort(context.Context, string, string) (int32, bool, error)
}

func (s *Service) queryDatabases(ctx context.Context, tx Reader) ([]Database, error) {
	out, e := tx.Databases(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	if s.documents != nil {
		documents, e := s.documents.Databases(ctx)
		if e != nil {
			return nil, e
		}
		out = append(out, documents...)
		slices.SortFunc(out, func(a, b Database) int { return compareKey(a.Key, b.Key) })
	}
	return out, nil
}
func (s *Service) querySnapshots(ctx context.Context, tx Reader) ([]Snapshot, error) {
	out, e := tx.Snapshots(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	if s.documents != nil {
		documents, e := s.documents.Snapshots(ctx)
		if e != nil {
			return nil, e
		}
		out = append(out, documents...)
		slices.SortFunc(out, func(a, b Snapshot) int { return compareKey(a.Key, b.Key) })
	}
	return out, nil
}
