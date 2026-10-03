package athena

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/athena"
)

func registerSavedQueries(s *Service) {
	registerControl(s, "CreateNamedQuery", s.createNamedQuery)
	registerControl(s, "GetNamedQuery", s.getNamedQuery)
	registerControl(s, "DeleteNamedQuery", s.deleteNamedQuery)
	registerControl(s, "ListNamedQueries", s.listNamedQueries)
	registerControl(s, "CreatePreparedStatement", s.createPreparedStatement)
	registerControl(s, "GetPreparedStatement", s.getPreparedStatement)
	registerControl(s, "DeletePreparedStatement", s.deletePreparedStatement)
	registerControl(s, "ListPreparedStatements", s.listPreparedStatements)
	registerControl(s, "UpdatePreparedStatement", s.updatePreparedStatement)
}
func fingerprint(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func (s *Service) createNamedQuery(ctx context.Context, tx Transaction, in *api.CreateNamedQueryInput) (*api.CreateNamedQueryOutput, error) {
	group, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "CreateNamedQuery")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(value(in.QueryString)) == "" || value(in.Name) == "" || value(in.Database) == "" {
		return nil, invalidRequest("Name, Database and QueryString are required.")
	}
	canonical := *in
	canonical.ClientRequestToken = nil
	canonical.WorkGroup = new(api.WorkGroupName(group.Key.Name))
	hash, err := fingerprint(canonical)
	if err != nil {
		return nil, err
	}
	token := value(in.ClientRequestToken)
	if token != "" {
		previous, err := tx.NamedQueryByToken(scopeFor(ctx), token)
		if err == nil {
			if previous.Fingerprint != hash {
				return nil, invalidRequest("ClientRequestToken was already used with different parameters.")
			}
			return &api.CreateNamedQueryOutput{NamedQueryId: previous.Data.NamedQueryId}, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	key := resourceFor(ctx, uuid.NewString())
	v := NamedQueryRecord{Key: key, Token: token, Fingerprint: hash, Data: api.NamedQuery{NamedQueryId: new(api.NamedQueryId(key.Name)), Name: in.Name, Database: in.Database, Description: in.Description, QueryString: in.QueryString, WorkGroup: new(api.WorkGroupName(group.Key.Name))}}
	if err := tx.PutNamedQuery(v); err != nil {
		return nil, err
	}
	return &api.CreateNamedQueryOutput{NamedQueryId: v.Data.NamedQueryId}, nil
}
func (s *Service) getNamedQuery(ctx context.Context, tx Transaction, in *api.GetNamedQueryInput) (*api.GetNamedQueryOutput, error) {
	v, err := tx.NamedQuery(resourceFor(ctx, value(in.NamedQueryId)))
	if err != nil {
		return nil, err
	}
	if _, err := s.loadWorkGroup(ctx, tx, value(v.Data.WorkGroup), "GetNamedQuery"); err != nil {
		return nil, err
	}
	return &api.GetNamedQueryOutput{NamedQuery: &v.Data}, nil
}
func (s *Service) deleteNamedQuery(ctx context.Context, tx Transaction, in *api.DeleteNamedQueryInput) (*api.DeleteNamedQueryOutput, error) {
	v, err := tx.NamedQuery(resourceFor(ctx, value(in.NamedQueryId)))
	if err != nil {
		return nil, err
	}
	if _, err := s.loadWorkGroup(ctx, tx, value(v.Data.WorkGroup), "DeleteNamedQuery"); err != nil {
		return nil, err
	}
	if err := tx.DeleteNamedQuery(v.Key); err != nil {
		return nil, err
	}
	return &api.DeleteNamedQueryOutput{}, nil
}
func (s *Service) listNamedQueries(ctx context.Context, tx Transaction, in *api.ListNamedQueriesInput) (*api.ListNamedQueriesOutput, error) {
	group, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "ListNamedQueries")
	if err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.MaxResults, 50)
	if err != nil {
		return nil, err
	}
	after, err := cursor(group.Key.Scope, "named", group.Key.Name, in.NextToken)
	if err != nil {
		return nil, err
	}
	rows, err := tx.NamedQueries(ResourceQuery{Scope: group.Key.Scope, WorkGroup: group.Key.Name, After: after, Limit: limit + 1})
	if err != nil {
		return nil, err
	}
	out := &api.ListNamedQueriesOutput{NamedQueryIds: api.NamedQueryIdList{}}
	if len(rows) > limit {
		out.NextToken = nextToken(group.Key.Scope, "named", group.Key.Name, rows[limit-1].Key.Name)
		rows = rows[:limit]
	}
	for _, v := range rows {
		out.NamedQueryIds = append(out.NamedQueryIds, api.NamedQueryId(v.Key.Name))
	}
	return out, nil
}
func (s *Service) createPreparedStatement(ctx context.Context, tx Transaction, in *api.CreatePreparedStatementInput) (*api.CreatePreparedStatementOutput, error) {
	group, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "CreatePreparedStatement")
	if err != nil {
		return nil, err
	}
	key := StatementKey{WorkGroup: group.Key, Name: value(in.StatementName)}
	if strings.TrimSpace(value(in.QueryStatement)) == "" || key.Name == "" {
		return nil, invalidRequest("StatementName and QueryStatement are required.")
	}
	if _, err := tx.PreparedStatement(key); err == nil {
		return nil, invalidRequest("Prepared statement already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := s.clock.Now()
	v := PreparedStatementRecord{Key: key, Data: api.PreparedStatement{StatementName: in.StatementName, WorkGroupName: new(api.WorkGroupName(group.Key.Name)), QueryStatement: in.QueryStatement, Description: in.Description, LastModifiedTime: &now}}
	if err := tx.PutPreparedStatement(v); err != nil {
		return nil, err
	}
	return &api.CreatePreparedStatementOutput{}, nil
}
func findPrepared(r Reader, key StatementKey) (PreparedStatementRecord, error) {
	v, err := r.PreparedStatement(key)
	if errors.Is(err, ErrNotFound) {
		return v, failure("ResourceNotFoundException", "Prepared statement does not exist in the requested workgroup.")
	}
	return v, err
}
func (s *Service) getPreparedStatement(ctx context.Context, tx Transaction, in *api.GetPreparedStatementInput) (*api.GetPreparedStatementOutput, error) {
	group, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "GetPreparedStatement")
	if err != nil {
		return nil, err
	}
	v, err := findPrepared(tx, StatementKey{WorkGroup: group.Key, Name: value(in.StatementName)})
	if err != nil {
		return nil, err
	}
	return &api.GetPreparedStatementOutput{PreparedStatement: &v.Data}, nil
}
func (s *Service) updatePreparedStatement(ctx context.Context, tx Transaction, in *api.UpdatePreparedStatementInput) (*api.UpdatePreparedStatementOutput, error) {
	group, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "UpdatePreparedStatement")
	if err != nil {
		return nil, err
	}
	v, err := findPrepared(tx, StatementKey{WorkGroup: group.Key, Name: value(in.StatementName)})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(value(in.QueryStatement)) == "" {
		return nil, invalidRequest("QueryStatement is required.")
	}
	now := s.clock.Now()
	v.Data.QueryStatement = in.QueryStatement
	if in.Description != nil {
		v.Data.Description = in.Description
	}
	v.Data.LastModifiedTime = &now
	if err := tx.PutPreparedStatement(v); err != nil {
		return nil, err
	}
	return &api.UpdatePreparedStatementOutput{}, nil
}
func (s *Service) deletePreparedStatement(ctx context.Context, tx Transaction, in *api.DeletePreparedStatementInput) (*api.DeletePreparedStatementOutput, error) {
	group, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "DeletePreparedStatement")
	if err != nil {
		return nil, err
	}
	key := StatementKey{WorkGroup: group.Key, Name: value(in.StatementName)}
	if _, err := findPrepared(tx, key); err != nil {
		return nil, err
	}
	if err := tx.DeletePreparedStatement(key); err != nil {
		return nil, err
	}
	return &api.DeletePreparedStatementOutput{}, nil
}
func (s *Service) listPreparedStatements(ctx context.Context, tx Transaction, in *api.ListPreparedStatementsInput) (*api.ListPreparedStatementsOutput, error) {
	group, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "ListPreparedStatements")
	if err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.MaxResults, 50)
	if err != nil {
		return nil, err
	}
	after, err := cursor(group.Key.Scope, "prepared", group.Key.Name, in.NextToken)
	if err != nil {
		return nil, err
	}
	rows, err := tx.PreparedStatements(ResourceQuery{Scope: group.Key.Scope, WorkGroup: group.Key.Name, After: after, Limit: limit + 1})
	if err != nil {
		return nil, err
	}
	out := &api.ListPreparedStatementsOutput{PreparedStatements: api.PreparedStatementsList{}}
	if len(rows) > limit {
		out.NextToken = nextToken(group.Key.Scope, "prepared", group.Key.Name, rows[limit-1].Key.Name)
		rows = rows[:limit]
	}
	for _, v := range rows {
		out.PreparedStatements = append(out.PreparedStatements, api.PreparedStatementSummary{StatementName: v.Data.StatementName, LastModifiedTime: v.Data.LastModifiedTime})
	}
	return out, nil
}
