package codebuild

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	api "stackd/internal/awsapi/codebuild"
	"time"
)

type pageToken struct {
	Scope  Scope
	Query  string
	Offset int
}

func page[T any](scope Scope, query, token string, rows []T, limit int) ([]T, *api.String, error) {
	offset := 0
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			return nil, nil, failure("InvalidInputException", "Invalid nextToken.")
		}
		var p pageToken
		if json.Unmarshal(raw, &p) != nil || p.Scope != scope || p.Query != query || p.Offset < 0 || p.Offset > len(rows) {
			return nil, nil, failure("InvalidInputException", "Invalid nextToken.")
		}
		offset = p.Offset
	}
	end := min(offset+limit, len(rows))
	var next *api.String
	if end < len(rows) {
		raw, _ := json.Marshal(pageToken{scope, query, end})
		next = new(api.String(base64.RawURLEncoding.EncodeToString(raw)))
	}
	return rows[offset:end], next, nil
}
func timestamp(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
func (s *Service) listProjects(ctx context.Context, tx Transaction, in *api.ListProjectsInput) (*api.ListProjectsOutput, error) {
	if err := s.authorize(ctx, "ListProjects", "*", nil); err != nil {
		return nil, err
	}
	scope := scopeFor(ctx)
	rows, err := tx.Projects(scope)
	if err != nil {
		return nil, err
	}
	order := value(in.SortOrder)
	sortBy := value(in.SortBy)
	slices.SortFunc(rows, func(a, b ProjectRecord) int {
		n := 0
		switch sortBy {
		case "CREATED_TIME":
			n = timestamp(a.Data.Created).Compare(timestamp(b.Data.Created))
		case "LAST_MODIFIED_TIME":
			n = timestamp(a.Data.LastModified).Compare(timestamp(b.Data.LastModified))
		default:
			n = cmp.Compare(a.Key.Name, b.Key.Name)
		}
		n = cmp.Or(n, cmp.Compare(a.Key.Name, b.Key.Name))
		if order == "DESCENDING" {
			return -n
		}
		return n
	})
	rows, next, err := page(scope, "projects/"+sortBy+"/"+order, value(in.NextToken), rows, 100)
	if err != nil {
		return nil, err
	}
	out := &api.ListProjectsOutput{NextToken: next}
	for _, r := range rows {
		out.Projects = append(out.Projects, api.NonEmptyString(r.Key.Name))
	}
	return out, nil
}
func (s *Service) buildList(ctx context.Context, tx Transaction, project, order, token string) (api.BuildIds, *api.String, error) {
	scope := scopeFor(ctx)
	action, resource := "ListBuilds", "*"
	if project != "" {
		key, err := sharedProjectKey(scope, project)
		if err != nil {
			return nil, nil, err
		}
		r, err := tx.Project(key)
		if err != nil {
			return nil, nil, err
		}
		action = "ListBuildsForProject"
		if err = s.authorizeProject(ctx, action, r); err != nil {
			return nil, nil, err
		}
		project = key.Name
		scope = key.Scope
	} else if err := s.authorize(ctx, action, resource, nil); err != nil {
		return nil, nil, err
	}
	rows, err := tx.Builds(scope)
	if err != nil {
		return nil, nil, err
	}
	rows = slices.DeleteFunc(rows, func(r BuildRecord) bool {
		return r.DeleteRequested || project != "" && value(r.Data.ProjectName) != project
	})
	slices.SortFunc(rows, func(a, b BuildRecord) int {
		n := cmp.Or(timestamp(a.Data.StartTime).Compare(timestamp(b.Data.StartTime)), cmp.Compare(a.Key.ID, b.Key.ID))
		if order != "ASCENDING" {
			return -n
		}
		return n
	})
	rows, next, err := page(scopeFor(ctx), "builds/"+scope.AccountID+"/"+project+"/"+order, token, rows, 100)
	if err != nil {
		return nil, nil, err
	}
	ids := make(api.BuildIds, 0, len(rows))
	for _, r := range rows {
		id := r.Key.ID
		if scope.AccountID != scopeFor(ctx).AccountID {
			id = r.Key.ARN()
		}
		ids = append(ids, api.NonEmptyString(id))
	}
	return ids, next, nil
}
func (s *Service) listBuilds(ctx context.Context, tx Transaction, in *api.ListBuildsInput) (*api.ListBuildsOutput, error) {
	ids, next, err := s.buildList(ctx, tx, "", value(in.SortOrder), value(in.NextToken))
	return &api.ListBuildsOutput{Ids: ids, NextToken: next}, err
}
func (s *Service) listBuildsForProject(ctx context.Context, tx Transaction, in *api.ListBuildsForProjectInput) (*api.ListBuildsForProjectOutput, error) {
	ids, next, err := s.buildList(ctx, tx, value(in.ProjectName), value(in.SortOrder), value(in.NextToken))
	return &api.ListBuildsForProjectOutput{Ids: ids, NextToken: next}, err
}
func (s *Service) listFleets(ctx context.Context, tx Transaction, in *api.ListFleetsInput) (*api.ListFleetsOutput, error) {
	if err := s.authorize(ctx, "ListFleets", "*", nil); err != nil {
		return nil, err
	}
	scope := scopeFor(ctx)
	rows, err := tx.Fleets(scope)
	if err != nil {
		return nil, err
	}
	order, sortBy := value(in.SortOrder), value(in.SortBy)
	slices.SortFunc(rows, func(a, b FleetRecord) int {
		n := 0
		switch sortBy {
		case "CREATED_TIME":
			n = timestamp(a.Data.Created).Compare(timestamp(b.Data.Created))
		case "LAST_MODIFIED_TIME":
			n = timestamp(a.Data.LastModified).Compare(timestamp(b.Data.LastModified))
		default:
			n = cmp.Compare(a.Key.Name, b.Key.Name)
		}
		n = cmp.Or(n, cmp.Compare(a.Key.Name, b.Key.Name))
		if order == "DESCENDING" {
			return -n
		}
		return n
	})
	limit := 100
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	if limit < 1 || limit > 100 {
		return nil, failure("InvalidInputException", "maxResults must be between 1 and 100.")
	}
	rows, next, err := page(scope, "fleets/"+sortBy+"/"+order, value(in.NextToken), rows, limit)
	if err != nil {
		return nil, err
	}
	out := &api.ListFleetsOutput{NextToken: next}
	for _, r := range rows {
		out.Fleets = append(out.Fleets, api.NonEmptyString(value(r.Data.Arn)))
	}
	return out, nil
}
