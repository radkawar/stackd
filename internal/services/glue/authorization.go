package glue

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"stackd/internal/authorization"
)

func (s *Service) authorize(ctx context.Context, r Reader, action string, scope Scope, arn string, tags map[string]string) error {
	if tags == nil {
		var err error
		tags, err = catalogAuthorizationTags(r, scope, arn)
		if err != nil {
			return err
		}
	}
	return s.authorizeWithConditions(ctx, r, action, scope, arn, tags, nil)
}
func (s *Service) authorizeWithConditions(ctx context.Context, r Reader, action string, scope Scope, arn string, tags map[string]string, extra map[string][]string) error {
	if arn == "" {
		arn = "*"
	}
	conditions := make(map[string][]string, len(tags)*2)
	for key, v := range tags {
		conditions["aws:ResourceTag/"+key] = []string{v}
		conditions["glue:ResourceTag/"+key] = []string{v}
	}
	maps.Copy(conditions, extra)
	now := s.clock.Now()
	// Statistics APIs authorize the underlying metadata operation, per Glue's API AuthorizedActions.
	action = strings.TrimPrefix(action, "glue:")
	switch action {
	case "GetColumnStatisticsForPartition":
		action = "GetPartition"
	case "UpdateColumnStatisticsForPartition", "DeleteColumnStatisticsForPartition":
		action = "UpdatePartition"
	case "GetColumnStatisticsForTable":
		action = "GetTable"
	case "UpdateColumnStatisticsForTable", "DeleteColumnStatisticsForTable":
		action = "UpdateTable"
	}
	request := authorization.Request{Action: "glue:" + action, ResourceARN: arn, ResourceAccountID: scope.AccountID, Context: conditions, EvaluationTime: &now}
	p, err := r.ResourcePolicy(scope)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil && p.Policy.Document != "" {
		request.ResourcePolicies = []authorization.BoundPolicy{p.Policy}
	}
	if rejected := s.authorizer.Authorize(ctx, request); rejected != nil {
		return wireError(rejected)
	}
	return nil
}
func requestTagConditions(tags map[string]string) map[string][]string {
	out := make(map[string][]string, len(tags)+1)
	keys := make([]string, 0, len(tags))
	for key, v := range tags {
		out["aws:RequestTag/"+key] = []string{v}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if len(keys) > 0 {
		out["aws:TagKeys"] = keys
	}
	return out
}
func (s *Service) authorizeCreate(ctx context.Context, r Reader, action string, scope Scope, arn string, tags map[string]string) error {
	conditions := requestTagConditions(tags)
	if err := s.authorizeWithConditions(ctx, r, action, scope, arn, nil, conditions); err != nil {
		return err
	}
	if len(tags) > 0 {
		return s.authorizeWithConditions(ctx, r, "TagResource", scope, arn, nil, conditions)
	}
	return nil
}
func (s *Service) authorizeCatalog(ctx context.Context, r Reader, action string, key CatalogKey, resources ...string) error {
	return s.authorizeCatalogWithConditions(ctx, r, action, key, nil, resources...)
}
func (s *Service) authorizeCatalogWithConditions(ctx context.Context, r Reader, action string, key CatalogKey, conditions map[string][]string, resources ...string) error {
	check := func(arn string) error {
		tags, err := catalogAuthorizationTags(r, key.Scope, arn)
		if err != nil {
			return err
		}
		return s.authorizeWithConditions(ctx, r, action, key.Scope, arn, tags, conditions)
	}
	ancestor := key
	ancestor.CatalogID = key.AccountID
	if err := check(ancestor.ARN()); err != nil {
		return err
	}
	if key.CatalogID != key.AccountID {
		for _, name := range strings.Split(strings.TrimPrefix(key.CatalogID, key.AccountID+":"), ":") {
			ancestor.CatalogID += ":" + name
			if err := check(ancestor.ARN()); err != nil {
				return err
			}
		}
	}
	for _, arn := range resources {
		if err := check(arn); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) authorizeCatalogCreate(ctx context.Context, r Reader, action string, key CatalogKey, arn string, tags map[string]string) error {
	conditions := requestTagConditions(tags)
	if err := s.authorizeCatalogWithConditions(ctx, r, action, key, conditions); err != nil {
		return err
	}
	if arn != key.ARN() {
		if err := s.authorizeWithConditions(ctx, r, action, key.Scope, arn, nil, conditions); err != nil {
			return err
		}
	}
	if len(tags) > 0 {
		return s.authorizeWithConditions(ctx, r, "TagResource", key.Scope, arn, nil, conditions)
	}
	return nil
}
func (s *Service) authorizeDatabase(ctx context.Context, r Reader, action string, key DatabaseKey) error {
	return s.authorizeCatalog(ctx, r, action, key.CatalogKey, key.ARN())
}
func (s *Service) authorizeTable(ctx context.Context, r Reader, action string, key TableKey) error {
	return s.authorizeCatalog(ctx, r, action, key.CatalogKey, key.DatabaseKey.ARN(), key.ARN())
}
func (s *Service) passRole(ctx context.Context, roleARN, sourceARN string) error {
	now := s.clock.Now()
	scope := scopeFor(ctx)
	role, ok := strings.CutPrefix(roleARN, "arn:"+scope.Partition+":iam::"+scope.AccountID+":role/")
	if !ok {
		return failure("AccessDeniedException", "The passed role must belong to the request account and partition.")
	}
	if role == "" || strings.HasSuffix(role, "/") {
		return failure("InvalidInputException", "An IAM role ARN is required.")
	}
	conditions := map[string][]string{"iam:PassedToService": {"glue.amazonaws.com"}, "iam:AssociatedResourceArn": {sourceARN}}
	if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: roleARN, ResourceAccountID: scope.AccountID, Context: conditions, EvaluationTime: &now}); denied != nil {
		return wireError(denied)
	}
	return nil
}
func catalogAuthorizationTags(r Reader, scope Scope, arn string) (map[string]string, error) {
	prefix := "arn:" + scope.Partition + ":glue:" + scope.Region + ":" + scope.AccountID + ":"
	resource, ok := strings.CutPrefix(arn, prefix)
	if !ok {
		return nil, nil
	}
	catalog := CatalogKey{Scope: scope, CatalogID: scope.AccountID}
	if path, ok := strings.CutPrefix(resource, "catalog/"); ok {
		catalog.CatalogID += ":" + strings.ReplaceAll(path, "/", ":")
		row, err := r.Catalog(catalog)
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return row.Tags, err
	}
	if path, ok := strings.CutPrefix(resource, "database/"); ok {
		name := path
		if split := strings.LastIndexByte(path, '/'); split >= 0 {
			catalog.CatalogID += ":" + strings.ReplaceAll(path[:split], "/", ":")
			name = path[split+1:]
		}
		row, err := r.Database(DatabaseKey{CatalogKey: catalog, Name: name})
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return row.Tags, err
	}
	return nil, nil
}
