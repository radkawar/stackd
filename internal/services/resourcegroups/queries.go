package resourcegroups

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/resourcegroups"
)

type tagFilter struct {
	Key    string
	Values []string
}
type resourceQuery struct {
	ResourceTypeFilters []string
	TagFilters          []tagFilter
	StackIdentifier     string
}

func parseQuery(in *api.ResourceQuery) (resourceQuery, error) {
	var q resourceQuery
	if in == nil || in.Query == nil || in.Type == nil {
		return q, failure("BadRequestException", "ResourceQuery requires Type and Query.")
	}
	if *in.Type != api.QueryTypeTAG_FILTERS_1_0 && *in.Type != api.QueryTypeCLOUDFORMATION_STACK_1_0 {
		return q, failure("BadRequestException", "The resource query type is not supported.")
	}
	decoder := json.NewDecoder(strings.NewReader(string(*in.Query)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&q); err != nil {
		return q, failure("BadRequestException", "Invalid resource query: "+err.Error())
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return q, failure("BadRequestException", "ResourceQuery must contain one JSON object.")
	}
	if len(q.ResourceTypeFilters) == 0 || len(q.ResourceTypeFilters) > 100 {
		return q, failure("BadRequestException", "ResourceTypeFilters must contain between 1 and 100 resource types.")
	}
	seen := map[string]bool{}
	for _, typ := range q.ResourceTypeFilters {
		if seen[typ] {
			return q, failure("BadRequestException", "ResourceTypeFilters contains a duplicate resource type.")
		}
		seen[typ] = true
		if typ == "AWS::AllSupported" && len(q.ResourceTypeFilters) != 1 {
			return q, failure("BadRequestException", "AWS::AllSupported cannot be combined with another resource type.")
		}
		if typ != "AWS::AllSupported" && !ResourceTypeSupported(typ, string(*in.Type)) {
			return q, failure("BadRequestException", "Invalid resource type: "+typ)
		}
	}
	if *in.Type == api.QueryTypeTAG_FILTERS_1_0 {
		if q.StackIdentifier != "" {
			return q, failure("BadRequestException", "StackIdentifier is not valid for a tag query.")
		}
		if len(q.TagFilters) == 0 || len(q.TagFilters) > 50 {
			return q, failure("BadRequestException", "TagFilters must contain between 1 and 50 filters.")
		}
		positions := map[string]int{}
		normalized := make([]tagFilter, 0, len(q.TagFilters))
		for _, f := range q.TagFilters {
			if f.Key == "" || len(f.Key) > 128 || len(f.Values) > 20 {
				return q, failure("BadRequestException", "Invalid tag filter key or values.")
			}
			for _, v := range f.Values {
				if len(v) > 256 {
					return q, failure("BadRequestException", "Tag filter values may not exceed 256 characters.")
				}
			}
			if i, ok := positions[f.Key]; ok {
				normalized[i] = f
			} else {
				positions[f.Key] = len(normalized)
				normalized = append(normalized, f)
			}
		}
		q.TagFilters = normalized
	} else {
		if q.StackIdentifier == "" || len(q.TagFilters) > 0 {
			return q, failure("BadRequestException", "CloudFormation queries require StackIdentifier and cannot include tag filters.")
		}
		parts := strings.SplitN(q.StackIdentifier, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[2] != "cloudformation" || !strings.HasPrefix(parts[5], "stack/") {
			return q, failure("BadRequestException", "StackIdentifier must be a CloudFormation stack ARN.")
		}
	}
	return q, nil
}
func (s *Service) selectResources(ctx context.Context, in *api.ResourceQuery) ([]Resource, api.QueryErrorList, error) {
	q, err := parseQuery(in)
	if err != nil {
		return nil, nil, err
	}
	now := s.clock.Now()
	if *in.Type == api.QueryTypeTAG_FILTERS_1_0 {
		if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "tag:GetResources", ResourceARN: "*", EvaluationTime: &now}); denied != nil {
			return nil, nil, denied
		}
	} else {
		for _, action := range []string{"cloudformation:DescribeStacks", "cloudformation:ListStackResources"} {
			if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: action, ResourceARN: q.StackIdentifier, EvaluationTime: &now}); denied != nil {
				return nil, nil, denied
			}
		}
	}
	return s.resolveQueryResources(ctx, in, q)
}

// resolveQueryResources evaluates owner state after the consuming operation has
// applied its own authorization contract.
func (s *Service) resolveQueryResources(ctx context.Context, in *api.ResourceQuery, q resourceQuery) ([]Resource, api.QueryErrorList, error) {
	var rows []Resource
	var err error
	if *in.Type == api.QueryTypeTAG_FILTERS_1_0 {
		if s.resources == nil {
			return nil, nil, failure("NotImplementedException", "Current resource discovery is not configured.")
		}
		rows, err = s.resources.List(ctx)
	} else {
		scope := scopeFor(ctx)
		parts := strings.SplitN(q.StackIdentifier, ":", 6)
		if parts[1] != scope.Partition || parts[3] != scope.Region || parts[4] != scope.AccountID {
			return nil, queryError(api.QueryErrorCodeCLOUDFORMATION_STACK_NOT_EXISTING, "The specified CloudFormation stack does not exist in this account and Region."), nil
		}
		if s.resources == nil {
			return nil, nil, failure("NotImplementedException", "Current CloudFormation discovery is not configured.")
		}
		var stack Stack
		stack, err = s.resources.Stack(ctx, q.StackIdentifier)
		if err == nil {
			if stack.ARN == "" {
				return nil, queryError(api.QueryErrorCodeCLOUDFORMATION_STACK_NOT_EXISTING, "The specified CloudFormation stack does not exist."), nil
			}
			switch stack.Status {
			case "DELETE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED":
				return nil, queryError(api.QueryErrorCodeCLOUDFORMATION_STACK_INACTIVE, "The specified CloudFormation stack cannot have the following statuses: DELETE_COMPLETE, ROLLBACK_COMPLETE, CREATE_FAILED."), nil
			default:
				rows = stack.Resources
			}
		}
	}
	if err != nil {
		return nil, nil, err
	}
	out := make([]Resource, 0, len(rows))
	for _, r := range rows {
		if *in.Type == api.QueryTypeTAG_FILTERS_1_0 && r.StackOnly {
			continue
		}
		if !slices.Contains(q.ResourceTypeFilters, "AWS::AllSupported") && !slices.Contains(q.ResourceTypeFilters, r.Type) {
			continue
		}
		matched := true
		for _, f := range q.TagFilters {
			v, ok := r.Tags[f.Key]
			if !ok || len(f.Values) > 0 && !slices.Contains(f.Values, v) {
				matched = false
				break
			}
		}
		if matched {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b Resource) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil, nil
}
func queryError(code api.QueryErrorCode, message string) api.QueryErrorList {
	return api.QueryErrorList{{ErrorCode: new(code), Message: new(api.QueryErrorMessage(message))}}
}
func resourceOutput(r Resource) api.ResourceIdentifier {
	return api.ResourceIdentifier{ResourceArn: new(api.ResourceArn(r.ARN)), ResourceType: new(api.ResourceType(r.Type))}
}
func (s *Service) searchResources(tx Transaction, in *api.SearchResourcesInput) (*api.SearchResourcesOutput, error) {
	if err := s.authorize(tx.Context(), "SearchResources", nil, nil, nil); err != nil {
		return nil, err
	}
	rows, queryErrors, err := s.selectResources(tx.Context(), in.ResourceQuery)
	if err != nil {
		return nil, err
	}
	page, next, err := paginate(tx.Context(), "SearchResources", in.ResourceQuery, in.NextToken, in.MaxResults, rows, func(r Resource) string { return r.ARN })
	if err != nil {
		return nil, err
	}
	out := &api.SearchResourcesOutput{ResourceIdentifiers: api.ResourceIdentifierList{}, NextToken: next, QueryErrors: queryErrors}
	for _, r := range page {
		out.ResourceIdentifiers = append(out.ResourceIdentifiers, resourceOutput(r))
	}
	return out, nil
}
func (s *Service) getGroupQuery(tx Transaction, in *api.GetGroupQueryInput) (*api.GetGroupQueryOutput, error) {
	id, err := identifier(value(in.Group), value(in.GroupName))
	if err != nil {
		return nil, err
	}
	g, err := s.loadGroup(tx, id, "GetGroupQuery")
	if err != nil {
		return nil, err
	}
	if g.Query == nil {
		return nil, failure("BadRequestException", "The specified group does not have a resource query.")
	}
	return &api.GetGroupQueryOutput{GroupQuery: &api.GroupQuery{GroupName: new(api.GroupName(g.Name)), ResourceQuery: g.Query}}, nil
}
func (s *Service) updateGroupQuery(tx Transaction, in *api.UpdateGroupQueryInput) (*api.UpdateGroupQueryOutput, error) {
	id, err := identifier(value(in.Group), value(in.GroupName))
	if err != nil {
		return nil, err
	}
	g, err := s.loadGroup(tx, id, "UpdateGroupQuery")
	if err != nil {
		return nil, err
	}
	if g.ApplicationARN != "" {
		return nil, failure("ForbiddenException", "Access denied. This group is managed by AppRegistry.")
	}
	if g.Query == nil {
		return nil, failure("BadRequestException", "A service-linked group cannot be changed to a query-based group.")
	}
	if err := s.validateQuery(tx.Context(), in.ResourceQuery); err != nil {
		return nil, err
	}
	g.Query = in.ResourceQuery
	if err := tx.PutGroup(g); err != nil {
		return nil, err
	}
	return &api.UpdateGroupQueryOutput{GroupQuery: &api.GroupQuery{GroupName: new(api.GroupName(g.Name)), ResourceQuery: g.Query}}, nil
}
func (s *Service) listGroupResources(tx Transaction, in *api.ListGroupResourcesInput) (*api.ListGroupResourcesOutput, error) {
	id, err := identifier(value(in.Group), value(in.GroupName))
	if err != nil {
		return nil, err
	}
	g, err := s.loadGroup(tx, id, "ListGroupResources")
	if err != nil {
		return nil, err
	}
	var types []string
	for _, f := range in.Filters {
		if value(f.Name) != "resource-type" || len(f.Values) == 0 || types != nil {
			return nil, failure("BadRequestException", "Specify one resource-type filter with at least one value.")
		}
		for _, v := range f.Values {
			types = append(types, string(v))
		}
	}
	if g.Query != nil {
		q, err := parseQuery(g.Query)
		if err != nil {
			return nil, err
		}
		for _, typ := range types {
			if !slices.Contains(q.ResourceTypeFilters, "AWS::AllSupported") && !slices.Contains(q.ResourceTypeFilters, typ) {
				return nil, failure("BadRequestException", "The resource-type filter must be within the group's resource query types.")
			}
		}
	}
	rows, queryErrors, err := s.groupMembers(tx, g)
	if err != nil {
		return nil, err
	}
	selected := make([]Resource, 0, len(rows))
	for _, r := range rows {
		if len(types) == 0 || slices.Contains(types, r.Type) {
			selected = append(selected, r)
		}
	}
	request := struct {
		Group   string
		Query   *api.ResourceQuery
		Filters api.ResourceFilterList
	}{g.ARN, g.Query, in.Filters}
	page, next, err := paginate(tx.Context(), "ListGroupResources", request, in.NextToken, in.MaxResults, selected, func(r Resource) string { return r.ARN })
	if err != nil {
		return nil, err
	}
	out := &api.ListGroupResourcesOutput{ResourceIdentifiers: api.ResourceIdentifierList{}, Resources: api.ListGroupResourcesItemList{}, NextToken: next, QueryErrors: queryErrors}
	for _, r := range page {
		v := resourceOutput(r)
		out.ResourceIdentifiers = append(out.ResourceIdentifiers, v)
		item := api.ListGroupResourcesItem{Identifier: &v}
		if r.Pending {
			item.Status = &api.ResourceStatus{Name: new(api.ResourceStatusValuePending)}
		}
		out.Resources = append(out.Resources, item)
	}
	return out, nil
}
