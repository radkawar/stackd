package memorydb

import (
	"context"
	"errors"
	"maps"
	"slices"
	engine "stackd/engine/valkey"
	api "stackd/internal/awsapi/memorydb"
	"strings"
)

var parameterDefaults = map[string]string{"maxmemory": "1073741824", "maxmemory-policy": "noeviction", "timeout": "0", "tcp-keepalive": "300", "notify-keyspace-events": ""}

func defaultParameterGroup(sc Scope, name string) (ParameterGroup, bool) {
	for _, family := range []string{"memorydb_valkey7", "memorydb_redis7"} {
		if name == "default."+family {
			return ParameterGroup{Key: Key{Scope: sc, Kind: "parametergroup", Name: name}, Family: family, Description: "Default native parameter group", Parameters: map[string]string{}}, true
		}
	}
	return ParameterGroup{}, false
}
func (s *Service) loadParameterGroup(ctx context.Context, r Reader, action, name string) (ParameterGroup, error) {
	name = strings.ToLower(name)
	v, ok := defaultParameterGroup(scopeFor(ctx), name)
	if !ok {
		k, e := keyFor(ctx, "parametergroup", name)
		if e != nil {
			return v, e
		}
		v, e = r.ParameterGroup(k)
		if errors.Is(e, ErrNotFound) {
			e = notFound("parametergroup")
		}
		if e != nil {
			return v, e
		}
	}
	if action == "CreateCluster" || action == "UpdateCluster" {
		return v, nil
	}
	return v, s.authorize(ctx, action, v.Key, v.Tags, nil)
}
func parameterGroupDTO(v ParameterGroup) *api.ParameterGroup {
	return &api.ParameterGroup{Name: new(api.String(v.Key.Name)), ARN: new(api.String(v.Key.ARN())), Family: new(api.String(v.Family)), Description: new(api.String(v.Description))}
}
func (s *Service) createParameterGroup(ctx context.Context, tx Transaction, in *api.CreateParameterGroupRequest) (*api.CreateParameterGroupResponse, error) {
	k, e := keyFor(ctx, "parametergroup", value(in.ParameterGroupName))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateParameterGroup", k, nil, tags); e != nil {
		return nil, e
	}
	if _, e = tx.ParameterGroup(k); e == nil {
		return nil, exists(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	family := value(in.Family)
	if family != "memorydb_valkey7" && family != "memorydb_redis7" {
		return nil, invalid("Only Valkey 7 and Redis 7 compatibility parameter groups are supported.")
	}
	v := ParameterGroup{Key: k, Family: family, Description: value(in.Description), Parameters: map[string]string{}, Tags: tags}
	if e = tx.PutParameterGroup(v); e != nil {
		return nil, e
	}
	return &api.CreateParameterGroupResponse{ParameterGroup: parameterGroupDTO(v)}, nil
}
func (s *Service) applyParameters(tx Transaction, v ParameterGroup) error {
	if e := s.ensureRuntime(); e != nil {
		return e
	}
	if e := engine.ValidateParameters(v.Parameters); e != nil {
		return invalid(e.Error())
	}
	all, e := tx.Clusters(v.Key.Scope)
	if e != nil {
		return e
	}
	for _, c := range all {
		if c.ParameterGroup != v.Key.Name {
			continue
		}
		if c.Status == "deleting" {
			return stateError("cluster")
		}
		s.scheduleCluster(&c, "parameters")
		if e = tx.PutCluster(c); e != nil {
			return e
		}
	}
	return tx.PutParameterGroup(v)
}
func (s *Service) updateParameterGroup(ctx context.Context, tx Transaction, in *api.UpdateParameterGroupRequest) (*api.UpdateParameterGroupResponse, error) {
	v, e := s.loadParameterGroup(ctx, tx, "UpdateParameterGroup", value(in.ParameterGroupName))
	if e != nil {
		return nil, e
	}
	if strings.HasPrefix(v.Key.Name, "default.") {
		return nil, invalid("Default parameter groups cannot be modified.")
	}
	replace, _ := ctx.Value(cloudFormationParameterReplacementKey{}).(bool)
	if !replace && len(in.ParameterNameValues) == 0 {
		return nil, invalid("At least one parameter is required.")
	}
	if replace {
		v.Parameters = map[string]string{}
	}
	seen := map[string]bool{}
	for _, p := range in.ParameterNameValues {
		name := value(p.ParameterName)
		if _, ok := parameterDefaults[name]; !ok {
			return nil, invalid("Unsupported parameter: " + name)
		}
		if seen[name] || p.ParameterValue == nil {
			return nil, invalid("Duplicate or missing parameter value.")
		}
		seen[name] = true
		v.Parameters[name] = value(p.ParameterValue)
	}
	if e = s.applyParameters(tx, v); e != nil {
		return nil, e
	}
	return &api.UpdateParameterGroupResponse{ParameterGroup: parameterGroupDTO(v)}, nil
}
func (s *Service) resetParameterGroup(ctx context.Context, tx Transaction, in *api.ResetParameterGroupRequest) (*api.ResetParameterGroupResponse, error) {
	v, e := s.loadParameterGroup(ctx, tx, "ResetParameterGroup", value(in.ParameterGroupName))
	if e != nil {
		return nil, e
	}
	if strings.HasPrefix(v.Key.Name, "default.") {
		return nil, invalid("Default parameter groups cannot be modified.")
	}
	if truth(in.AllParameters) {
		if len(in.ParameterNames) > 0 {
			return nil, invalid("Specify AllParameters or ParameterNames, not both.")
		}
		v.Parameters = map[string]string{}
	} else {
		if len(in.ParameterNames) == 0 {
			return nil, invalid("ParameterNames is required.")
		}
		for _, raw := range in.ParameterNames {
			name := string(raw)
			if _, ok := parameterDefaults[name]; !ok {
				return nil, invalid("Unsupported parameter: " + name)
			}
			delete(v.Parameters, name)
		}
	}
	if e = s.applyParameters(tx, v); e != nil {
		return nil, e
	}
	return &api.ResetParameterGroupResponse{ParameterGroup: parameterGroupDTO(v)}, nil
}
func (s *Service) deleteParameterGroup(ctx context.Context, tx Transaction, in *api.DeleteParameterGroupRequest) (*api.DeleteParameterGroupResponse, error) {
	v, e := s.loadParameterGroup(ctx, tx, "DeleteParameterGroup", value(in.ParameterGroupName))
	if e != nil {
		return nil, e
	}
	if strings.HasPrefix(v.Key.Name, "default.") {
		return nil, invalid("Default parameter groups cannot be deleted.")
	}
	all, e := tx.Clusters(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	for _, c := range all {
		if c.ParameterGroup == v.Key.Name {
			return nil, stateError("parametergroup")
		}
	}
	if e = tx.DeleteParameterGroup(v.Key); e != nil {
		return nil, e
	}
	return &api.DeleteParameterGroupResponse{ParameterGroup: parameterGroupDTO(v)}, nil
}
func (s *Service) describeParameterGroups(ctx context.Context, tx Transaction, in *api.DescribeParameterGroupsRequest) (*api.DescribeParameterGroupsResponse, error) {
	var rows []ParameterGroup
	if in.ParameterGroupName != nil {
		v, e := s.loadParameterGroup(ctx, tx, "DescribeParameterGroups", value(in.ParameterGroupName))
		if e != nil {
			return nil, e
		}
		rows = []ParameterGroup{v}
	} else {
		if e := s.authorize(ctx, "DescribeParameterGroups", Key{}, nil, nil); e != nil {
			return nil, e
		}
		var e error
		rows, e = tx.ParameterGroups(scopeFor(ctx))
		if e != nil {
			return nil, e
		}
		for _, name := range []string{"default.memorydb_redis7", "default.memorydb_valkey7"} {
			v, _ := defaultParameterGroup(scopeFor(ctx), name)
			rows = append(rows, v)
		}
		slices.SortFunc(rows, func(a, b ParameterGroup) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	}
	rows, next, e := page(rows, in.MaxResults, in.NextToken, binding(ctx, "DescribeParameterGroups", value(in.ParameterGroupName)), func(v ParameterGroup) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.DescribeParameterGroupsResponse{NextToken: next}
	for _, v := range rows {
		out.ParameterGroups = append(out.ParameterGroups, *parameterGroupDTO(v))
	}
	return out, nil
}
func (s *Service) describeParameters(ctx context.Context, tx Transaction, in *api.DescribeParametersRequest) (*api.DescribeParametersResponse, error) {
	v, e := s.loadParameterGroup(ctx, tx, "DescribeParameters", value(in.ParameterGroupName))
	if e != nil {
		return nil, e
	}
	rows := []api.Parameter{}
	controllerProjection, _ := ctx.Value(cloudFormationParameterReplacementKey{}).(bool)
	for _, name := range slices.Sorted(maps.Keys(parameterDefaults)) {
		if _, explicit := v.Parameters[name]; controllerProjection && !explicit {
			continue
		}
		val := parameterDefaults[name]
		if x, ok := v.Parameters[name]; ok {
			val = x
		}
		rows = append(rows, api.Parameter{Name: new(api.String(name)), Value: new(api.String(val))})
	}
	rows, next, e := page(rows, in.MaxResults, in.NextToken, binding(ctx, "DescribeParameters", v.Key.Name), func(v api.Parameter) string { return value(v.Name) })
	if e != nil {
		return nil, e
	}
	return &api.DescribeParametersResponse{Parameters: rows, NextToken: next}, nil
}
