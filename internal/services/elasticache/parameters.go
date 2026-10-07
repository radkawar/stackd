package elasticache

import (
	"context"
	"errors"
	"maps"
	"slices"
	engine "stackd/engine/valkey"
	api "stackd/internal/awsapi/elasticache"
	"strconv"
	"strings"
)

// Only these parameters have a real CONFIG SET/reset implementation. The
// native runtime restores absent settings; persisted omission is not inertia.
var parameterDefaults = map[string]string{"maxmemory": "0", "maxmemory-policy": "noeviction", "timeout": "0", "tcp-keepalive": "300", "notify-keyspace-events": ""}

var builtinParameterGroups = [...]struct{ Name, Family string }{
	{"default.redis7", "redis7"},
	{"default.redis7.cluster.on", "redis7"},
	{"default.valkey8", "valkey8"},
	{"default.valkey8.cluster.on", "valkey8"},
}

func builtinParameterFamily(name string) string {
	for _, group := range builtinParameterGroups {
		if group.Name == name {
			return group.Family
		}
	}
	return ""
}

func parameterRecord(r Reader, k Key) (ParameterGroup, error) {
	if family := builtinParameterFamily(k.Name); family != "" {
		return ParameterGroup{Key: k, Family: family, Description: "Default parameter group for " + family}, nil
	}
	return r.ParameterGroup(k)
}

func validFamily(v string) bool { return v == "redis7" || v == "valkey8" }
func parameterOutput(v ParameterGroup) *api.CacheParameterGroup {
	return &api.CacheParameterGroup{ARN: new(api.String(v.Key.ARN())), CacheParameterGroupName: new(api.String(v.Key.Name)), CacheParameterGroupFamily: new(api.String(v.Family)), Description: new(api.String(v.Description)), IsGlobal: new(api.Boolean(false))}
}
func (s *Service) loadParameterGroup(ctx context.Context, r Reader, action, name string) (ParameterGroup, error) {
	k, e := resourceKey(ctx, "parametergroup", name)
	if e != nil {
		return ParameterGroup{}, e
	}
	v, e := parameterRecord(r, k)
	if errors.Is(e, ErrNotFound) {
		e = notFound(k.Kind)
	}
	if e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func (s *Service) createParameterGroup(ctx context.Context, tx Transaction, in *api.CreateCacheParameterGroupMessage) (*api.CreateCacheParameterGroupResult, error) {
	k, e := resourceKey(ctx, "parametergroup", value(in.CacheParameterGroupName))
	if e != nil {
		return nil, e
	}
	if !validFamily(value(in.CacheParameterGroupFamily)) {
		return nil, failure("InvalidParameterValue", "Only redis7 and valkey8 parameter families are supported.")
	}
	if value(in.Description) == "" {
		return nil, failure("InvalidParameterValue", "Description is required.")
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateCacheParameterGroup", k, nil, tags); e != nil {
		return nil, e
	}
	if _, e = parameterRecord(tx, k); e == nil {
		return nil, existsError(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	v := ParameterGroup{Key: k, Family: value(in.CacheParameterGroupFamily), Description: value(in.Description), Parameters: map[string]string{}, Tags: tags}
	return &api.CreateCacheParameterGroupResult{CacheParameterGroup: parameterOutput(v)}, tx.PutParameterGroup(v)
}
func (s *Service) applyParameters(tx Transaction, v ParameterGroup) error {
	if e := engine.ValidateParameters(v.Parameters); e != nil {
		return failure("InvalidParameterValue", e.Error())
	}
	all, e := tx.Clusters(v.Key.Scope)
	if e != nil {
		return e
	}
	for _, c := range all {
		if c.ParameterGroup != v.Key.Name {
			continue
		}
		if c.Status != "available" {
			return stateError(c.Key.Kind)
		}
		if e = validateCapacity(v.Parameters, c.MemoryBytes); e != nil {
			return e
		}
		c.Parameters = maps.Clone(v.Parameters)
		if e = s.markCluster(tx, c, "parameters", "modifying"); e != nil {
			return e
		}
	}
	return tx.PutParameterGroup(v)
}

func validateCapacity(parameters map[string]string, capacity int64) error {
	if configured, ok := parameters["maxmemory"]; ok && capacity > 0 {
		value, err := strconv.ParseInt(configured, 10, 64)
		if err != nil || value <= 0 || value > capacity {
			return failure("InvalidParameterValue", "maxmemory must be positive and must not exceed the native node capacity.")
		}
	}
	return nil
}
func (s *Service) modifyParameterGroup(ctx context.Context, tx Transaction, in *api.ModifyCacheParameterGroupMessage) (*api.CacheParameterGroupNameMessage, error) {
	v, e := s.loadParameterGroup(ctx, tx, "ModifyCacheParameterGroup", value(in.CacheParameterGroupName))
	if e != nil {
		return nil, e
	}
	if builtinParameterFamily(v.Key.Name) != "" {
		return nil, stateError(v.Key.Kind)
	}
	replace, _ := ctx.Value(cloudFormationParameterReplacementKey{}).(bool)
	if (!replace && len(in.ParameterNameValues) < 1) || len(in.ParameterNameValues) > 20 {
		return nil, failure("InvalidParameterValue", "Supply between 1 and 20 parameters.")
	}
	if replace {
		v.Parameters = map[string]string{}
	}
	seen := map[string]bool{}
	for _, p := range in.ParameterNameValues {
		name := value(p.ParameterName)
		if seen[name] || p.ParameterValue == nil {
			return nil, failure("InvalidParameterValue", "Parameter names must be unique and values required.")
		}
		seen[name] = true
		if _, ok := parameterDefaults[name]; !ok {
			return nil, failure("InvalidParameterValue", "Could not find a supported parameter with that name.")
		}
		v.Parameters[name] = value(p.ParameterValue)
	}
	return &api.CacheParameterGroupNameMessage{CacheParameterGroupName: new(api.String(v.Key.Name))}, s.applyParameters(tx, v)
}
func (s *Service) resetParameterGroup(ctx context.Context, tx Transaction, in *api.ResetCacheParameterGroupMessage) (*api.CacheParameterGroupNameMessage, error) {
	v, e := s.loadParameterGroup(ctx, tx, "ResetCacheParameterGroup", value(in.CacheParameterGroupName))
	if e != nil {
		return nil, e
	}
	if builtinParameterFamily(v.Key.Name) != "" {
		return nil, stateError(v.Key.Kind)
	}
	if boolean(in.ResetAllParameters) {
		if len(in.ParameterNameValues) > 0 {
			return nil, unsupported("ResetAllParameters cannot be combined with parameter names.")
		}
		v.Parameters = map[string]string{}
	} else {
		if len(in.ParameterNameValues) < 1 || len(in.ParameterNameValues) > 20 {
			return nil, failure("InvalidParameterValue", "Supply between 1 and 20 parameter names.")
		}
		for _, p := range in.ParameterNameValues {
			name := value(p.ParameterName)
			if _, ok := parameterDefaults[name]; !ok {
				return nil, failure("InvalidParameterValue", "Could not find a supported parameter with that name.")
			}
			if p.ParameterValue != nil {
				return nil, unsupported("Reset must not include a parameter value.")
			}
			delete(v.Parameters, name)
		}
	}
	return &api.CacheParameterGroupNameMessage{CacheParameterGroupName: new(api.String(v.Key.Name))}, s.applyParameters(tx, v)
}
func (s *Service) deleteParameterGroup(ctx context.Context, tx Transaction, in *api.DeleteCacheParameterGroupMessage) (*struct{}, error) {
	v, e := s.loadParameterGroup(ctx, tx, "DeleteCacheParameterGroup", value(in.CacheParameterGroupName))
	if e != nil {
		return nil, e
	}
	if builtinParameterFamily(v.Key.Name) != "" {
		return nil, stateError(v.Key.Kind)
	}
	all, e := tx.Clusters(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	for _, c := range all {
		if c.ParameterGroup == v.Key.Name {
			return nil, stateError(v.Key.Kind)
		}
	}
	return &struct{}{}, tx.DeleteParameterGroup(v.Key)
}
func (s *Service) describeParameterGroups(ctx context.Context, tx Transaction, in *api.DescribeCacheParameterGroupsMessage) (*api.CacheParameterGroupsMessage, error) {
	var all []ParameterGroup
	var e error
	if in.CacheParameterGroupName != nil {
		v, err := s.loadParameterGroup(ctx, tx, "DescribeCacheParameterGroups", value(in.CacheParameterGroupName))
		e = err
		all = []ParameterGroup{v}
	} else {
		e = s.authorize(ctx, "DescribeCacheParameterGroups", Key{}, nil, nil)
		if e == nil {
			all, e = tx.ParameterGroups(scopeFor(ctx))
		}
		if e == nil {
			for _, group := range builtinParameterGroups {
				v, err := parameterRecord(tx, Key{Scope: scopeFor(ctx), Kind: "parametergroup", Name: group.Name})
				if err != nil {
					return nil, err
				}
				all = append(all, v)
			}
			slices.SortFunc(all, func(a, b ParameterGroup) int { return strings.Compare(a.Key.Name, b.Key.Name) })
		}
	}
	if e != nil {
		return nil, e
	}
	selected, next, e := page(ctx, "DescribeCacheParameterGroups", value(in.CacheParameterGroupName), all, in.Marker, in.MaxRecords, func(v ParameterGroup) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.CacheParameterGroupsMessage{Marker: next}
	for _, v := range selected {
		out.CacheParameterGroups = append(out.CacheParameterGroups, *parameterOutput(v))
	}
	return out, nil
}
func (s *Service) describeParameters(ctx context.Context, tx Transaction, in *api.DescribeCacheParametersMessage) (*api.CacheParameterGroupDetails, error) {
	v, e := s.loadParameterGroup(ctx, tx, "DescribeCacheParameters", value(in.CacheParameterGroupName))
	if e != nil {
		return nil, e
	}
	source := value(in.Source)
	if source != "" && source != "user" && source != "system" {
		return nil, failure("InvalidParameterValue", "Source must be user or system.")
	}
	items := []api.Parameter{}
	for _, name := range slices.Sorted(maps.Keys(parameterDefaults)) {
		val := parameterDefaults[name]
		origin := "system"
		if configured, ok := v.Parameters[name]; ok {
			val = configured
			origin = "user"
		}
		if source != "" && origin != source {
			continue
		}
		kind := "string"
		if name == "maxmemory" || name == "timeout" || name == "tcp-keepalive" {
			kind = "integer"
		}
		items = append(items, api.Parameter{ParameterName: new(api.String(name)), ParameterValue: new(api.String(val)), Source: new(api.String(origin)), IsModifiable: new(api.Boolean(true)), ChangeType: new(api.ChangeType("immediate")), DataType: new(api.String(kind))})
	}
	selected, next, e := page(ctx, "DescribeCacheParameters", v.Key.Name+"/"+source, items, in.Marker, in.MaxRecords, func(v api.Parameter) string { return value(v.ParameterName) })
	return &api.CacheParameterGroupDetails{Parameters: selected, Marker: next}, e
}
