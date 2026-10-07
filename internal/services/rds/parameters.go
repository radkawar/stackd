package rds

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"

	engine "stackd/engine/rds"
	api "stackd/internal/awsapi/rds"
)

func familyEngine(f string) string {
	switch f {

	case "postgres17":
		return "postgres"
	case "mysql8.4":
		return "mysql"
	case "aurora-postgresql17":
		return "aurora-postgresql"
	case "aurora-mysql8.4":
		return "aurora-mysql"

	}
	return ""
}

func (s *Service) groupParameters(ctx context.Context, tx Reader, kind, name, eng string) (map[string]string, error) {
	if name == "" {
		return map[string]string{}, nil
	}
	pkind := "pg"
	if kind == "cluster" {
		pkind = "cluster-pg"
	}
	k, e := resourceKey(ctx, pkind, name)
	if e != nil {
		return nil, e
	}
	g, e := tx.ParameterGroup(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound(pkind)
	}
	if e != nil {
		return nil, e
	}
	if g.Family != engineFamily(eng) {
		return nil, failure("InvalidParameterCombination", "Parameter group family does not match the database engine.")
	}
	return maps.Clone(g.Parameters), nil
}

func (s *Service) newParameterGroup(ctx context.Context, tx Transaction, kind, name, family, description string, tags api.TagList) (ParameterGroup, error) {
	k, e := resourceKey(ctx, kind, name)
	if e != nil {
		return ParameterGroup{}, e
	}
	if familyEngine(family) == "" {
		return ParameterGroup{}, failure("InvalidParameterValue", "The DB parameter group family is not supported by the pinned engine.")
	}
	if description == "" || len(description) > 255 {
		return ParameterGroup{}, failure("InvalidParameterValue", "A description of at most 255 characters is required.")
	}
	tagged, e := tagsFrom(tags)
	if e != nil {
		return ParameterGroup{}, e
	}
	action := "CreateDBParameterGroup"
	if kind == "cluster-pg" {
		action = "CreateDBClusterParameterGroup"
	}
	if e = s.authorize(ctx, action, k, nil, tagged); e != nil {
		return ParameterGroup{}, e
	}
	if _, e = tx.ParameterGroup(k); e == nil {
		return ParameterGroup{}, existsError(kind)
	} else if !errors.Is(e, ErrNotFound) {
		return ParameterGroup{}, e
	}
	v := ParameterGroup{Key: k, Family: family, Description: description, Parameters: map[string]string{}, ApplyMethods: map[string]string{}, Tags: tagged}
	v.ResourceID, e = incarnation()
	if e != nil {
		return v, e
	}
	v.Owner = cloudFormationClaim(ctx, k)
	return v, tx.PutParameterGroup(v)
}

func parameterGroupDTO(v ParameterGroup) api.DBParameterGroup {
	return api.DBParameterGroup{DBParameterGroupName: new(api.String(v.Key.Name)), DBParameterGroupArn: new(api.String(v.Key.ARN())), DBParameterGroupFamily: new(api.String(v.Family)), Description: new(api.String(v.Description))}
}

func clusterParameterGroupDTO(v ParameterGroup) api.DBClusterParameterGroup {
	return api.DBClusterParameterGroup{DBClusterParameterGroupName: new(api.String(v.Key.Name)), DBClusterParameterGroupArn: new(api.String(v.Key.ARN())), DBParameterGroupFamily: new(api.String(v.Family)), Description: new(api.String(v.Description))}
}

func (s *Service) createParameterGroup(ctx context.Context, tx Transaction, in *api.CreateDBParameterGroupMessage) (*api.CreateDBParameterGroupResult, error) {
	v, e := s.newParameterGroup(ctx, tx, "pg", value(in.DBParameterGroupName), value(in.DBParameterGroupFamily), value(in.Description), in.Tags)
	if e != nil {
		return nil, e
	}
	return &api.CreateDBParameterGroupResult{DBParameterGroup: new(parameterGroupDTO(v))}, nil
}

func (s *Service) createClusterParameterGroup(ctx context.Context, tx Transaction, in *api.CreateDBClusterParameterGroupMessage) (*api.CreateDBClusterParameterGroupResult, error) {
	v, e := s.newParameterGroup(ctx, tx, "cluster-pg", value(in.DBClusterParameterGroupName), value(in.DBParameterGroupFamily), value(in.Description), in.Tags)
	if e != nil {
		return nil, e
	}
	return &api.CreateDBClusterParameterGroupResult{DBClusterParameterGroup: new(clusterParameterGroupDTO(v))}, nil
}

func (s *Service) loadParameterGroup(ctx context.Context, tx Reader, action, kind, name string) (ParameterGroup, error) {
	k, e := resourceKey(ctx, kind, name)
	if e != nil {
		return ParameterGroup{}, e
	}
	v, e := tx.ParameterGroup(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound(kind)
	}
	if e != nil {
		return v, e
	}
	if e = checkCloudFormationOwner(ctx, k, v.Owner); e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}

func validateParameter(eng string, p api.Parameter, reset bool) error {
	name, method := value(p.ParameterName), value(p.ApplyMethod)
	if method != "immediate" && method != "pending-reboot" {
		return failure("InvalidParameterValue", "ApplyMethod must be immediate or pending-reboot.")
	}
	if engine.StaticParameter(eng, name) && method == "immediate" {
		return failure("InvalidParameterCombination", "Static parameters require pending-reboot.")
	}
	val := value(p.ParameterValue)
	if reset {
		val = "1"
	}
	if e := engine.ValidateParameters(eng, map[string]string{name: val}); e != nil {
		return failure("InvalidParameterValue", "The parameter name or value is not supported by the native engine.")
	}
	if p.AllowedValues != nil || p.ApplyType != nil || p.DataType != nil || p.Description != nil || p.IsModifiable != nil || p.MinimumEngineVersion != nil || p.Source != nil || len(p.SupportedEngineModes) > 0 {
		return unsupported("Only ParameterName, ParameterValue and ApplyMethod may be modified.")
	}
	if !reset {
		switch name {
		case "max_connections", "wait_timeout", "interactive_timeout", "statement_timeout", "idle_in_transaction_session_timeout":
			n, e := strconv.ParseInt(val, 10, 32)
			if e != nil || n < 0 || name == "max_connections" && n < 1 {
				return failure("InvalidParameterValue", "The parameter requires a nonnegative integer within the native range.")
			}
		}
	}
	return nil
}

// TODO: Comeback model independently visible cluster-group propagation when its
// real publication owner exists. Unattached local groups currently commit
// atomically; AWS's transient pending-change reset rejection is not simulated.
func (s *Service) changeParameters(ctx context.Context, tx Transaction, kind, name string, params api.ParametersList, reset, all bool) (ParameterGroup, error) {
	action := "ModifyDBParameterGroup"
	if reset {
		action = "ResetDBParameterGroup"
	}
	if kind == "cluster-pg" {

		action = "ModifyDBClusterParameterGroup"
		if reset {
			action = "ResetDBClusterParameterGroup"
		}

	}
	v, e := s.loadParameterGroup(ctx, tx, action, kind, name)
	if e != nil {
		return v, e
	}
	if all && len(params) > 0 {
		return v, failure("InvalidParameterCombination", "ResetAllParameters cannot be combined with Parameters.")
	}
	if !all && (len(params) == 0 || len(params) > 20) {
		return v, failure("InvalidParameterValue", "Between 1 and 20 parameters are required.")
	}
	if v.Parameters == nil {
		v.Parameters = map[string]string{}
	}
	if v.ApplyMethods == nil {
		v.ApplyMethods = map[string]string{}
	}
	seen := map[string]bool{}
	for _, p := range params {

		if e = validateParameter(familyEngine(v.Family), p, reset); e != nil {
			return v, e
		}
		n := value(p.ParameterName)
		if seen[n] {
			return v, failure("InvalidParameterValue", "Parameter names must be unique.")
		}
		seen[n] = true
		if reset {

			delete(v.Parameters, n)
			delete(v.ApplyMethods, n)

		} else {

			v.Parameters[n] = value(p.ParameterValue)
			v.ApplyMethods[n] = value(p.ApplyMethod)

		}

	}
	if all {

		v.Parameters = map[string]string{}
		v.ApplyMethods = map[string]string{}

	}
	dbs, e := tx.Databases(v.Key.Scope)
	if e != nil {
		return v, e
	}
	for _, db := range dbs {

		if db.ParameterGroup != v.Key.Name || kind == "pg" && db.Key.Kind != "db" || kind == "cluster-pg" && db.Key.Kind != "cluster" {
			continue
		}
		if db.Status != "available" && db.Status != "stopped" {
			return v, stateError(db.Key.Kind)
		}
		if db.Status == "available" {
			active := maps.Clone(db.Parameters)
			if active == nil {
				active = map[string]string{}
			}
			if all {
				for n := range active {
					if !engine.StaticParameter(db.Engine, n) {
						delete(active, n)
					}
				}
			} else {
				for _, p := range params {
					if value(p.ApplyMethod) != "immediate" {
						continue
					}
					n := value(p.ParameterName)
					if reset {
						delete(active, n)
					} else {
						active[n] = value(p.ParameterValue)
					}
				}
			}
			if !maps.Equal(db.Parameters, active) {
				// Retain native intent before I/O. Unrelated pending-reboot
				// values stay in the group, not in this active generation.
				db.Parameters = active
				db.Operation = "parameters"
				db.Status = "modifying"
				db.Due = s.clock.Now()
			}
		}
		db.PendingParameters = !maps.Equal(db.Parameters, v.Parameters)
		db.Version++
		if e = tx.PutDatabase(db); e != nil {
			return v, e
		}
		if db.Key.Kind == "cluster" {
			if e = s.mirrorMembers(tx, db); e != nil {
				return v, e
			}
		}

	}
	return v, tx.PutParameterGroup(v)
}

func (s *Service) modifyParameterGroup(ctx context.Context, tx Transaction, in *api.ModifyDBParameterGroupMessage) (*api.DBParameterGroupNameMessage, error) {
	v, e := s.changeParameters(ctx, tx, "pg", value(in.DBParameterGroupName), in.Parameters, false, false)
	if e != nil {
		return nil, e
	}
	return &api.DBParameterGroupNameMessage{DBParameterGroupName: new(api.String(v.Key.Name))}, nil
}

func (s *Service) modifyClusterParameterGroup(ctx context.Context, tx Transaction, in *api.ModifyDBClusterParameterGroupMessage) (*api.DBClusterParameterGroupNameMessage, error) {
	v, e := s.changeParameters(ctx, tx, "cluster-pg", value(in.DBClusterParameterGroupName), in.Parameters, false, false)
	if e != nil {
		return nil, e
	}
	return &api.DBClusterParameterGroupNameMessage{DBClusterParameterGroupName: new(api.String(v.Key.Name))}, nil
}

func (s *Service) resetParameterGroup(ctx context.Context, tx Transaction, in *api.ResetDBParameterGroupMessage) (*api.DBParameterGroupNameMessage, error) {
	v, e := s.changeParameters(ctx, tx, "pg", value(in.DBParameterGroupName), in.Parameters, true, boolean(in.ResetAllParameters))
	if e != nil {
		return nil, e
	}
	return &api.DBParameterGroupNameMessage{DBParameterGroupName: new(api.String(v.Key.Name))}, nil
}

func (s *Service) resetClusterParameterGroup(ctx context.Context, tx Transaction, in *api.ResetDBClusterParameterGroupMessage) (*api.DBClusterParameterGroupNameMessage, error) {
	v, e := s.changeParameters(ctx, tx, "cluster-pg", value(in.DBClusterParameterGroupName), in.Parameters, true, boolean(in.ResetAllParameters))
	if e != nil {
		return nil, e
	}
	return &api.DBClusterParameterGroupNameMessage{DBClusterParameterGroupName: new(api.String(v.Key.Name))}, nil
}

type emptyResult struct{}

func (s *Service) removeParameterGroup(ctx context.Context, tx Transaction, kind, name string) error {
	action := "DeleteDBParameterGroup"
	if kind == "cluster-pg" {
		action = "DeleteDBClusterParameterGroup"
	}
	v, e := s.loadParameterGroup(ctx, tx, action, kind, name)
	if e != nil {
		return e
	}
	dbs, e := tx.Databases(v.Key.Scope)
	if e != nil {
		return e
	}
	for _, db := range dbs {
		if db.ParameterGroup == v.Key.Name && (kind == "pg" && db.Key.Kind == "db" || kind == "cluster-pg" && db.Key.Kind == "cluster") {
			return failure("InvalidDBParameterGroupState", "The parameter group is associated with a database.")
		}
	}
	return tx.DeleteParameterGroup(v.Key)
}

func (s *Service) deleteParameterGroup(ctx context.Context, tx Transaction, in *api.DeleteDBParameterGroupMessage) (*emptyResult, error) {
	return &emptyResult{}, s.removeParameterGroup(ctx, tx, "pg", value(in.DBParameterGroupName))
}

func (s *Service) deleteClusterParameterGroup(ctx context.Context, tx Transaction, in *api.DeleteDBClusterParameterGroupMessage) (*emptyResult, error) {
	return &emptyResult{}, s.removeParameterGroup(ctx, tx, "cluster-pg", value(in.DBClusterParameterGroupName))
}

func (s *Service) listParameterGroups(ctx context.Context, tx Reader, kind, name string, marker *api.String, max *api.IntegerOptional, filters api.FilterList) ([]ParameterGroup, *api.String, error) {
	action := "DescribeDBParameterGroups"
	if kind == "cluster-pg" {
		action = "DescribeDBClusterParameterGroups"
	}
	if len(filters) > 0 {
		return nil, nil, unsupported("Parameter group filters are not supported.")
	}
	start, limit, e := pageStart(ctx, action, marker, max)
	if e != nil {
		return nil, nil, e
	}
	if name != "" {

		v, e := s.loadParameterGroup(ctx, tx, action, kind, name)
		if e != nil {
			return nil, nil, e
		}
		name = v.Key.Name

	} else if e = s.authorize(ctx, action, Key{}, nil, nil); e != nil {
		return nil, nil, e
	}
	all, e := tx.ParameterGroups(scopeFor(ctx))
	if e != nil {
		return nil, nil, e
	}
	out := []ParameterGroup{}
	last := ""
	for _, v := range all {

		if v.Key.Kind != kind || v.Key.Name <= start || name != "" && name != v.Key.Name {
			continue
		}
		if len(out) == limit {
			return out, pageMarker(ctx, action, last), nil
		}
		out = append(out, v)
		last = v.Key.Name

	}
	return out, nil, nil
}

func (s *Service) describeParameterGroups(ctx context.Context, tx Transaction, in *api.DescribeDBParameterGroupsMessage) (*api.DBParameterGroupsMessage, error) {
	items, marker, e := s.listParameterGroups(ctx, tx, "pg", value(in.DBParameterGroupName), in.Marker, in.MaxRecords, in.Filters)
	if e != nil {
		return nil, e
	}
	out := &api.DBParameterGroupsMessage{Marker: marker, DBParameterGroups: api.DBParameterGroupList{}}
	for _, v := range items {
		out.DBParameterGroups = append(out.DBParameterGroups, parameterGroupDTO(v))
	}
	return out, nil
}

func (s *Service) describeClusterParameterGroups(ctx context.Context, tx Transaction, in *api.DescribeDBClusterParameterGroupsMessage) (*api.DBClusterParameterGroupsMessage, error) {
	items, marker, e := s.listParameterGroups(ctx, tx, "cluster-pg", value(in.DBClusterParameterGroupName), in.Marker, in.MaxRecords, in.Filters)
	if e != nil {
		return nil, e
	}
	out := &api.DBClusterParameterGroupsMessage{Marker: marker, DBClusterParameterGroups: api.DBClusterParameterGroupList{}}
	for _, v := range items {
		out.DBClusterParameterGroups = append(out.DBClusterParameterGroups, clusterParameterGroupDTO(v))
	}
	return out, nil
}

func (s *Service) readParameters(ctx context.Context, tx Reader, kind, name, source string, marker *api.String, max *api.IntegerOptional, filters api.FilterList) (api.ParametersList, *api.String, error) {
	action := "DescribeDBParameters"
	if kind == "cluster-pg" {
		action = "DescribeDBClusterParameters"
	}
	if source != "" && source != "user" {
		return nil, nil, unsupported("Only configured user parameters are exposed; cloud default catalogs are not implemented.")
	}
	if len(filters) > 0 {
		return nil, nil, unsupported("Parameter filters are not supported.")
	}
	v, e := s.loadParameterGroup(ctx, tx, action, kind, name)
	if e != nil {
		return nil, nil, e
	}
	start, limit, e := pageStart(ctx, action, marker, max)
	if e != nil {
		return nil, nil, e
	}
	out := api.ParametersList{}
	last := ""
	for _, n := range slices.Sorted(maps.Keys(v.Parameters)) {

		if n <= start {
			continue
		}
		if len(out) == limit {
			return out, pageMarker(ctx, action, last), nil
		}
		applyType := "dynamic"
		if engine.StaticParameter(familyEngine(v.Family), n) {
			applyType = "static"
		}
		out = append(out, api.Parameter{ParameterName: new(api.String(n)), ParameterValue: new(api.PotentiallySensitiveParameterValue(v.Parameters[n])), ApplyMethod: new(api.ApplyMethod(v.ApplyMethods[n])), Source: new(api.String("user")), ApplyType: new(api.String(applyType)), IsModifiable: new(api.Boolean(true))})
		last = n

	}
	return out, nil, nil
}

func (s *Service) describeParameters(ctx context.Context, tx Transaction, in *api.DescribeDBParametersMessage) (*api.DBParameterGroupDetails, error) {
	items, marker, e := s.readParameters(ctx, tx, "pg", value(in.DBParameterGroupName), value(in.Source), in.Marker, in.MaxRecords, in.Filters)
	if e != nil {
		return nil, e
	}
	return &api.DBParameterGroupDetails{Parameters: items, Marker: marker}, nil
}

func (s *Service) describeClusterParameters(ctx context.Context, tx Transaction, in *api.DescribeDBClusterParametersMessage) (*api.DBClusterParameterGroupDetails, error) {
	items, marker, e := s.readParameters(ctx, tx, "cluster-pg", value(in.DBClusterParameterGroupName), value(in.Source), in.Marker, in.MaxRecords, in.Filters)
	if e != nil {
		return nil, e
	}
	return &api.DBClusterParameterGroupDetails{Parameters: items, Marker: marker}, nil
}
