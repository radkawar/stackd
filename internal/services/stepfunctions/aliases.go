package stepfunctions

import (
	"cmp"
	"errors"
	"slices"

	api "stackd/internal/awsapi/stepfunctions"
)

func admitAliasRoutes(r Reader, machine MachineRecord, input api.RoutingConfigurationList) ([]AliasRoute, error) {
	if len(input) < 1 || len(input) > 2 {
		return nil, invalid("Routing configuration must contain one or two state machine versions.")
	}
	routes := make([]AliasRoute, 0, len(input))
	weight := int64(0)
	for _, item := range input {
		key, qualifier, err := machineReference(value(item.StateMachineVersionArn))
		if err != nil {
			return nil, err
		}
		number, ok := versionNumber(qualifier)
		if !ok {
			return nil, invalid("Routing configuration must contain state machine version ARNs.")
		}
		if key != machine.Key {
			return nil, invalid("Routing configuration must contain versions of the same state machine.")
		}
		if item.Weight == nil || *item.Weight < 0 || *item.Weight > 100 {
			return nil, invalid("Routing configuration weights must be between 0 and 100.")
		}
		for _, route := range routes {
			if route.Version == number {
				return nil, invalid("Routing configuration must contain distinct state machine version ARNs.")
			}
		}
		routes = append(routes, AliasRoute{Version: number, Weight: int32(*item.Weight)})
		weight += int64(*item.Weight)
	}
	if weight != 100 {
		return nil, invalid("Sum of routing configuration weights must equal 100.")
	}
	for _, route := range routes {
		key := VersionKey{Machine: machine.Key, MachineID: machine.ID, Number: route.Version}
		if _, err := r.Version(key); err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, resourceMissing(key.ARN())
			}
			return nil, err
		}
	}
	slices.SortFunc(routes, func(a, b AliasRoute) int { return cmp.Compare(a.Version, b.Version) })
	return routes, nil
}

func (s *Service) createStateMachineAlias(tx Transaction, in *api.CreateStateMachineAliasInput) (*api.CreateStateMachineAliasOutput, error) {
	name := value(in.Name)
	if !validAliasName(name) {
		return nil, invalid("Alias name must contain 1 to 80 letters, digits, underscores, hyphens, or periods, and must not be all digits.")
	}
	if err := validDescription(value(in.Description)); err != nil {
		return nil, err
	}
	if len(in.RoutingConfiguration) < 1 || len(in.RoutingConfiguration) > 2 {
		return nil, invalid("Routing configuration must contain one or two state machine versions.")
	}
	raw := value(in.RoutingConfiguration[0].StateMachineVersionArn)
	machine, qualifier, err := lookupMachine(tx, raw)
	if _, ok := versionNumber(qualifier); !ok {
		if err != nil {
			return nil, err
		}
		return nil, invalid("Routing configuration must contain state machine version ARNs.")
	}
	if machine.Key.Name != "" {
		if denied := s.authorize(tx, "CreateStateMachineAlias", machine.Key.ARN(), machine.Tags, nil); denied != nil {
			return nil, denied
		}
	}
	if err != nil {
		return nil, err
	}
	if machine.Status == "DELETING" {
		return nil, failure("StateMachineDeleting", "State Machine is being deleted.", 400)
	}
	routes, err := admitAliasRoutes(tx, machine, in.RoutingConfiguration)
	if err != nil {
		return nil, err
	}
	key := AliasKey{Machine: machine.Key, MachineID: machine.ID, Name: name}
	previous, err := tx.Alias(key)
	if err == nil {
		if err := cloudFormationCheck(tx.Context(), "StateMachineAlias", previous.CFNOwner); err != nil {
			return nil, err
		}
		if previous.Description != value(in.Description) || !slices.Equal(previous.Routes, routes) {
			return nil, failure("ConflictException", "An alias with the same name and a different configuration already exists.", 400)
		}
		return &api.CreateStateMachineAliasOutput{CreationDate: controlTimestamp(previous.Created), StateMachineAliasArn: new(api.Arn(key.ARN()))}, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	aliases, err := tx.Aliases(machine.Key, machine.ID)
	if err != nil {
		return nil, err
	}
	if len(aliases) >= 100 {
		return nil, failure("ServiceQuotaExceededException", "The maximum number of state machine aliases has been reached.", 400)
	}
	now := s.clock.Now().UTC()
	alias := AliasRecord{Key: key, Description: value(in.Description), Created: now, Updated: now, Routes: routes}
	alias.CFNOwner = cloudFormationClaim(tx.Context(), "StateMachineAlias")
	if err := tx.PutAlias(alias); err != nil {
		return nil, err
	}
	return &api.CreateStateMachineAliasOutput{CreationDate: controlTimestamp(now), StateMachineAliasArn: new(api.Arn(key.ARN()))}, nil
}

func (s *Service) controlAlias(r Reader, raw, action string, active bool) (MachineRecord, AliasRecord, error) {
	machine, qualifier, err := s.controlMachine(r, raw, action, false, active)
	if err != nil {
		if wireError(err).Code == "StateMachineDoesNotExist" {
			return machine, AliasRecord{}, resourceMissing(raw)
		}
		return machine, AliasRecord{}, err
	}
	if !validAliasName(qualifier) {
		return machine, AliasRecord{}, invalid("stateMachineAliasArn must be an alias-qualified state machine ARN.")
	}
	alias, err := r.Alias(AliasKey{Machine: machine.Key, MachineID: machine.ID, Name: qualifier})
	if errors.Is(err, ErrNotFound) {
		return machine, AliasRecord{}, resourceMissing(raw)
	}
	if err == nil {
		err = cloudFormationCheck(r.Context(), "StateMachineAlias", alias.CFNOwner)
	}
	return machine, alias, err
}

func (s *Service) updateStateMachineAlias(tx Transaction, in *api.UpdateStateMachineAliasInput) (*api.UpdateStateMachineAliasOutput, error) {
	machine, alias, err := s.controlAlias(tx, value(in.StateMachineAliasArn), "UpdateStateMachineAlias", true)
	if err != nil {
		return nil, err
	}
	if in.Description == nil && in.RoutingConfiguration == nil {
		return nil, invalid("Either description or routing configuration must be specified.")
	}
	if in.Description != nil {
		if err := validDescription(value(in.Description)); err != nil {
			return nil, err
		}
		alias.Description = value(in.Description)
	}
	if in.RoutingConfiguration != nil {
		routes, err := admitAliasRoutes(tx, machine, in.RoutingConfiguration)
		if err != nil {
			return nil, err
		}
		alias.Routes = routes
	}
	alias.Updated = s.clock.Now().UTC()
	if err := tx.PutAlias(alias); err != nil {
		return nil, err
	}
	return &api.UpdateStateMachineAliasOutput{UpdateDate: controlTimestamp(alias.Updated)}, nil
}

func (s *Service) deleteStateMachineAlias(tx Transaction, in *api.DeleteStateMachineAliasInput) (*api.DeleteStateMachineAliasOutput, error) {
	_, alias, err := s.controlAlias(tx, value(in.StateMachineAliasArn), "DeleteStateMachineAlias", false)
	if err != nil {
		if wireError(err).Code == "ResourceNotFound" {
			return &api.DeleteStateMachineAliasOutput{}, nil
		}
		return nil, err
	}
	if err := tx.DeleteAlias(alias.Key); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return &api.DeleteStateMachineAliasOutput{}, nil
}

func (s *Service) describeStateMachineAlias(tx Transaction, in *api.DescribeStateMachineAliasInput) (*api.DescribeStateMachineAliasOutput, error) {
	_, alias, err := s.controlAlias(tx, value(in.StateMachineAliasArn), "DescribeStateMachineAlias", false)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeStateMachineAliasOutput{CreationDate: controlTimestamp(alias.Created), UpdateDate: controlTimestamp(alias.Updated), Name: new(api.Name(alias.Key.Name)), StateMachineAliasArn: new(api.Arn(alias.Key.ARN())), RoutingConfiguration: api.RoutingConfigurationList{}}
	if alias.Description != "" {
		out.Description = new(api.AliasDescription(alias.Description))
	}
	for _, route := range alias.Routes {
		key := VersionKey{Machine: alias.Key.Machine, MachineID: alias.Key.MachineID, Number: route.Version}
		out.RoutingConfiguration = append(out.RoutingConfiguration, api.RoutingConfigurationListItem{StateMachineVersionArn: new(api.Arn(key.ARN())), Weight: new(api.VersionWeight(route.Weight))})
	}
	return out, nil
}

func (s *Service) listStateMachineAliases(tx Transaction, in *api.ListStateMachineAliasesInput) (*api.ListStateMachineAliasesOutput, error) {
	raw := value(in.StateMachineArn)
	machine, qualifier, err := s.controlMachine(tx, raw, "ListStateMachineAliases", false, false)
	if err != nil {
		return nil, err
	}
	var version int64
	if qualifier != "" {
		var ok bool
		version, ok = versionNumber(qualifier)
		if !ok {
			return nil, invalid("stateMachineArn must be an unqualified or version-qualified state machine ARN.")
		}
	}
	collection := controlCollection(tx, "ListStateMachineAliases", raw, machine.ID)
	now := s.clock.Now()
	limit, after, err := controlPage(in.NextToken, in.MaxResults, collection, now)
	if err != nil {
		return nil, err
	}
	aliases, err := tx.Aliases(machine.Key, machine.ID)
	if err != nil {
		return nil, err
	}
	out := &api.ListStateMachineAliasesOutput{StateMachineAliases: api.StateMachineAliasList{}}
	for _, alias := range aliases {
		if alias.Key.Name <= after {
			continue
		}
		if version != 0 && !slices.ContainsFunc(alias.Routes, func(route AliasRoute) bool { return route.Version == version }) {
			continue
		}
		if len(out.StateMachineAliases) == limit {
			out.NextToken = controlNext(collection, after, now)
			break
		}
		out.StateMachineAliases = append(out.StateMachineAliases, api.StateMachineAliasListItem{CreationDate: controlTimestamp(alias.Created), StateMachineAliasArn: new(api.LongArn(alias.Key.ARN()))})
		after = alias.Key.Name
	}
	return out, nil
}
