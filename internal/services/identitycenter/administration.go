package identitycenter

import (
	"maps"
	"slices"
	api "stackd/internal/awsapi/ssoadmin"
	"stackd/internal/services/identitystore"
	"strconv"
	"strings"
	"time"
)

func (s *Service) registerAdministration() {
	register(s, "ssoadmin", "CreateInstance", s.createInstance)
	register(s, "ssoadmin", "ListInstances", s.listInstances)
	register(s, "ssoadmin", "DescribeInstance", func(tx Transaction, in *api.DescribeInstanceInput) (*api.DescribeInstanceOutput, error) {
		v, e := s.ownedInstance(tx, value(in.InstanceArn), "DescribeInstance")
		if e != nil {
			return nil, e
		}
		return &api.DescribeInstanceOutput{InstanceArn: new(api.InstanceArn(v.ARN)), IdentityStoreId: new(api.Id(v.StoreID)), Name: new(api.NameType(v.Name)), OwnerAccountId: new(api.AccountId(v.AccountID)), CreatedDate: new(api.Date(v.Created)), Status: new(api.InstanceStatusACTIVE), PermissionSetsEnabled: new(api.Boolean(true))}, nil
	})
	register(s, "ssoadmin", "UpdateInstance", func(tx Transaction, in *api.UpdateInstanceInput) (*api.UpdateInstanceOutput, error) {
		v, e := s.ownedInstance(tx, value(in.InstanceArn), "UpdateInstance")
		if e != nil {
			return nil, e
		}
		if in.EncryptionConfiguration != nil || (in.PermissionSetsEnabled != nil && !bool(*in.PermissionSetsEnabled)) {
			return nil, bad("Custom instance encryption and disabling permission sets are not implemented.")
		}
		if in.Name != nil {
			v.Name = value(in.Name)
		}
		return &api.UpdateInstanceOutput{}, tx.PutInstance(v)
	})
	register(s, "ssoadmin", "DeleteInstance", func(tx Transaction, in *api.DeleteInstanceInput) (*api.DeleteInstanceOutput, error) {
		v, e := s.ownedInstance(tx, value(in.InstanceArn), "DeleteInstance")
		if e != nil {
			return nil, e
		}
		permissions, e := tx.PermissionSets(v.ARN)
		if e != nil {
			return nil, e
		}
		if len(permissions) != 0 {
			return nil, failure("ConflictException", "Delete permission sets and account assignments before deleting the instance.", 400)
		}
		if s.directory == nil {
			return nil, failure("InternalServerException", "Identity Store is not configured.", 500)
		}
		if e = s.directory.DeleteStore(tx.Context(), directoryScope(v), v.StoreID); e != nil {
			return nil, e
		}
		return &api.DeleteInstanceOutput{}, tx.DeleteInstance(v.ARN)
	})
	register(s, "ssoadmin", "CreatePermissionSet", s.createPermissionSet)
	register(s, "ssoadmin", "DescribePermissionSet", func(tx Transaction, in *api.DescribePermissionSetInput) (*api.DescribePermissionSetOutput, error) {
		_, p, e := s.ownedPermission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "DescribePermissionSet")
		if e != nil {
			return nil, e
		}
		return &api.DescribePermissionSetOutput{PermissionSet: wirePermission(p)}, nil
	})
	register(s, "ssoadmin", "UpdatePermissionSet", func(tx Transaction, in *api.UpdatePermissionSetInput) (*api.UpdatePermissionSetOutput, error) {
		_, p, e := s.ownedPermission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "UpdatePermissionSet")
		if e != nil {
			return nil, e
		}
		if in.Description != nil {
			p.Description = value(in.Description)
		}
		if in.RelayState != nil {
			p.RelayState = value(in.RelayState)
		}
		if in.SessionDuration != nil {
			p.Duration, e = parseDuration(value(in.SessionDuration))
			if e != nil {
				return nil, e
			}
		}
		return &api.UpdatePermissionSetOutput{}, tx.PutPermissionSet(p)
	})
	register(s, "ssoadmin", "DeletePermissionSet", func(tx Transaction, in *api.DeletePermissionSetInput) (*api.DeletePermissionSetOutput, error) {
		i, p, e := s.ownedPermission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "DeletePermissionSet")
		if e != nil {
			return nil, e
		}
		assignments, e := tx.Assignments(i.ARN)
		if e != nil {
			return nil, e
		}
		for _, a := range assignments {
			if a.PermissionSetARN == p.ARN {
				return nil, failure("ConflictException", "Delete account assignments before deleting the permission set.", 400)
			}
		}
		provisions, e := tx.Provisionings(i.ARN)
		if e != nil {
			return nil, e
		}
		for _, v := range provisions {
			if v.PermissionSetARN == p.ARN {
				if e = s.targetEligible(tx, i, v.AccountID); e != nil {
					return nil, e
				}
				if s.roles == nil {
					return nil, failure("InternalServerException", "IAM provisioning is not configured.", 500)
				}
				if e = s.roles.Remove(tx.Context(), v); e != nil {
					return nil, e
				}
				if e = tx.DeleteProvisioning(v); e != nil {
					return nil, e
				}
			}
		}
		return &api.DeletePermissionSetOutput{}, tx.DeletePermissionSet(p.ARN)
	})
	register(s, "ssoadmin", "ListPermissionSets", func(tx Transaction, in *api.ListPermissionSetsInput) (*api.ListPermissionSetsOutput, error) {
		i, e := s.instance(tx, value(in.InstanceArn), "ListPermissionSets")
		if e != nil {
			return nil, e
		}
		rows, e := tx.PermissionSets(i.ARN)
		if e != nil {
			return nil, e
		}
		// Controller observers list only their own incarnation's permission sets.
		if owner := identitystore.CloudFormationOwner(tx.Context()); owner != "" {
			rows = slices.DeleteFunc(rows, func(v PermissionSet) bool { return v.CloudFormationOwner != owner })
		}
		rows, next, e := pageSlice(rows, value(in.NextToken), "ListPermissionSets/"+i.ARN, intValue(in.MaxResults), func(v PermissionSet) string { return v.ARN })
		if e != nil {
			return nil, e
		}
		out := &api.ListPermissionSetsOutput{PermissionSets: api.PermissionSetList{}}
		for _, p := range rows {
			out.PermissionSets = append(out.PermissionSets, api.PermissionSetArn(p.ARN))
		}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
	s.registerTags()
}
func (s *Service) createInstance(tx Transaction, in *api.CreateInstanceInput) (*api.CreateInstanceOutput, error) {
	if s.directory == nil {
		return nil, failure("InternalServerException", "Identity Store is not configured.", 500)
	}
	tags, e := parseTags(in.Tags)
	if e != nil {
		return nil, e
	}
	scope := scopeFor(tx.Context())
	rows, e := tx.Instances(scope)
	if e != nil {
		return nil, e
	}
	// A controller replay observes only its own committed instance. The
	// customer-visible ClientToken is not an ownership claim.
	owner := identitystore.CloudFormationOwner(tx.Context())
	for _, v := range rows {
		if e = s.authorizeTags(tx.Context(), "CreateInstance", v.ARN, nil, tags); e != nil {
			return nil, e
		}
		if owner != "" {
			if v.CloudFormationOwner == owner {
				return &api.CreateInstanceOutput{InstanceArn: new(api.InstanceArn(v.ARN))}, nil
			}
			continue
		}
		if value(in.ClientToken) != "" && v.ClientToken == value(in.ClientToken) {
			if v.Name != value(in.Name) || !maps.Equal(v.Tags, tags) {
				return nil, failure("ConflictException", "The client token was used with different parameters.", 400)
			}
			return &api.CreateInstanceOutput{InstanceArn: new(api.InstanceArn(v.ARN))}, nil
		}
	}
	if len(rows) != 0 {
		return nil, failure("ConflictException", "An Identity Center instance already exists in this account and Region.", 400)
	}
	id, e := randomHex(8)
	if e != nil {
		return nil, e
	}
	store, e := randomHex(5)
	if e != nil {
		return nil, e
	}
	v := Instance{Scope: scope, ARN: "arn:" + scope.Partition + ":sso:::instance/ssoins-" + id, StoreID: "d-" + store, Name: value(in.Name), ClientToken: value(in.ClientToken), Created: s.clock.Now(), Tags: tags, CloudFormationOwner: owner}
	if e = s.authorizeTags(tx.Context(), "CreateInstance", v.ARN, nil, tags); e != nil {
		return nil, e
	}
	if e = s.directory.EnsureStore(tx.Context(), directoryScope(v), v.StoreID); e != nil {
		return nil, e
	}
	if e = tx.PutInstance(v); e != nil {
		return nil, e
	}
	return &api.CreateInstanceOutput{InstanceArn: new(api.InstanceArn(v.ARN))}, nil
}
func (s *Service) listInstances(tx Transaction, in *api.ListInstancesInput) (*api.ListInstancesOutput, error) {
	if e := s.authorize(tx.Context(), "ListInstances", "*"); e != nil {
		return nil, e
	}
	scope := scopeFor(tx.Context())
	rows, e := tx.Instances(scope)
	if e != nil {
		return nil, e
	}
	if owner := identitystore.CloudFormationOwner(tx.Context()); owner != "" {
		rows = slices.DeleteFunc(rows, func(v Instance) bool { return v.CloudFormationOwner != owner })
	}
	rows, next, e := pageSlice(rows, value(in.NextToken), "ListInstances/"+scope.Partition+"/"+scope.AccountID+"/"+scope.Region, intValue(in.MaxResults), func(v Instance) string { return v.ARN })
	if e != nil {
		return nil, e
	}
	out := &api.ListInstancesOutput{Instances: api.InstanceList{}}
	for _, v := range rows {
		out.Instances = append(out.Instances, api.InstanceMetadata{InstanceArn: new(api.InstanceArn(v.ARN)), IdentityStoreId: new(api.Id(v.StoreID)), Name: new(api.NameType(v.Name)), OwnerAccountId: new(api.AccountId(v.AccountID)), CreatedDate: new(api.Date(v.Created)), Status: new(api.InstanceStatusACTIVE), PrimaryRegion: new(api.RegionName(v.Region))})
	}
	if next != "" {
		out.NextToken = new(api.Token(next))
	}
	return out, nil
}
func (s *Service) createPermissionSet(tx Transaction, in *api.CreatePermissionSetInput) (*api.CreatePermissionSetOutput, error) {
	instance, e := tx.Instance(value(in.InstanceArn))
	if e != nil {
		return nil, e
	}
	if instance.Scope != scopeFor(tx.Context()) {
		return nil, ErrNotFound
	}
	duration, e := parseDuration(value(in.SessionDuration))
	if e != nil {
		return nil, e
	}
	tags, e := parseTags(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorizeTags(tx.Context(), "CreatePermissionSet", instance.ARN, instance.Tags, tags); e != nil {
		return nil, e
	}
	rows, e := tx.PermissionSets(instance.ARN)
	if e != nil {
		return nil, e
	}
	// A controller replay observes its committed permission set, even after a
	// native rename; it never adopts a same-name permission set.
	owner := identitystore.CloudFormationOwner(tx.Context())
	if owner != "" {
		for _, p := range rows {
			if p.CloudFormationOwner == owner {
				return &api.CreatePermissionSetOutput{PermissionSet: wirePermission(p)}, nil
			}
		}
	}
	for _, p := range rows {
		if p.Name == value(in.Name) {
			return nil, failure("ConflictException", "A permission set with this name already exists.", 400)
		}
	}
	id, e := randomHex(8)
	if e != nil {
		return nil, e
	}
	instanceID := instance.ARN[strings.LastIndexByte(instance.ARN, '/')+1:]
	p := PermissionSet{InstanceARN: instance.ARN, ARN: "arn:" + instance.Partition + ":sso:::permissionSet/" + instanceID + "/ps-" + id, Name: value(in.Name), Description: value(in.Description), RelayState: value(in.RelayState), Duration: duration, Created: s.clock.Now(), Tags: tags, CloudFormationOwner: owner}
	if e = s.authorizeTags(tx.Context(), "CreatePermissionSet", p.ARN, nil, tags); e != nil {
		return nil, e
	}
	if e = tx.PutPermissionSet(p); e != nil {
		return nil, e
	}
	return &api.CreatePermissionSetOutput{PermissionSet: wirePermission(p)}, nil
}
func wirePermission(p PermissionSet) *api.PermissionSet {
	out := &api.PermissionSet{PermissionSetArn: new(api.PermissionSetArn(p.ARN)), Name: new(api.PermissionSetName(p.Name)), CreatedDate: new(api.Date(p.Created)), SessionDuration: new(api.Duration("PT" + strconv.FormatInt(int64(p.Duration/time.Second), 10) + "S"))}
	if p.Description != "" {
		out.Description = new(api.PermissionSetDescription(p.Description))
	}
	if p.RelayState != "" {
		out.RelayState = new(api.RelayState(p.RelayState))
	}
	return out
}
func parseDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return time.Hour, nil
	}
	if !strings.HasPrefix(raw, "PT") {
		return 0, bad("SessionDuration must be an ISO-8601 duration from one to twelve hours.")
	}
	text := strings.NewReplacer("H", "h", "M", "m", "S", "s").Replace(strings.TrimPrefix(raw, "PT"))
	v, e := time.ParseDuration(text)
	if e != nil || v < time.Hour || v > 12*time.Hour || v%time.Second != 0 {
		return 0, bad("SessionDuration must be an ISO-8601 duration from one to twelve hours.")
	}
	return v, nil
}
func parseTags(in api.TagList) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range in {
		key := value(v.Key)
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, bad("Tag keys cannot use the reserved aws: prefix.")
		}
		if _, ok := out[key]; ok {
			return nil, bad("Tag keys must be unique.")
		}
		out[key] = value(v.Value)
	}
	if len(out) > 50 {
		return nil, bad("A resource can have at most 50 tags.")
	}
	return out, nil
}
func wireTags(tags map[string]string) api.TagList {
	out := api.TagList{}
	for _, key := range slices.Sorted(maps.Keys(tags)) {
		out = append(out, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(tags[key]))})
	}
	return out
}
