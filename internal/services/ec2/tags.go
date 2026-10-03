package ec2

import (
	"context"
	"errors"
	"maps"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	"strings"
	"unicode/utf8"
)

func validateTags(tags api.TagList) error {
	seen := map[string]bool{}
	for _, t := range tags {
		k := str(t.Key)
		if k == "" || utf8.RuneCountInString(k) > 127 || utf8.RuneCountInString(str(t.Value)) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return failure("InvalidParameterValue", "Tag keys must be nonempty, at most 127 characters, and must not start with aws:. Values must be at most 256 characters.")
		}
		if seen[k] {
			return failure("InvalidParameterValue", "Duplicate tag key '"+k+"'.")
		}
		seen[k] = true
	}
	if len(tags) > 50 {
		return failure("TagLimitExceeded", "The maximum number of tags has been reached.")
	}
	return nil
}

// CreationTags validates and detaches the tags for one EC2 resource kind.
func CreationTags(spec api.TagSpecificationList, kind string) (api.TagList, error) {
	var out api.TagList
	seen := false
	for _, s := range spec {
		if str(s.ResourceType) != kind {
			return nil, failure("InvalidParameterValue", "Tag specification resource type must be '"+kind+"'.")
		}
		if seen {
			return nil, failure("InvalidParameterValue", "Duplicate tag specification.")
		}
		seen = true
		out = api.CloneTagList(s.Tags)
	}
	if err := validateTags(out); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Value == nil {
			out[i].Value = new(api.String(""))
		}
	}
	return out, nil
}
func (s *Service) createTags(ctx context.Context, tx Transaction, in *api.CreateTagsRequest) (*emptyResult, error) {
	if len(in.Tags) == 0 {
		return nil, failure("MissingParameter", "The request must contain at least one tag.")
	}
	return s.changeTags(ctx, tx, "CreateTags", in.Resources, in.Tags, in.DryRun)
}
func (s *Service) deleteTags(ctx context.Context, tx Transaction, in *api.DeleteTagsRequest) (*emptyResult, error) {
	return s.changeTags(ctx, tx, "DeleteTags", in.Resources, in.Tags, in.DryRun)
}
func (s *Service) changeTags(ctx context.Context, tx Transaction, action string, resources api.ResourceIdList, tags api.TagList, dry *api.Boolean) (*emptyResult, error) {
	if len(resources) == 0 {
		return nil, failure("MissingParameter", "The request must contain at least one resource ID.")
	}
	if err := validateTags(tags); err != nil {
		return nil, err
	}
	conditions := map[string][]string{}
	for _, t := range tags {
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], str(t.Key))
		if action == "CreateTags" {
			conditions["aws:RequestTag/"+str(t.Key)] = []string{str(t.Value)}
		}
	}
	updates := make([]func() error, 0, len(resources))
	for _, id := range resources {
		kind := resourceKind(string(id))
		if strings.HasPrefix(string(id), "snap-") && s.snapshots != nil {
			kind = "snapshot"
		}
		if strings.HasPrefix(string(id), "vol-") && s.volumes != nil {
			kind = "volume"
		}
		if kind == "" {
			return nil, unsupported("Tagging this resource type is not implemented.")
		}
		var old api.TagList
		var put func(api.TagList) error
		var err error
		authorizeID := string(id)
		var resourceConditions map[string][]string
		var ownerRequest authorization.Request
		if kind == "key-pair" {
			var pair KeyPairRecord
			pair, err = tx.KeyPair(key(ctx, string(id)))
			old = pair.Data.Tags
			put = func(tags api.TagList) error { pair.Data.Tags = tags; return tx.PutKeyPair(pair) }
			// Key pairs are selected by ID for tagging, but IAM ARNs use names.
			authorizeID = str(pair.Data.KeyName)
			resourceConditions = keyPairConditions(pair.Data)
			maps.Copy(resourceConditions, conditions)
		} else if kind == "elastic-ip" {
			var address PublicAddressRecord
			address, err = tx.PublicAddress(key(ctx, string(id)))
			old = address.Data.Tags
			put = func(tags api.TagList) error { address.Data.Tags = tags; return tx.PutPublicAddress(address) }
			resourceConditions = addressConditions(address.Data)
			maps.Copy(resourceConditions, conditions)
		} else if kind == "snapshot" {
			old, ownerRequest, err = s.snapshots.SnapshotTags(ctx, action, string(id))
			put = func(tags api.TagList) error { return s.snapshots.SetSnapshotTags(ctx, string(id), tags) }
		} else if kind == "volume" {
			old, ownerRequest, err = s.volumes.VolumeTags(ctx, action, string(id))
			put = func(tags api.TagList) error { return s.volumes.SetVolumeTags(ctx, string(id), tags) }
		} else {
			old, put, err = resourceTags(tx, key(ctx, string(id)), kind)
			resourceConditions = maps.Clone(conditions)
		}
		if errors.Is(err, ErrNotFound) {
			err = missing(kind, string(id))
		}
		if err != nil {
			return nil, err
		}
		if kind == "snapshot" || kind == "volume" {
			if ownerRequest.Context == nil {
				ownerRequest.Context = map[string][]string{}
			}
			maps.Copy(ownerRequest.Context, conditions)
			if rejected := s.authorizer.Authorize(ctx, ownerRequest); rejected != nil {
				return nil, rejected
			}
		} else if err = s.authorizeWith(ctx, action, kind, authorizeID, old, resourceConditions); err != nil {
			return nil, err
		}
		values := map[string]api.Tag{}
		for _, t := range old {
			values[str(t.Key)] = t
		}
		if action == "CreateTags" {
			for _, t := range tags {
				values[str(t.Key)] = api.Tag{Key: copyPointer(t.Key), Value: new(api.String(str(t.Value)))}
			}
		} else if len(tags) == 0 {
			for k := range values {
				if !strings.HasPrefix(k, "aws:") {
					delete(values, k)
				}
			}
		} else {
			for _, t := range tags {
				if current, ok := values[str(t.Key)]; ok && (t.Value == nil || str(current.Value) == str(t.Value)) {
					delete(values, str(t.Key))
				}
			}
		}
		customerTags := 0
		for k := range values {
			if !strings.HasPrefix(k, "aws:") {
				customerTags++
			}
		}
		if customerTags > 50 {
			return nil, failure("TagLimitExceeded", "The maximum number of tags has been reached.")
		}
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		next := make(api.TagList, 0, len(keys))
		for _, k := range keys {
			next = append(next, values[k])
		}
		updates = append(updates, func() error { return put(next) })
	}
	if err := dryRun(dry); err != nil {
		return nil, err
	}
	for _, put := range updates {
		if err := put(); err != nil {
			return nil, err
		}
	}
	return &emptyResult{}, nil
}
func resourceTags(tx Transaction, k ResourceKey, kind string) (api.TagList, func(api.TagList) error, error) {
	switch kind {
	case "launch-template":
		v, err := tx.LaunchTemplate(k)
		return v.Data.Tags, func(tags api.TagList) error { v.Data.Tags = tags; return tx.PutLaunchTemplate(v) }, err
	case "instance":
		v, err := tx.Instance(k)
		return v.Data.Tags, func(tags api.TagList) error {
			if v.Data.MetadataOptions != nil && str(v.Data.MetadataOptions.InstanceMetadataTags) == "enabled" {
				if err := validateMetadataTags(tags); err != nil {
					return err
				}
			}
			v.Data.Tags = tags
			return tx.PutInstance(v)
		}, err
	case "image":
		v, err := tx.Image(k)
		if err == nil && str(v.Data.State) == "deregistered" {
			err = imageNotFound(k.ID)
		}
		if errors.Is(err, ErrNotFound) {
			err = imageNotFound(k.ID)
		}
		return v.Data.Tags, func(t api.TagList) error { v.Data.Tags = t; return tx.PutImage(v) }, err
	case "dhcp-options":
		v, err := tx.DHCPOptions(k)
		return v.Data.Tags, func(t api.TagList) error { v.Data.Tags = t; return tx.PutDHCPOptions(v) }, err
	case "vpc":
		v, err := tx.VPC(k)
		return v.Data.Tags, func(t api.TagList) error { v.Data.Tags = t; return tx.PutVPC(v) }, err
	case "subnet":
		v, err := tx.Subnet(k)
		return v.Data.Tags, func(t api.TagList) error { v.Data.Tags = t; return tx.PutSubnet(v) }, err
	case "security-group":
		v, err := tx.SecurityGroup(k)
		return v.Data.Tags, func(t api.TagList) error { v.Data.Tags = t; return tx.PutSecurityGroup(v) }, err
	case "security-group-rule":
		v, err := tx.SecurityGroupRule(k)
		return v.Data.Tags, func(t api.TagList) error { v.Data.Tags = t; return tx.PutSecurityGroupRule(v) }, err
	case "route-table":
		v, err := tx.RouteTable(k)
		return v.Data.Tags, func(t api.TagList) error { v.Data.Tags = t; return tx.PutRouteTable(v) }, err
	case "internet-gateway":
		v, err := tx.InternetGateway(k)
		return v.Data.Tags, func(t api.TagList) error { v.Data.Tags = t; return tx.PutInternetGateway(v) }, err
	case "network-interface":
		v, err := tx.NetworkInterface(k)
		return v.Data.TagSet, func(t api.TagList) error { v.Data.TagSet = t; return tx.PutNetworkInterface(v) }, err
	case "network-acl":
		v, err := tx.NetworkACL(k)
		return v.Data.Tags, func(t api.TagList) error { v.Data.Tags = t; return tx.PutNetworkACL(v) }, err
	}
	return nil, nil, ErrNotFound
}
func (s *Service) describeTags(ctx context.Context, tx Transaction, in *api.DescribeTagsRequest) (*api.DescribeTagsResult, error) {
	if err := s.authorize(ctx, "DescribeTags", "", "", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	items := []pageItem{}
	data := map[string]api.TagDescription{}
	add := func(id, kind string, tags api.TagList) {
		for _, t := range tags {
			k := id + "\x00" + str(t.Key)
			items = append(items, pageItem{k, nil, map[string][]string{"resource-id": {id}, "resource-type": {kind}, "key": {str(t.Key)}, "value": {str(t.Value)}}})
			data[k] = api.TagDescription{Key: t.Key, Value: t.Value, ResourceId: new(api.String(id)), ResourceType: new(api.ResourceType(kind))}
		}
	}
	scope := scopeFor(ctx)
	templates, err := tx.LaunchTemplates(scope)
	if err != nil {
		return nil, err
	}
	for _, template := range templates {
		add(template.Key.ID, "launch-template", template.Data.Tags)
	}
	addresses, err := tx.PublicAddresses(scope)
	if err != nil {
		return nil, err
	}
	for _, v := range addresses {
		if !v.Automatic {
			add(v.Key.ID, "elastic-ip", v.Data.Tags)
		}
	}
	vpcs, err := tx.VPCs(scope)
	if err != nil {
		return nil, err
	}
	for _, v := range vpcs {
		add(v.Key.ID, "vpc", v.Data.Tags)
	}
	subnets, err := tx.Subnets(scope)
	if err != nil {
		return nil, err
	}
	for _, v := range subnets {
		add(v.Key.ID, "subnet", v.Data.Tags)
	}
	groups, err := tx.SecurityGroups(scope)
	if err != nil {
		return nil, err
	}
	for _, v := range groups {
		add(v.Key.ID, "security-group", v.Data.Tags)
	}
	rules, err := tx.SecurityGroupRules(scope)
	if err != nil {
		return nil, err
	}
	for _, v := range rules {
		add(v.Key.ID, "security-group-rule", v.Data.Tags)
	}
	routes, err := tx.RouteTables(scope)
	if err != nil {
		return nil, err
	}
	for _, v := range routes {
		add(v.Key.ID, "route-table", v.Data.Tags)
	}
	gateways, err := tx.InternetGateways(scope)
	if err != nil {
		return nil, err
	}
	for _, v := range gateways {
		add(v.Key.ID, "internet-gateway", v.Data.Tags)
	}
	interfaces, err := tx.NetworkInterfaces(scope)
	if err != nil {
		return nil, err
	}
	for _, v := range interfaces {
		add(v.Key.ID, "network-interface", v.Data.TagSet)
	}
	acls, err := tx.NetworkACLs(scope)
	if err != nil {
		return nil, err
	}
	for _, v := range acls {
		add(v.Key.ID, "network-acl", v.Data.Tags)
	}
	options, err := tx.DHCPOptionsSets(scope)
	if err != nil {
		return nil, err
	}
	for _, option := range options {
		add(option.Key.ID, "dhcp-options", option.Data.Tags)
	}
	keyPairs, err := tx.KeyPairs(scope)
	if err != nil {
		return nil, err
	}
	for _, pair := range keyPairs {
		add(pair.Key.ID, "key-pair", pair.Data.Tags)
	}
	images, err := tx.Images(scope)
	if err != nil {
		return nil, err
	}
	for _, image := range images {
		if str(image.Data.State) != "deregistered" {
			add(image.Key.ID, "image", image.Data.Tags)
		}
	}
	instances, err := tx.Instances(scope)
	if err != nil {
		return nil, err
	}
	for _, instance := range instances {
		add(instance.Key.ID, "instance", instance.Data.Tags)
	}
	if s.snapshots != nil {
		tags, err := s.snapshots.ListSnapshotTags(ctx)
		if err != nil {
			return nil, err
		}
		for _, tag := range tags {
			add(str(tag.ResourceId), "snapshot", api.TagList{{Key: tag.Key, Value: tag.Value}})
		}
	}
	if s.volumes != nil {
		tags, err := s.volumes.ListVolumeTags(ctx)
		if err != nil {
			return nil, err
		}
		for _, tag := range tags {
			add(str(tag.ResourceId), "volume", api.TagList{{Key: tag.Key, Value: tag.Value}})
		}
	}
	ids, next, err := selectPage(ctx, "DescribeTags", nil, in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeTagsResult{Tags: api.TagDescriptionList{}, NextToken: next}
	for _, id := range ids {
		out.Tags = append(out.Tags, data[id])
	}
	return out, nil
}
