package integrations

import (
	"context"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/ebs"
	"stackd/internal/services/ec2"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
)

func resourceTaggingEC2Tags(tags api.TagList) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[resourceTaggingText(tag.Key)] = resourceTaggingText(tag.Value)
	}
	return out
}

func (r ResourceTaggingResources) listTaggingEC2(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	appendResource := func(kind, id string, tags api.TagList) {
		owner := scope
		if kind == "image" {
			owner.AccountID = ""
		}
		out = append(out, tagging.Resource{ARN: resourceTaggingARN(owner, "ec2", kind+"/"+id), ResourceType: "ec2:" + kind, Tags: resourceTaggingEC2Tags(tags)})
	}
	err = r.Backends.EC2.View(ctx, func(tx ec2.Reader) error {
		sc := ec2.Scope(scope)
		vpcs, err := tx.VPCs(sc)
		if err != nil {
			return err
		}
		for _, row := range vpcs {
			appendResource("vpc", row.Key.ID, row.Data.Tags)
		}
		subnets, err := tx.Subnets(sc)
		if err != nil {
			return err
		}
		for _, row := range subnets {
			appendResource("subnet", row.Key.ID, row.Data.Tags)
		}
		groups, err := tx.SecurityGroups(sc)
		if err != nil {
			return err
		}
		for _, row := range groups {
			appendResource("security-group", row.Key.ID, row.Data.Tags)
		}
		rules, err := tx.SecurityGroupRules(sc)
		if err != nil {
			return err
		}
		for _, row := range rules {
			appendResource("security-group-rule", row.Key.ID, row.Data.Tags)
		}
		routes, err := tx.RouteTables(sc)
		if err != nil {
			return err
		}
		for _, row := range routes {
			appendResource("route-table", row.Key.ID, row.Data.Tags)
		}
		gateways, err := tx.InternetGateways(sc)
		if err != nil {
			return err
		}
		for _, row := range gateways {
			appendResource("internet-gateway", row.Key.ID, row.Data.Tags)
		}
		interfaces, err := tx.NetworkInterfaces(sc)
		if err != nil {
			return err
		}
		for _, row := range interfaces {
			appendResource("network-interface", row.Key.ID, row.Data.TagSet)
		}
		acls, err := tx.NetworkACLs(sc)
		if err != nil {
			return err
		}
		for _, row := range acls {
			appendResource("network-acl", row.Key.ID, row.Data.Tags)
		}
		dhcp, err := tx.DHCPOptionsSets(sc)
		if err != nil {
			return err
		}
		for _, row := range dhcp {
			appendResource("dhcp-options", row.Key.ID, row.Data.Tags)
		}
		addresses, err := tx.PublicAddresses(sc)
		if err != nil {
			return err
		}
		for _, row := range addresses {
			if !row.Automatic {
				appendResource("elastic-ip", row.Key.ID, row.Data.Tags)
			}
		}
		pairs, err := tx.KeyPairs(sc)
		if err != nil {
			return err
		}
		for _, row := range pairs {
			appendResource("key-pair", row.Key.ID, row.Data.Tags)
		}
		images, err := tx.Images(sc)
		if err != nil {
			return err
		}
		for _, row := range images {
			if resourceTaggingText(row.Data.State) != "deregistered" {
				appendResource("image", row.Key.ID, row.Data.Tags)
			}
		}
		instances, err := tx.Instances(sc)
		if err != nil {
			return err
		}
		for _, row := range instances {
			if row.Data.State != nil && resourceTaggingText(row.Data.State.Name) == "terminated" {
				continue
			}
			appendResource("instance", row.Key.ID, row.Data.Tags)
		}
		templates, err := tx.LaunchTemplates(sc)
		if err != nil {
			return err
		}
		for _, row := range templates {
			appendResource("launch-template", row.Key.ID, row.Data.Tags)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = r.Backends.EBS.View(ctx, func(tx ebs.Reader) error {
		snapshots, err := tx.Snapshots(ebs.Scope(scope))
		if err != nil {
			return err
		}
		owner := scope
		owner.AccountID = ""
		for _, row := range snapshots {
			if row.Deleted {
				continue
			}
			out = append(out, tagging.Resource{ARN: resourceTaggingARN(owner, "ec2", "snapshot/"+row.Key.ID), ResourceType: "ec2:snapshot", Tags: row.Tags})
		}
		volumes, err := tx.Volumes(ebs.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range volumes {
			if row.Status == "deleted" {
				continue
			}
			out = append(out, tagging.Resource{ARN: resourceTaggingARN(scope, "ec2", "volume/"+row.Key.ID), ResourceType: "ec2:volume", Tags: row.Tags})
		}
		return nil
	})
	return
}
