package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strings"

	elbapi "stackd/internal/awsapi/elbv2"
	"stackd/internal/services/applicationautoscaling"
	"stackd/internal/services/autoscaling"
	"stackd/internal/services/ecs"
	"stackd/internal/services/eks"
	"stackd/internal/services/elbv2"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
)

func (r ResourceTaggingResources) listTaggingECS(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.ECS.View(ctx, func(tx ecs.Reader) error {
		sc := ecs.Scope(scope)
		appendResource := func(arn, kind string) error {
			record, err := tx.Tags(ecs.TagKey{Scope: sc, ResourceARN: arn})
			if err != nil && !errors.Is(err, ecs.ErrNotFound) {
				return err
			}
			var tags map[string]string
			if len(record.Tags) != 0 {
				tags = make(map[string]string, len(record.Tags))
				for _, tag := range record.Tags {
					tags[resourceTaggingText(tag.Key)] = resourceTaggingText(tag.Value)
				}
			}
			out = append(out, tagging.Resource{ARN: arn, ResourceType: "ecs:" + kind, Tags: tags})
			return nil
		}
		clusters, err := tx.Clusters(ecs.ClusterQuery{Scope: sc, Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, cluster := range clusters {
			if resourceTaggingText(cluster.Data.Status) == "INACTIVE" {
				continue
			}
			if err := appendResource(cluster.Key.ARN(), "cluster"); err != nil {
				return err
			}
			services, err := tx.Services(ecs.ServiceQuery{ClusterKey: cluster.Key, Limit: math.MaxInt})
			if err != nil {
				return err
			}
			for _, row := range services {
				if resourceTaggingText(row.Data.Status) == "INACTIVE" {
					continue
				}
				if err := appendResource(row.Key.ARN(), "service"); err != nil {
					return err
				}
			}
			tasks, err := tx.Tasks(ecs.TaskQuery{ClusterKey: cluster.Key, Limit: math.MaxInt})
			if err != nil {
				return err
			}
			for _, row := range tasks {
				if resourceTaggingText(row.Data.LastStatus) == "STOPPED" {
					continue
				}
				if err := appendResource(row.Key.ARN(), "task"); err != nil {
					return err
				}
			}
		}
		definitions, err := tx.TaskDefinitions(ecs.TaskDefinitionQuery{Scope: sc, Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, row := range definitions {
			if err := appendResource(row.Key.ARN(), "task-definition"); err != nil {
				return err
			}
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingEKS(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.EKS.View(ctx, func(tx eks.Reader) error {
		clusters, err := tx.Clusters(eks.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range clusters {
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "eks:cluster", Tags: row.Tags})
			entries, err := tx.AccessEntries(row.Key)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				out = append(out, tagging.Resource{ARN: resourceTaggingEKSAccessARN(entry), ResourceType: "eks:access-entry", Tags: entry.Tags})
			}
			nodegroups, err := tx.Nodegroups(row.Key)
			if err != nil {
				return err
			}
			for _, group := range nodegroups {
				out = append(out, tagging.Resource{ARN: group.Key.ARN(group.ID), ResourceType: "eks:nodegroup", Tags: group.Tags})
			}
			addons, err := tx.Addons(row.Key)
			if err != nil {
				return err
			}
			for _, addon := range addons {
				out = append(out, tagging.Resource{ARN: addon.ARN(), ResourceType: "eks:addon", Tags: addon.Tags})
			}
			profiles, err := tx.FargateProfiles(row.Key)
			if err != nil {
				return err
			}
			for _, profile := range profiles {
				out = append(out, tagging.Resource{ARN: profile.ARN(), ResourceType: "eks:fargateprofile", Tags: profile.Tags})
			}
			associations, err := tx.PodIdentityAssociations(row.Key)
			if err != nil {
				return err
			}
			for _, association := range associations {
				out = append(out, tagging.Resource{ARN: association.ARN(), ResourceType: "eks:podidentityassociation", Tags: association.Tags})
			}
		}
		return nil
	})
	return
}

// Access-entry IDs include the principal's immutable identity. Match the EKS
// owner's legacy identity fallback rather than deriving identity from its name.
func resourceTaggingEKSAccessARN(entry eks.AccessEntry) string {
	parts := strings.SplitN(entry.PrincipalARN, ":", 6)
	kind, name, account := "root", "root", entry.Key.AccountID
	if len(parts) == 6 {
		account = parts[4]
		if k, n, ok := strings.Cut(parts[5], "/"); ok {
			kind, name = k, n
		}
	}
	id := entry.ID
	if id == "" {
		digest := sha256.Sum256([]byte(entry.PrincipalID))
		id = hex.EncodeToString(digest[:16])
	}
	return resourceTaggingARN(tagging.Scope(entry.Key.Scope), "eks", "access-entry/"+entry.Key.Name+"/"+kind+"/"+account+"/"+name+"/"+id)
}

func (r ResourceTaggingResources) listTaggingELB(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	appendResource := func(arn, kind string, list elbapi.TagList) {
		var tags map[string]string
		if len(list) != 0 {
			tags = make(map[string]string, len(list))
			for _, tag := range list {
				tags[resourceTaggingText(tag.Key)] = resourceTaggingText(tag.Value)
			}
		}
		out = append(out, tagging.Resource{ARN: arn, ResourceType: "elasticloadbalancing:" + kind, Tags: tags})
	}
	err = r.Backends.ELBv2.View(ctx, func(tx elbv2.Reader) error {
		sc := elbv2.Scope(scope)
		balancers, err := tx.LoadBalancers(sc)
		if err != nil {
			return err
		}
		for _, row := range balancers {
			appendResource(resourceTaggingText(row.Data.LoadBalancerArn), "loadbalancer", row.Tags)
		}
		groups, err := tx.TargetGroups(sc)
		if err != nil {
			return err
		}
		for _, row := range groups {
			appendResource(resourceTaggingText(row.Data.TargetGroupArn), "targetgroup", row.Tags)
		}
		listeners, err := tx.Listeners(sc)
		if err != nil {
			return err
		}
		for _, row := range listeners {
			appendResource(resourceTaggingText(row.Data.ListenerArn), "listener", row.Tags)
		}
		rules, err := tx.Rules(sc)
		if err != nil {
			return err
		}
		for _, row := range rules {
			appendResource(resourceTaggingText(row.Data.RuleArn), "listener-rule", row.Tags)
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingAutoScaling(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.AutoScaling.View(ctx, func(tx autoscaling.Reader) error {
		rows, err := tx.Groups(autoscaling.GroupQuery{Scope: autoscaling.Scope(scope), Limit: math.MaxInt})
		if err != nil {
			return err
		}
		for _, row := range rows {
			var tags map[string]string
			if len(row.Data.Tags) != 0 {
				tags = make(map[string]string, len(row.Data.Tags))
				for _, tag := range row.Data.Tags {
					tags[resourceTaggingText(tag.Key)] = resourceTaggingText(tag.Value)
				}
			}
			out = append(out, tagging.Resource{ARN: resourceTaggingText(row.Data.AutoScalingGroupARN), ResourceType: "autoscaling:autoScalingGroup", Tags: tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingApplicationAutoScaling(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.ApplicationAutoScaling.View(ctx, func(tx applicationautoscaling.Reader) error {
		keys, err := tx.TargetKeys(scope.Partition, scope.AccountID)
		if err != nil {
			return err
		}
		for _, key := range keys {
			if key.Region != scope.Region {
				continue
			}
			row, err := tx.Target(key)
			if err != nil {
				return err
			}
			out = append(out, tagging.Resource{ARN: resourceTaggingText(row.Data.ScalableTargetARN), ResourceType: "application-autoscaling:scalable-target", Tags: resourceTaggingSnapshotMap(row.Tags)})
		}
		return nil
	})
	return
}
