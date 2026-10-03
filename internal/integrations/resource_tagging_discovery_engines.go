package integrations

import (
	"context"

	"stackd/internal/services/elasticache"
	"stackd/internal/services/kafka"
	"stackd/internal/services/memorydb"
	"stackd/internal/services/opensearch"
	"stackd/internal/services/pipes"
	"stackd/internal/services/rds"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
	"stackd/internal/services/scheduler"
)

func (r ResourceTaggingResources) listTaggingRDS(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	appendResource := func(key rds.Key, tags map[string]string) {
		out = append(out, tagging.Resource{ARN: key.ARN(), ResourceType: "rds:" + key.Kind, Tags: tags})
	}
	err = r.Backends.RDS.View(ctx, func(tx rds.Reader) error {
		sc := rds.Scope(scope)
		databases, err := tx.Databases(sc)
		if err != nil {
			return err
		}
		for _, row := range databases {
			appendResource(row.Key, row.Tags)
		}
		snapshots, err := tx.Snapshots(sc)
		if err != nil {
			return err
		}
		for _, row := range snapshots {
			appendResource(row.Key, row.Tags)
		}
		parameters, err := tx.ParameterGroups(sc)
		if err != nil {
			return err
		}
		for _, row := range parameters {
			appendResource(row.Key, row.Tags)
		}
		subnets, err := tx.SubnetGroups(sc)
		if err != nil {
			return err
		}
		for _, row := range subnets {
			appendResource(row.Key, row.Tags)
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingScheduler(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.Scheduler.View(ctx, func(tx scheduler.Reader) error {
		rows, err := tx.Groups(scheduler.Scope{Partition: scope.Partition, Account: scope.AccountID, Region: scope.Region})
		if err != nil {
			return err
		}
		hasDefault := false
		for _, row := range rows {
			hasDefault = hasDefault || row.Key.Name == "default"
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "scheduler:schedule-group", Tags: row.Tags})
		}
		// The default schedule group exists before the owner materializes it.
		if !hasDefault {
			out = append(out, tagging.Resource{ARN: resourceTaggingARN(scope, "scheduler", "schedule-group/default"), ResourceType: "scheduler:schedule-group"})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingPipes(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.Pipes.View(ctx, func(tx pipes.Reader) error {
		rows, err := tx.Pipes()
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Key.Scope != pipes.Scope(scope) {
				continue
			}
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "pipes:pipe", Tags: resourceTaggingSnapshotMap(row.Tags)})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingElastiCache(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	appendResource := func(key elasticache.Key, tags map[string]string) {
		out = append(out, tagging.Resource{ARN: key.ARN(), ResourceType: "elasticache:" + key.Kind, Tags: tags})
	}
	err = r.Backends.ElastiCache.View(ctx, func(tx elasticache.Reader) error {
		sc := elasticache.Scope(scope)
		clusters, err := tx.Clusters(sc)
		if err != nil {
			return err
		}
		for _, row := range clusters {
			appendResource(row.Key, row.Tags)
		}
		snapshots, err := tx.Snapshots(sc)
		if err != nil {
			return err
		}
		for _, row := range snapshots {
			appendResource(row.Key, row.Tags)
		}
		users, err := tx.Users(sc)
		if err != nil {
			return err
		}
		for _, row := range users {
			appendResource(row.Key, row.Tags)
		}
		groups, err := tx.UserGroups(sc)
		if err != nil {
			return err
		}
		for _, row := range groups {
			appendResource(row.Key, row.Tags)
		}
		parameters, err := tx.ParameterGroups(sc)
		if err != nil {
			return err
		}
		for _, row := range parameters {
			appendResource(row.Key, row.Tags)
		}
		subnets, err := tx.SubnetGroups(sc)
		if err != nil {
			return err
		}
		for _, row := range subnets {
			appendResource(row.Key, row.Tags)
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingMemoryDB(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	appendResource := func(key memorydb.Key, tags map[string]string) {
		out = append(out, tagging.Resource{ARN: key.ARN(), ResourceType: "memorydb:" + key.Kind, Tags: tags})
	}
	err = r.Backends.MemoryDB.View(ctx, func(tx memorydb.Reader) error {
		sc := memorydb.Scope(scope)
		clusters, err := tx.Clusters(sc)
		if err != nil {
			return err
		}
		for _, row := range clusters {
			appendResource(row.Key, row.Tags)
		}
		snapshots, err := tx.Snapshots(sc)
		if err != nil {
			return err
		}
		for _, row := range snapshots {
			appendResource(row.Key, row.Tags)
		}
		users, err := tx.Users(sc)
		if err != nil {
			return err
		}
		for _, row := range users {
			appendResource(row.Key, row.Tags)
		}
		acls, err := tx.ACLs(sc)
		if err != nil {
			return err
		}
		for _, row := range acls {
			appendResource(row.Key, row.Tags)
		}
		parameters, err := tx.ParameterGroups(sc)
		if err != nil {
			return err
		}
		for _, row := range parameters {
			appendResource(row.Key, row.Tags)
		}
		subnets, err := tx.SubnetGroups(sc)
		if err != nil {
			return err
		}
		for _, row := range subnets {
			appendResource(row.Key, row.Tags)
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingOpenSearch(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.OpenSearch.View(ctx, func(tx opensearch.Reader) error {
		rows, err := tx.Domains(opensearch.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "es:domain", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingKafka(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.Kafka.View(ctx, func(tx kafka.Reader) error {
		rows, err := tx.Clusters(kafka.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, tagging.Resource{ARN: row.ARN, ResourceType: "kafka:cluster", Tags: row.Tags})
		}
		return nil
	})
	return
}
