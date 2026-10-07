package integrations

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/services/athena"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/dynamodb"
	"stackd/internal/services/ecr"
	"stackd/internal/services/elasticache"
	"stackd/internal/services/firehose"
	"stackd/internal/services/glue"
	"stackd/internal/services/kafka"
	"stackd/internal/services/kinesis"
	"stackd/internal/services/memorydb"
	"stackd/internal/services/opensearch"
	"stackd/internal/services/pipes"
	"stackd/internal/services/rds"
	"stackd/internal/services/scheduler"
)

// privateDataOwners projects the data, catalog and engine families exposed by
// native tagging discovery. Each candidate is point-read inside the enclosing
// coordinated read context; its request PhysicalID must address the exact
// native row whose canonical ARN is the candidate. Only the row's private
// CloudFormation claim proves membership. Tags and the ledger prove nothing.
func (r ResourceGroupsResources) privateDataOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	for _, project := range []func(context.Context, cloudformation.Scope, *resourceGroupsPrivateOwners) error{
		r.privateDataDynamoDBOwners, r.privateDataKinesisOwners, r.privateDataFirehoseOwners,
		r.privateDataGlueOwners, r.privateDataAthenaOwners,
		r.privateDataRDSOwners, r.privateDataElastiCacheOwners, r.privateDataMemoryDBOwners,
		r.privateDataOpenSearchOwners, r.privateDataKafkaOwners,
		r.privateDataECROwners, r.privateDataCodeBuildOwners,
		r.privateDataSchedulerOwners, r.privateDataPipesOwners,
	} {
		if err := project(ctx, scope, owners); err != nil {
			return err
		}
	}
	return nil
}

// Glue and Athena rows retain the exact analytics incarnation stamped by cfnAnalyticsContext.
func resourceGroupsDataAnalyticsClaim(request cloudformation.ResourceRequest) string {
	return request.StackID + "/" + request.LogicalID + "/" + request.Token
}

var (
	resourceGroupsDataRDSKinds = map[string]string{
		"AWS::RDS::DBInstance": "db", "AWS::RDS::DBCluster": "cluster",
		"AWS::RDS::DBParameterGroup": "pg", "AWS::RDS::DBClusterParameterGroup": "cluster-pg",
		"AWS::RDS::DBSubnetGroup": "subgrp",
	}
	resourceGroupsDataCacheKinds = map[string]string{
		"AWS::ElastiCache::CacheCluster": "cluster", "AWS::ElastiCache::ReplicationGroup": "replicationgroup",
		"AWS::ElastiCache::User": "user", "AWS::ElastiCache::UserGroup": "usergroup",
		"AWS::ElastiCache::ParameterGroup": "parametergroup", "AWS::ElastiCache::SubnetGroup": "subnetgroup",
	}
	resourceGroupsDataMemoryKinds = map[string]string{
		"AWS::MemoryDB::Cluster": "cluster", "AWS::MemoryDB::User": "user", "AWS::MemoryDB::ACL": "acl",
		"AWS::MemoryDB::ParameterGroup": "parametergroup", "AWS::MemoryDB::SubnetGroup": "subnetgroup",
		"AWS::MemoryDB::Snapshot": "snapshot",
	}
)

func resourceGroupsDataTypes(kinds map[string]string) []string {
	types := make([]string, 0, len(kinds))
	for kind := range kinds {
		types = append(types, kind)
	}
	return types
}

func (r ResourceGroupsResources) privateDataDynamoDBOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::DynamoDB::Table", "AWS::DynamoDB::GlobalTable") || r.Tagging.Backends.DynamoDB == nil {
		return nil
	}
	return r.Tagging.Backends.DynamoDB.View(ctx, func(tx dynamodb.Reader) error {
		sc := dynamodb.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			if request.Scope != scope || (request.Type != "AWS::DynamoDB::Table" && request.Type != "AWS::DynamoDB::GlobalTable") {
				continue
			}
			key := dynamodb.TableKey{Scope: sc, Name: request.PhysicalID}
			if key.ARN() != candidate {
				continue
			}
			row, err := tx.Table(key)
			if errors.Is(err, dynamodb.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if row.Key == key {
				owners.structured(candidate, row.Owner.StackID, row.Owner.LogicalID, row.Owner.Token)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataKinesisOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::Kinesis::Stream", "AWS::Kinesis::StreamConsumer") || r.Tagging.Backends.Kinesis == nil {
		return nil
	}
	return r.Tagging.Backends.Kinesis.View(ctx, func(tx kinesis.Reader) error {
		sc := kinesis.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		streamPrefix := kinesis.StreamKey{Scope: sc}.ARN()
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			switch request.Type {
			case "AWS::Kinesis::Stream":
				key := kinesis.StreamKey{Scope: sc, Name: request.PhysicalID}
				if key.ARN() != candidate {
					continue
				}
				row, err := tx.Stream(key)
				if errors.Is(err, kinesis.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if row.Key == key {
					owners.structured(candidate, row.Owner.StackID, row.Owner.LogicalID, row.Owner.Token)
				}
			case "AWS::Kinesis::StreamConsumer":
				// The consumer's physical identity is its exact incarnation ARN.
				if request.PhysicalID != candidate || !strings.HasPrefix(candidate, streamPrefix) {
					continue
				}
				name, _, ok := strings.Cut(strings.TrimPrefix(candidate, streamPrefix), "/consumer/")
				if !ok || name == "" {
					continue
				}
				consumers, err := tx.Consumers(kinesis.StreamKey{Scope: sc, Name: name})
				if errors.Is(err, kinesis.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				for _, row := range consumers {
					if row.Key.Stream.Scope == sc && row.Key.ARN() == candidate {
						owners.structured(candidate, row.Owner.StackID, row.Owner.LogicalID, row.Owner.Token)
						break
					}
				}
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataFirehoseOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::KinesisFirehose::DeliveryStream") || r.Tagging.Backends.Firehose == nil {
		return nil
	}
	return r.Tagging.Backends.Firehose.View(ctx, func(tx firehose.Reader) error {
		sc := firehose.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			if request.Scope != scope || request.Type != "AWS::KinesisFirehose::DeliveryStream" {
				continue
			}
			key := firehose.StreamKey{Scope: sc, Name: request.PhysicalID}
			if key.ARN() != candidate {
				continue
			}
			row, err := tx.Stream(key)
			if errors.Is(err, firehose.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if row.Key == key {
				owners.claim(candidate, row.CFNOwner, cfnMessagingMarker)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataGlueOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::Glue::Catalog", "AWS::Glue::Database", "AWS::Glue::Connection", "AWS::Glue::Job", "AWS::Glue::Crawler", "AWS::Glue::Registry", "AWS::Glue::Schema", "AWS::Glue::Workflow", "AWS::Glue::Trigger") || r.Tagging.Backends.Glue == nil {
		return nil
	}
	return r.Tagging.Backends.Glue.View(ctx, func(tx glue.Reader) error {
		sc := glue.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			var owner string
			var err error
			switch request.Type {
			case "AWS::Glue::Catalog":
				// The default account catalog is implicit and never claimed.
				if request.PhysicalID != candidate {
					continue
				}
				catalogID, parseErr := cfnGlueCatalogFromARN(request, candidate)
				if parseErr != nil || catalogID == scope.Account {
					continue
				}
				key := glue.CatalogKey{Scope: sc, CatalogID: catalogID}
				if key.ARN() != candidate {
					continue
				}
				var row glue.CatalogRecord
				if row, err = tx.Catalog(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			case "AWS::Glue::Database":
				key := glue.DatabaseKey{CatalogKey: glue.CatalogKey{Scope: sc, CatalogID: cfnGlueDatabaseCatalogID(request)}, Name: request.PhysicalID}
				if key.ARN() != candidate {
					continue
				}
				var row glue.DatabaseRecord
				if row, err = tx.Database(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			case "AWS::Glue::Connection":
				// Connections live in the account catalog; the physical ID is catalog|name.
				catalog, name, ok := strings.Cut(request.PhysicalID, "|")
				key := glue.ResourceKey{Scope: sc, Name: name}
				if !ok || catalog != scope.Account || name == "" || key.ARN("connection") != candidate {
					continue
				}
				var row glue.ConnectionRecord
				if row, err = tx.Connection(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			case "AWS::Glue::Job":
				key := glue.ResourceKey{Scope: sc, Name: request.PhysicalID}
				if key.ARN("job") != candidate {
					continue
				}
				var row glue.JobRecord
				if row, err = tx.GetJob(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			case "AWS::Glue::Crawler":
				key := glue.ResourceKey{Scope: sc, Name: request.PhysicalID}
				if key.ARN("crawler") != candidate {
					continue
				}
				var row glue.CrawlerRecord
				if row, err = tx.Crawler(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			case "AWS::Glue::Workflow":
				key := glue.ResourceKey{Scope: sc, Name: request.PhysicalID}
				if key.ARN("workflow") != candidate {
					continue
				}
				var row glue.WorkflowRecord
				if row, err = tx.Workflow(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			case "AWS::Glue::Trigger":
				key := glue.ResourceKey{Scope: sc, Name: request.PhysicalID}
				if key.ARN("trigger") != candidate {
					continue
				}
				var row glue.TriggerRecord
				if row, err = tx.Trigger(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			case "AWS::Glue::Registry":
				// Registry and schema physical identities are their exact ARNs.
				prefix := glue.ResourceKey{Scope: sc}.ARN("registry")
				if request.PhysicalID != candidate || !strings.HasPrefix(candidate, prefix) {
					continue
				}
				key := glue.ResourceKey{Scope: sc, Name: strings.TrimPrefix(candidate, prefix)}
				if key.Name == "" || key.ARN("registry") != candidate {
					continue
				}
				var row glue.RegistryRecord
				if row, err = tx.Registry(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			case "AWS::Glue::Schema":
				prefix := glue.ResourceKey{Scope: sc}.ARN("schema")
				if request.PhysicalID != candidate || !strings.HasPrefix(candidate, prefix) {
					continue
				}
				registry, name, ok := strings.Cut(strings.TrimPrefix(candidate, prefix), "/")
				key := glue.SchemaKey{Scope: sc, Registry: registry, Name: name}
				if !ok || registry == "" || name == "" || key.ARN() != candidate {
					continue
				}
				var row glue.SchemaRecord
				if row, err = tx.Schema(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			default:
				continue
			}
			if errors.Is(err, glue.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			owners.claim(candidate, owner, resourceGroupsDataAnalyticsClaim)
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataAthenaOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::Athena::WorkGroup", "AWS::Athena::DataCatalog") || r.Tagging.Backends.Athena == nil {
		return nil
	}
	return r.Tagging.Backends.Athena.View(ctx, func(tx athena.Reader) error {
		sc := athena.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			// Service defaults (primary, AwsDataCatalog) are never stamped and stay absent.
			key := athena.ResourceKey{Scope: sc, Name: request.PhysicalID}
			var owner string
			var err error
			switch request.Type {
			case "AWS::Athena::WorkGroup":
				if key.ARN("workgroup") != candidate {
					continue
				}
				var row athena.WorkGroupRecord
				if row, err = tx.WorkGroup(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			case "AWS::Athena::DataCatalog":
				if key.ARN("datacatalog") != candidate {
					continue
				}
				var row athena.CatalogRecord
				if row, err = tx.Catalog(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CFNOwner
			default:
				continue
			}
			if errors.Is(err, athena.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			owners.claim(candidate, owner, resourceGroupsDataAnalyticsClaim)
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataRDSOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs(resourceGroupsDataTypes(resourceGroupsDataRDSKinds)...) || r.Tagging.Backends.RDS == nil {
		return nil
	}
	return r.Tagging.Backends.RDS.View(ctx, func(tx rds.Reader) error {
		sc := rds.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			kind, supported := resourceGroupsDataRDSKinds[request.Type]
			if !supported || request.Scope != scope {
				continue
			}
			key := rds.Key{Scope: sc, Kind: kind, Name: request.PhysicalID}
			if key.ARN() != candidate {
				continue
			}
			var owner rds.CloudFormationOwner
			var err error
			switch kind {
			case "db", "cluster":
				var row rds.Database
				if row, err = tx.Database(key); err == nil && row.Key != key {
					continue
				}
				owner = row.Owner
			case "pg", "cluster-pg":
				var row rds.ParameterGroup
				if row, err = tx.ParameterGroup(key); err == nil && row.Key != key {
					continue
				}
				owner = row.Owner
			case "subgrp":
				var row rds.SubnetGroup
				if row, err = tx.SubnetGroup(key); err == nil && row.Key != key {
					continue
				}
				owner = row.Owner
			}
			if errors.Is(err, rds.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			owners.structured(candidate, owner.StackID, owner.LogicalID, owner.Token)
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataElastiCacheOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs(resourceGroupsDataTypes(resourceGroupsDataCacheKinds)...) || r.Tagging.Backends.ElastiCache == nil {
		return nil
	}
	return r.Tagging.Backends.ElastiCache.View(ctx, func(tx elasticache.Reader) error {
		sc := elasticache.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			kind, supported := resourceGroupsDataCacheKinds[request.Type]
			if !supported || request.Scope != scope {
				continue
			}
			key := elasticache.Key{Scope: sc, Kind: kind, Name: request.PhysicalID}
			if key.ARN() != candidate {
				continue
			}
			var owner string
			var err error
			switch kind {
			case "cluster", "replicationgroup":
				var row elasticache.Cluster
				if row, err = tx.Cluster(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			case "user":
				var row elasticache.User
				if row, err = tx.User(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			case "usergroup":
				var row elasticache.UserGroup
				if row, err = tx.UserGroup(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			case "parametergroup":
				var row elasticache.ParameterGroup
				if row, err = tx.ParameterGroup(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			case "subnetgroup":
				var row elasticache.SubnetGroup
				if row, err = tx.SubnetGroup(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			}
			if errors.Is(err, elasticache.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			owners.claim(candidate, owner, cfnNativeComputeClaim)
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataMemoryDBOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs(resourceGroupsDataTypes(resourceGroupsDataMemoryKinds)...) || r.Tagging.Backends.MemoryDB == nil {
		return nil
	}
	return r.Tagging.Backends.MemoryDB.View(ctx, func(tx memorydb.Reader) error {
		sc := memorydb.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			kind, supported := resourceGroupsDataMemoryKinds[request.Type]
			if !supported || request.Scope != scope {
				continue
			}
			name := request.PhysicalID
			if kind == "snapshot" {
				// A stack snapshot's physical identity is its scoped ARN.
				prefix := memorydb.Key{Scope: sc, Kind: kind}.ARN()
				if request.PhysicalID != candidate || !strings.HasPrefix(candidate, prefix) {
					continue
				}
				name = strings.TrimPrefix(candidate, prefix)
			}
			key := memorydb.Key{Scope: sc, Kind: kind, Name: name}
			if name == "" || key.ARN() != candidate {
				continue
			}
			var owner string
			var err error
			switch kind {
			case "cluster":
				var row memorydb.Cluster
				if row, err = tx.Cluster(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			case "user":
				var row memorydb.User
				if row, err = tx.User(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			case "acl":
				var row memorydb.ACL
				if row, err = tx.ACL(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			case "parametergroup":
				var row memorydb.ParameterGroup
				if row, err = tx.ParameterGroup(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			case "subnetgroup":
				var row memorydb.SubnetGroup
				if row, err = tx.SubnetGroup(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			case "snapshot":
				var row memorydb.Snapshot
				if row, err = tx.Snapshot(key); err == nil && row.Key != key {
					continue
				}
				owner = row.CloudFormationOwner
			}
			if errors.Is(err, memorydb.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			owners.claim(candidate, owner, cfnNativeComputeClaim)
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataOpenSearchOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::OpenSearchService::Domain", "AWS::Elasticsearch::Domain") || r.Tagging.Backends.OpenSearch == nil {
		return nil
	}
	return r.Tagging.Backends.OpenSearch.View(ctx, func(tx opensearch.Reader) error {
		sc := opensearch.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			var name string
			switch request.Type {
			case "AWS::OpenSearchService::Domain":
				name = request.PhysicalID
			case "AWS::Elasticsearch::Domain":
				// The legacy frontend's physical ID is account/name over the same domain row.
				account, domain, ok := strings.Cut(request.PhysicalID, "/")
				if !ok || account != scope.Account {
					continue
				}
				name = domain
			default:
				continue
			}
			key := opensearch.Key{Scope: sc, Name: name}
			if name == "" || key.ARN() != candidate {
				continue
			}
			row, err := tx.Domain(key)
			if errors.Is(err, opensearch.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if row.Key == key {
				owners.claim(candidate, row.Ownership, cfnMessagingMarker)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataKafkaOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::MSK::Cluster") || r.Tagging.Backends.Kafka == nil {
		return nil
	}
	return r.Tagging.Backends.Kafka.View(ctx, func(tx kafka.Reader) error {
		sc := kafka.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			// A cluster's physical identity is its exact incarnation ARN.
			if request.Scope != scope || request.Type != "AWS::MSK::Cluster" || request.PhysicalID != candidate {
				continue
			}
			row, err := tx.Cluster(candidate)
			if errors.Is(err, kafka.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if row.Scope == sc && row.ARN == candidate {
				owners.structured(candidate, row.OwnerStackID, row.OwnerLogicalID, row.OwnerToken)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataECROwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::ECR::Repository") || r.Tagging.Backends.ECR == nil {
		return nil
	}
	return r.Tagging.Backends.ECR.View(ctx, func(tx ecr.Reader) error {
		sc := ecr.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			if request.Scope != scope || request.Type != "AWS::ECR::Repository" || request.PhysicalID == "" {
				continue
			}
			key := ecr.RepositoryKey{Scope: sc, Name: request.PhysicalID}
			row, err := tx.Repository(key)
			if errors.Is(err, ecr.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if row.Key == key && row.ARN == candidate {
				owners.claim(candidate, row.Ownership, cfnDeveloperClaim)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataCodeBuildOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::CodeBuild::Project", "AWS::CodeBuild::Fleet") || r.Tagging.Backends.CodeBuild == nil {
		return nil
	}
	return r.Tagging.Backends.CodeBuild.View(ctx, func(tx codebuild.Reader) error {
		sc := codebuild.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		fleetPrefix := strings.TrimSuffix(codebuild.FleetKey{Scope: sc}.ARN(""), ":")
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			switch request.Type {
			case "AWS::CodeBuild::Project":
				key := codebuild.ProjectKey{Scope: sc, Name: request.PhysicalID}
				if key.ARN() != candidate {
					continue
				}
				row, err := tx.Project(key)
				if errors.Is(err, codebuild.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if row.Key == key {
					owners.claim(candidate, row.Ownership, cfnDeveloperClaim)
				}
			case "AWS::CodeBuild::Fleet":
				// A fleet's physical identity is its exact incarnation ARN (fleet/name:id).
				if request.PhysicalID != candidate || !strings.HasPrefix(candidate, fleetPrefix) {
					continue
				}
				name, id, ok := strings.Cut(strings.TrimPrefix(candidate, fleetPrefix), ":")
				key := codebuild.FleetKey{Scope: sc, Name: name}
				if !ok || name == "" || id == "" || key.ARN(id) != candidate {
					continue
				}
				row, err := tx.Fleet(key)
				if errors.Is(err, codebuild.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if row.Key == key && resourceTaggingText(row.Data.Arn) == candidate {
					owners.claim(candidate, row.Ownership, cfnDeveloperClaim)
				}
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataSchedulerOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::Scheduler::ScheduleGroup") || r.Tagging.Backends.Scheduler == nil {
		return nil
	}
	return r.Tagging.Backends.Scheduler.View(ctx, func(tx scheduler.Reader) error {
		sc := scheduler.Scope{Partition: scope.Partition, Account: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			// The implicit default group carries no claim and stays absent.
			if request.Scope != scope || request.Type != "AWS::Scheduler::ScheduleGroup" {
				continue
			}
			key := scheduler.GroupKey{Scope: sc, Name: request.PhysicalID}
			if key.ARN() != candidate {
				continue
			}
			row, err := tx.Group(key)
			if errors.Is(err, scheduler.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if row.Key == key {
				owners.claim(candidate, row.CFNOwner, cfnMessagingMarker)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateDataPipesOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::Pipes::Pipe") || r.Tagging.Backends.Pipes == nil {
		return nil
	}
	return r.Tagging.Backends.Pipes.View(ctx, func(tx pipes.Reader) error {
		sc := pipes.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			if request.Scope != scope || request.Type != "AWS::Pipes::Pipe" {
				continue
			}
			key := pipes.Key{Scope: sc, Name: request.PhysicalID}
			if key.ARN() != candidate {
				continue
			}
			row, err := tx.Pipe(key)
			if errors.Is(err, pipes.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if row.Key == key {
				owners.claim(candidate, row.CFNOwner, cfnMessagingMarker)
			}
		}
		return nil
	})
}
