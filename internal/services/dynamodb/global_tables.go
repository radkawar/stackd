package dynamodb

import (
	"context"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awscatalog"
)

const legacyGlobalTablesUnavailable = "DynamoDB global tables version 2017.11.29 is not supported. We recommend using DynamoDB global tables version 2019.11.21, instead of version 2017.11.29 (Legacy)."

// AWS no longer admits new legacy groups, even with valid existing replicas.
// These APIs do not expose or change current-version UpdateTable groups. See
// testdata/aws/dynamodb/legacy_global_{controls,data}.json for native evidence.
func (s *Service) createGlobalTable(ctx context.Context, tx Transaction, in *api.CreateGlobalTableInput) (*api.CreateGlobalTableOutput, error) {
	name := value(in.GlobalTableName)
	if err := s.authorize(ctx, "CreateGlobalTable", globalTableARN(ctx, name), nil); err != nil {
		return nil, err
	}
	if len(in.ReplicationGroup) == 0 {
		return nil, invalidTable("Global table must have atleast one replica")
	}
	for _, replica := range in.ReplicationGroup {
		if replica.RegionName == nil {
			return nil, invalidTable("ReplicationGroup members must specify RegionName")
		}
		if err := s.authorizeGlobalReplica(ctx, tx, "CreateGlobalTable", name, value(replica.RegionName)); err != nil {
			return nil, err
		}
	}
	for _, replica := range in.ReplicationGroup {
		if err := legacyGlobalRegion(value(replica.RegionName)); err != nil {
			return nil, err
		}
	}
	return nil, invalidTable(legacyGlobalTablesUnavailable)
}

func (s *Service) describeGlobalTable(ctx context.Context, _ Transaction, in *api.DescribeGlobalTableInput) (*api.DescribeGlobalTableOutput, error) {
	name := value(in.GlobalTableName)
	if err := s.authorize(ctx, "DescribeGlobalTable", globalTableARN(ctx, name), nil); err != nil {
		return nil, err
	}
	return nil, globalTableNotFound(name)
}

func (s *Service) listGlobalTables(ctx context.Context, _ Transaction, in *api.ListGlobalTablesInput) (*api.ListGlobalTablesOutput, error) {
	if err := s.authorize(ctx, "ListGlobalTables", globalTableARN(ctx, "*"), nil); err != nil {
		return nil, err
	}
	if in.RegionName != nil && awscatalog.RegionPartition(value(in.RegionName)) == "" {
		return nil, failure("InternalServerError", "Internal server error", 500)
	}
	return &api.ListGlobalTablesOutput{GlobalTables: api.GlobalTableList{}}, nil
}

func (s *Service) updateGlobalTable(ctx context.Context, tx Transaction, in *api.UpdateGlobalTableInput) (*api.UpdateGlobalTableOutput, error) {
	name := value(in.GlobalTableName)
	if err := s.authorize(ctx, "UpdateGlobalTable", globalTableARN(ctx, name), nil); err != nil {
		return nil, err
	}
	if len(in.ReplicaUpdates) == 0 {
		return nil, failure("ValidationException", "One or more parameter values were invalid")
	}
	create := false
	for _, update := range in.ReplicaUpdates {
		if update.Create != nil && update.Delete != nil {
			return nil, invalidTable("A ReplicaUpdate structure cannot contain both a create replica action and a delete replica action")
		}
		var region string
		switch {
		case update.Create != nil:
			region, create = value(update.Create.RegionName), true
		case update.Delete != nil:
			region = value(update.Delete.RegionName)
		default:
			return nil, failure("ValidationException", "One or more parameter values were invalid")
		}
		if err := s.authorizeGlobalReplica(ctx, tx, "UpdateGlobalTable", name, region); err != nil {
			return nil, err
		}
		if awscatalog.RegionPartition(region) == "" {
			return nil, invalidTable("Invalid AWS Region: " + region)
		}
	}
	// Create admission precedes both legacy lookup and Delete-region availability.
	if create {
		return nil, invalidTable(legacyGlobalTablesUnavailable)
	}
	for _, update := range in.ReplicaUpdates {
		if err := legacyGlobalRegion(value(update.Delete.RegionName)); err != nil {
			return nil, err
		}
	}
	return nil, globalTableNotFound(name)
}

func globalTableARN(ctx context.Context, name string) string {
	scope := scopeFor(ctx)
	return "arn:" + scope.Partition + ":dynamodb::" + scope.AccountID + ":global-table/" + name
}

func globalTableNotFound(name string) error {
	return failure("GlobalTableNotFoundException", "Global table not found: Global table with name: '"+name+"' does not exist.")
}

func (s *Service) authorizeGlobalReplica(ctx context.Context, r Reader, action, name, region string) error {
	key := TableKey{Scope: scopeFor(ctx), Name: name}
	key.Region = region
	return s.authorizeTable(ctx, r, key, action, "", nil)
}

// Legacy availability is a fixed retired-service boundary, not the current
// account Region catalogue. AWS still checks it for creation and removal.
func legacyGlobalRegion(region string) error {
	switch region {
	case "eu-west-2", "eu-west-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-2", "eu-central-1", "ap-northeast-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2":
		return nil
	default:
		return invalidTable("DynamoDB global tables version 2017.11.29 is not supported in this Region: " + region)
	}
}
