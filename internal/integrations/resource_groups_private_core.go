package integrations

import (
	"context"
	"errors"
	"math"
	"strings"

	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cognitoidp"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/kms"
	"stackd/internal/services/lambda"
	"stackd/internal/services/logs"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
	"stackd/internal/services/s3"
	"stackd/internal/services/secretsmanager"
	"stackd/internal/services/sns"
	"stackd/internal/services/sqs"
	"stackd/internal/services/ssm"
	"stackd/internal/services/ssmdocuments"
	"stackd/internal/services/stepfunctions"
)

func (r ResourceGroupsResources) privateCoreOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	b := r.Tagging.Backends
	sc := tagging.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
	// Each family's ledger PhysicalID must name the claimed native row itself.
	same := func(resourceARN, id string) bool {
		request, found := owners.requests[resourceARN]
		return found && id != "" && request.PhysicalID == id
	}
	if owners.needs("AWS::S3::Bucket", "AWS::S3::AccessPoint") {
		if err := b.S3.View(ctx, func(tx s3.Reader) error {
			if owners.needs("AWS::S3::Bucket") {
				rows, err := tx.Buckets(scope.Partition, scope.Account)
				if err != nil {
					return err
				}
				for _, row := range rows {
					if row.AccountID == scope.Account && row.Region == scope.Region && row.Key.Partition == scope.Partition && same(row.Key.ARN(), row.Key.Name) {
						owners.claim(row.Key.ARN(), row.CloudFormationOwner, cfnS3Claim)
					}
				}
			}
			if owners.needs("AWS::S3::AccessPoint") {
				rows, err := tx.AccessPoints(s3.AccessPointQuery{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, Limit: math.MaxInt})
				if err != nil {
					return err
				}
				for _, row := range rows {
					if row.Key.Partition == scope.Partition && row.Key.AccountID == scope.Account && row.Key.Region == scope.Region && same(row.Key.ARN(), row.Key.Name) {
						owners.claim(row.Key.ARN(), row.CloudFormationOwner, cfnS3Claim)
					}
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::SQS::Queue") {
		if err := b.SQS.View(ctx, func(tx sqs.Reader) error {
			rows, err := tx.Queues()
			if err != nil {
				return err
			}
			for _, row := range rows {
				resourceARN := resourceTaggingARN(sc, "sqs", row.Key.Name)
				request := owners.requests[resourceARN]
				if row.Key.Partition == scope.Partition && row.Key.Account == scope.Account && row.Key.Region == scope.Region && strings.HasSuffix(request.PhysicalID, "/"+scope.Account+"/"+row.Key.Name) {
					owners.claim(resourceARN, row.CreationOwner, cfnSQSOwner)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::SNS::Topic") {
		if err := b.SNS.View(ctx, func(tx sns.Reader) error {
			rows, err := tx.Topics(sns.TopicQuery{Scope: sns.Scope(sc), Limit: math.MaxInt})
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Key.Scope != sns.Scope(sc) || !same(row.Key.ARN(), row.Key.ARN()) || row.CreationOwner.Owner == "" || row.CreationOwner.Token == "" {
					continue
				}
				owners.claim(row.Key.ARN(), row.CreationOwner.Owner+":"+row.CreationOwner.Token, cfnMessagingMarker)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::Lambda::Function", "AWS::Lambda::EventSourceMapping") {
		if err := b.Lambda.View(ctx, func(tx lambda.Reader) error {
			ls := lambda.Scope{Partition: scope.Partition, Account: scope.Account, Region: scope.Region}
			if owners.needs("AWS::Lambda::Function") {
				rows, err := tx.Functions(ls)
				if err != nil {
					return err
				}
				for _, row := range rows {
					if row.Key.Scope == ls && same(row.Key.ARN(), row.Key.Name) {
						owners.structured(row.Key.ARN(), row.Owner.StackID, row.Owner.LogicalID, row.Owner.Token)
					}
				}
			}
			if owners.needs("AWS::Lambda::EventSourceMapping") {
				rows, err := tx.EventSourceMappings(ls)
				if err != nil {
					return err
				}
				for _, row := range rows {
					if row.Key.Scope == ls && same(row.Key.ARN(), row.Key.UUID) {
						owners.structured(row.Key.ARN(), row.Owner.StackID, row.Owner.LogicalID, row.Owner.Token)
					}
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::Events::EventBus", "AWS::Events::Rule") {
		if err := b.EventBridge.View(ctx, func(tx eventbridge.Reader) error {
			rows, err := tx.Buses(eventbridge.Scope{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Key.Scope != (eventbridge.Scope{Partition: scope.Partition, Account: scope.Account, Region: scope.Region}) {
					continue
				}
				if busARN := resourceTaggingARN(sc, "events", "event-bus/"+row.Key.Name); same(busARN, row.Key.Name) {
					owners.claim(busARN, row.CFNOwner, cfnMessagingMarker)
				}
				if !owners.needs("AWS::Events::Rule") {
					continue
				}
				rules, err := tx.Rules(row.Key)
				if err != nil {
					return err
				}
				for _, rule := range rules {
					if rule.Key.Bus != row.Key {
						continue
					}
					path, id := rule.Key.Name, rule.Key.Name
					if row.Key.Name != "default" {
						path, id = row.Key.Name+"/"+path, row.Key.Name+"|"+id
					}
					if ruleARN := resourceTaggingARN(sc, "events", "rule/"+path); same(ruleARN, id) {
						owners.claim(ruleARN, rule.CFNOwner, cfnMessagingMarker)
					}
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::Logs::LogGroup", "AWS::Logs::Destination") {
		if err := b.Logs.View(ctx, func(tx logs.Reader) error {
			if owners.needs("AWS::Logs::LogGroup") {
				rows, err := tx.Groups(logs.GroupQuery{Scope: logs.Scope(sc), Limit: math.MaxInt})
				if err != nil {
					return err
				}
				for _, row := range rows {
					if row.Key.Scope == logs.Scope(sc) && same(row.Key.ARN(), row.Key.Name) {
						owners.claim(row.Key.ARN(), row.CFNOwner, cfnLogsMarker)
					}
				}
			}
			if owners.needs("AWS::Logs::Destination") {
				rows, err := tx.Destinations(logs.DestinationQuery{Scope: logs.Scope(sc), Limit: math.MaxInt})
				if err != nil {
					return err
				}
				for _, row := range rows {
					if row.Key.Scope == logs.Scope(sc) && same(row.Key.ARN(), row.Key.Name) {
						owners.claim(row.Key.ARN(), row.CFNOwner, cfnLogsMarker)
					}
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::KMS::Key", "AWS::KMS::ReplicaKey") {
		if err := b.KMS.View(ctx, func(tx kms.Reader) error {
			rows, err := tx.Keys(kms.StorageScope(sc))
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Manager == "CUSTOMER" && same(row.ARN, row.ID) {
					owners.structured(row.ARN, row.Owner.StackID, row.Owner.LogicalID, row.Owner.Token)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::SSM::Parameter") {
		if err := b.SSM.View(ctx, func(tx ssm.Reader) error {
			rows, err := tx.Parameters(ssm.Scope(sc))
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Key.Scope == ssm.Scope(sc) && same(row.ARN, row.Key.Name) {
					owners.claim(row.ARN, row.CloudFormationOwner, cfnSSMClaim)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::SSM::Document") {
		if err := b.SSMDocuments.View(ctx, func(tx ssmdocuments.Reader) error {
			rows, err := tx.Documents(ssmdocuments.Scope(sc))
			if err != nil {
				return err
			}
			for _, row := range rows {
				if documentARN := resourceTaggingARN(sc, "ssm", "document/"+row.Key.Name); row.Key.Scope == ssmdocuments.Scope(sc) && same(documentARN, row.Key.Name) {
					owners.claim(documentARN, row.CloudFormationOwner, cfnSSMClaim)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::SecretsManager::Secret") {
		if err := b.SecretsManager.View(ctx, func(tx secretsmanager.Reader) error {
			rows, err := tx.Secrets(secretsmanager.Scope(sc))
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Key.Scope != secretsmanager.Scope(sc) || row.Deleted != nil || !same(row.ARN, row.ARN) || row.Ownership.Owner == "" || row.Ownership.Token == "" {
					continue
				}
				owners.claim(row.ARN, row.Ownership.Owner+":"+row.Ownership.Token, cfnMessagingMarker)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::StepFunctions::StateMachine", "AWS::StepFunctions::Activity") {
		if err := b.StepFunctions.View(ctx, func(tx stepfunctions.Reader) error {
			if owners.needs("AWS::StepFunctions::StateMachine") {
				rows, err := tx.Machines(stepfunctions.Scope(sc))
				if err != nil {
					return err
				}
				for _, row := range rows {
					if machineARN := resourceTaggingARN(sc, "states", "stateMachine:"+row.Key.Name); row.Key.Scope == stepfunctions.Scope(sc) && same(machineARN, machineARN) {
						owners.claim(machineARN, row.CFNOwner, cfnMessagingMarker)
					}
				}
			}
			if owners.needs("AWS::StepFunctions::Activity") {
				rows, err := tx.Activities(stepfunctions.Scope(sc))
				if err != nil {
					return err
				}
				for _, row := range rows {
					if activityARN := resourceTaggingARN(sc, "states", "activity:"+row.Key.Name); row.Key.Scope == stepfunctions.Scope(sc) && same(activityARN, activityARN) {
						owners.claim(activityARN, row.CFNOwner, cfnMessagingMarker)
					}
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::Cognito::UserPool") {
		if err := b.CognitoIDP.View(ctx, func(tx cognitoidp.Reader) error {
			for resourceARN, request := range owners.requests {
				if request.Type != "AWS::Cognito::UserPool" {
					continue
				}
				claim, err := tx.PoolOwnership(cognitoidp.Scope(sc), cognitoidp.ResourceOwner{StackID: request.StackID, LogicalID: request.LogicalID, Token: request.Token})
				if errors.Is(err, cognitoidp.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				pool, err := tx.Pool(claim.Key.PoolKey)
				if errors.Is(err, cognitoidp.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if claim.Key.Kind == cognitoidp.OwnerKindPool && claim.PhysicalID == pool.Key.ID && pool.Key.Scope == cognitoidp.Scope(sc) && pool.Key.ARN() == resourceARN && request.PhysicalID == pool.Key.ID {
					owners.structured(resourceARN, claim.Owner.StackID, claim.Owner.LogicalID, claim.Owner.Token)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
