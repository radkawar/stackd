package integrations

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	ec2api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/iam"
	"stackd/internal/services/lambda"
	"stackd/internal/services/s3"
	"stackd/internal/services/sqs"
	"stackd/storage"
	"stackd/storage/sqlite"
	sqlbackends "stackd/storage/sqlite/backends"
)

// Stack membership is proved by typed native private claims in real memory and
// SQLite repositories. Public markers are removed from owned rows and forged on
// unclaimed or recreated rows; neither changes membership.
func TestResourceGroupsStackMembershipUsesNativePrivateOwners(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			at := time.Date(2036, 2, 3, 4, 5, 6, 0, time.UTC)
			path := filepath.Join(t.TempDir(), "members.sqlite")
			var backends *storage.Backends
			open := func() {
				t.Helper()
				if backend == "memory" {
					if backends == nil {
						backends = storage.NewMemory()
					}
					return
				}
				db, err := sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				if backends, err = sqlbackends.New(ctx, db); err != nil {
					t.Fatal(err)
				}
			}
			open()
			scope := cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
			stackID := "arn:aws:cloudformation:us-east-1:123456789012:stack/members/11111111-1111-1111-1111-111111111111"
			request := func(kind, logicalID string) cloudformation.ResourceRequest {
				return cloudformation.ResourceRequest{Type: kind, StackID: stackID, StackName: "members", LogicalID: logicalID, Token: logicalID + "-token", Scope: scope}
			}
			forged := func(r cloudformation.ResourceRequest) map[string]string {
				tags := cfnComputeOwnedTags(r)
				tags["stackd:cloudformation:owner"] = cfnMessagingMarker(r)
				return tags
			}
			var ledger []cloudformation.ResourceRecord
			candidate := func(r cloudformation.ResourceRequest, physicalID, resourceARN string) {
				record := cloudformation.ResourceRecord{StackID: stackID, LogicalID: r.LogicalID, Type: r.Type, PhysicalID: physicalID, Ref: physicalID, Token: r.Token, Generation: 1, Current: true, Status: "CREATE_COMPLETE", Updated: at}
				if resourceARN != "" {
					record.Attributes = map[string]any{"Arn": resourceARN}
				}
				ledger = append(ledger, record)
			}
			update := func(name string, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
			}

			// S3: exact claim, unclaimed forged row, and a claim for another token.
			ownedBucket, forgedBucket, staleBucket := request("AWS::S3::Bucket", "OwnedBucket"), request("AWS::S3::Bucket", "ForgedBucket"), request("AWS::S3::Bucket", "StaleBucket")
			staleClaim := staleBucket
			staleClaim.Token = "earlier-token"
			buckets := []struct {
				r     cloudformation.ResourceRequest
				name  string
				claim string
			}{{ownedBucket, "owned-bucket", cfnS3Claim(ownedBucket)}, {forgedBucket, "forged-bucket", ""}, {staleBucket, "stale-bucket", cfnS3Claim(staleClaim)}}
			update("s3", backends.S3.Update(ctx, func(tx s3.Transaction) error {
				for _, row := range buckets {
					key := s3.BucketKey{Partition: "aws", Name: row.name}
					if err := tx.PutBucket(s3.BucketRecord{Key: key, AccountID: "123456789012", Region: "us-east-1", Incarnation: row.name + "-1", CloudFormationOwner: row.claim, Created: at}); err != nil {
						return err
					}
					var tags []s3.Tag
					if row.claim == "" || row.r.LogicalID == "StaleBucket" {
						for k, v := range forged(row.r) {
							tags = append(tags, s3.Tag{Key: k, Value: v})
						}
					}
					if err := tx.ReplaceBucketTags(key, tags); err != nil {
						return err
					}
				}
				return nil
			}))
			for _, row := range buckets {
				candidate(row.r, row.name, "arn:aws:s3:::"+row.name)
			}

			// SQS: queue creation owner is private; customer tags are ordinary metadata.
			ownedQueue, forgedQueue := request("AWS::SQS::Queue", "OwnedQueue"), request("AWS::SQS::Queue", "ForgedQueue")
			queueTags := func(tags map[string]string) []sqs.QueueTag {
				out := []sqs.QueueTag{{Key: "team", Value: "blue"}}
				for k, v := range tags {
					out = append(out, sqs.QueueTag{Key: k, Value: v})
				}
				return out
			}
			update("sqs", backends.SQS.Update(ctx, func(tx sqs.Transaction) error {
				if err := tx.PutQueue(sqs.QueueRecord{Key: sqs.QueueKey{Partition: "aws", Account: "123456789012", Region: "us-east-1", Name: "owned-queue"}, ID: "queue-owned-1", CreationOwner: cfnSQSOwner(ownedQueue), Tags: queueTags(nil), Created: at, Modified: at}); err != nil {
					return err
				}
				return tx.PutQueue(sqs.QueueRecord{Key: sqs.QueueKey{Partition: "aws", Account: "123456789012", Region: "us-east-1", Name: "forged-queue"}, ID: "queue-forged-1", Tags: queueTags(forged(forgedQueue)), Created: at, Modified: at})
			}))
			candidate(ownedQueue, "https://sqs.us-east-1.amazonaws.com/123456789012/owned-queue", "arn:aws:sqs:us-east-1:123456789012:owned-queue")
			candidate(forgedQueue, "https://sqs.us-east-1.amazonaws.com/123456789012/forged-queue", "arn:aws:sqs:us-east-1:123456789012:forged-queue")

			// Lambda: function owner plus the existing qualified alias owner path.
			ownedFunction, forgedFunction := request("AWS::Lambda::Function", "OwnedFunction"), request("AWS::Lambda::Function", "ForgedFunction")
			ownedAlias, forgedAlias := request("AWS::Lambda::Alias", "OwnedAlias"), request("AWS::Lambda::Alias", "ForgedAlias")
			lambdaScope := lambda.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
			ownedKey, forgedKey := lambda.FunctionKey{Scope: lambdaScope, Name: "owned-function"}, lambda.FunctionKey{Scope: lambdaScope, Name: "forged-function"}
			update("lambda", backends.Lambda.Update(ctx, func(tx lambda.Transaction) error {
				if err := tx.PutFunction(lambda.FunctionRecord{Key: ownedKey, Runtime: "python3.12", Handler: "index.handler", Owner: lambda.FunctionOwner{StackID: stackID, LogicalID: ownedFunction.LogicalID, Token: ownedFunction.Token}, Tags: map[string]string{"team": "blue"}, Revision: "owned", DeploymentRevision: "owned", State: "Active", Modified: at}); err != nil {
					return err
				}
				if err := tx.PutFunction(lambda.FunctionRecord{Key: forgedKey, Runtime: "python3.12", Handler: "index.handler", Tags: forged(forgedFunction), Revision: "forged", DeploymentRevision: "forged", State: "Active", Modified: at}); err != nil {
					return err
				}
				if err := tx.PutAlias(lambda.AliasRecord{Key: lambda.FunctionReference{FunctionKey: ownedKey, Qualifier: "live"}, Revision: "live", Owner: lambda.AliasOwner{StackID: stackID, LogicalID: ownedAlias.LogicalID, Token: ownedAlias.Token}}); err != nil {
					return err
				}
				return tx.PutAlias(lambda.AliasRecord{Key: lambda.FunctionReference{FunctionKey: ownedKey, Qualifier: "forged"}, Revision: "forged"})
			}))
			candidate(ownedFunction, "owned-function", ownedKey.ARN())
			candidate(forgedFunction, "forged-function", forgedKey.ARN())
			candidate(ownedAlias, ownedKey.ARN()+":live", "")
			candidate(forgedAlias, ownedKey.ARN()+":forged", "")

			// EventBridge rules on the default bus.
			ownedRule, forgedRule := request("AWS::Events::Rule", "OwnedRule"), request("AWS::Events::Rule", "ForgedRule")
			bus := eventbridge.BusKey{Scope: eventbridge.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Name: "default"}
			update("eventbridge", backends.EventBridge.Update(ctx, func(tx eventbridge.Transaction) error {
				if err := tx.PutBus(eventbridge.BusRecord{Key: bus, Created: at, Modified: at}); err != nil {
					return err
				}
				if err := tx.PutRule(eventbridge.RuleRecord{Key: eventbridge.RuleKey{Bus: bus, Name: "owned-rule"}, CFNOwner: cfnMessagingMarker(ownedRule), State: "ENABLED", ScheduleExpression: "rate(1 hour)", HasScheduleExpression: true}); err != nil {
					return err
				}
				return tx.PutRule(eventbridge.RuleRecord{Key: eventbridge.RuleKey{Bus: bus, Name: "forged-rule"}, State: "ENABLED", ScheduleExpression: "rate(1 hour)", HasScheduleExpression: true, Tags: forged(forgedRule)})
			}))
			candidate(ownedRule, "owned-rule", "arn:aws:events:us-east-1:123456789012:rule/owned-rule")
			candidate(forgedRule, "forged-rule", "arn:aws:events:us-east-1:123456789012:rule/forged-rule")

			// EC2 claims are admitted by native creation, never ordinary repository Put.
			ownedVPC, forgedVPC, otherFamilyVPC, staleVPC := request("AWS::EC2::VPC", "OwnedVpc"), request("AWS::EC2::VPC", "ForgedVpc"), request("AWS::EC2::VPC", "OtherFamilyVpc"), request("AWS::EC2::VPC", "StaleVpc")
			ec2Scope := ec2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
			network := ec2.New(ec2.Config{Repository: backends.EC2})
			t.Cleanup(func() { _ = network.Close() })
			vpcHandler := cfnEC2VPC{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": network})}
			ownedVPC.Properties = cloudformation.Properties{"CidrBlock": "10.0.0.0/16"}
			ownedVPCResult, err := vpcHandler.Create(ctx, ownedVPC)
			if err != nil {
				t.Fatal(err)
			}
			ownedVPC.PhysicalID = ownedVPCResult.PhysicalID
			ownedVPCARN := "arn:aws:ec2:us-east-1:123456789012:vpc/" + ownedVPC.PhysicalID
			staleVPCClaim := staleVPC
			staleVPCClaim.Token = "earlier-token"
			staleVPCClaim.Properties = cloudformation.Properties{"CidrBlock": "10.1.0.0/16"}
			staleVPCResult, err := vpcHandler.Create(ctx, staleVPCClaim)
			if err != nil {
				t.Fatal(err)
			}
			vpcTags := func(tags map[string]string) ec2api.TagList {
				var out ec2api.TagList
				for k, v := range tags {
					out = append(out, ec2api.Tag{Key: new(ec2api.String(k)), Value: new(ec2api.String(v))})
				}
				return out
			}
			update("ec2", backends.EC2.Update(ctx, func(tx ec2.Transaction) error {
				// Removing all public tags must retain the native creation claim.
				key := ec2.ResourceKey{Scope: ec2Scope, ID: ownedVPC.PhysicalID}
				live, err := tx.VPC(key)
				if err != nil {
					return err
				}
				live.Data.Tags = nil
				if err := tx.PutVPC(live); err != nil {
					return err
				}
				for _, row := range []struct {
					id    string
					owner ec2.CloudFormationOwner
					tags  map[string]string
				}{
					{"vpc-ffffffffffffffffe", ec2.CloudFormationOwner{}, forged(forgedVPC)},
					{"vpc-ffffffffffffffffd", ec2.CloudFormationOwner{ResourceType: "AWS::EC2::Subnet", Owner: cfnEC2NativeIdentity(otherFamilyVPC)}, forged(otherFamilyVPC)},
				} {
					if err := tx.PutVPC(ec2.VPCRecord{Key: ec2.ResourceKey{Scope: ec2Scope, ID: row.id}, CloudFormationOwner: row.owner, Data: ec2api.Vpc{VpcId: new(ec2api.String(row.id)), CidrBlock: new(ec2api.String("10.0.0.0/16")), Tags: vpcTags(row.tags)}}); err != nil {
						return err
					}
				}
				return nil
			}))
			candidate(ownedVPC, ownedVPCResult.PhysicalID, "")
			candidate(forgedVPC, "vpc-ffffffffffffffffe", "")
			candidate(otherFamilyVPC, "vpc-ffffffffffffffffd", "")
			candidate(staleVPC, staleVPCResult.PhysicalID, "")

			// IAM identity: the private owner is retained beside the role, never in tags.
			ownedRole, forgedRole := request("AWS::IAM::Role", "OwnedRole"), request("AWS::IAM::Role", "ForgedRole")
			iamScope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			role := func(name, claim string, tags map[string]string) iam.Role {
				row := iam.Role{Path: "/", RoleName: name, RoleId: "AROA" + name, Arn: "arn:aws:iam::123456789012:role/" + name, CreateDate: at, AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[]}`, MaxSessionDuration: 3600}
				row.CloudFormationOwner = claim
				for k, v := range tags {
					row.Tags = append(row.Tags, iam.Tag{Key: k, Value: v})
				}
				return row
			}
			update("iam", backends.IAM.Update(ctx, func(tx iam.WriteTx) error {
				if err := tx.PutRole(iamScope, role("owned-role", cfnIAMPolicyOwner(ownedRole), nil)); err != nil {
					return err
				}
				return tx.PutRole(iamScope, role("forged-role", "", forged(forgedRole)))
			}))
			candidate(ownedRole, "owned-role", "arn:aws:iam::123456789012:role/owned-role")
			candidate(forgedRole, "forged-role", "arn:aws:iam::123456789012:role/forged-role")

			// AppConfig resources are TAG_FILTERS-only; a ledger candidate and forged
			// marker can never make one a CloudFormation stack member.
			if _, stackEligible := resourceGroupsEligibility("AWS::AppConfig::Application"); stackEligible {
				t.Fatal("AppConfig application unexpectedly became stack-query eligible")
			}
			candidate(request("AWS::AppConfig::Application", "TagOnlyApplication"), "abc1234", "arn:aws:appconfig:us-east-1:123456789012:application/abc1234")

			update("cloudformation", backends.CloudFormation.Update(ctx, func(tx cloudformation.Transaction) error {
				if err := tx.PutStack(cloudformation.StackRecord{Scope: scope, ID: stackID, Name: "members", Status: "CREATE_COMPLETE", Created: at, Updated: at}); err != nil {
					return err
				}
				for _, row := range ledger {
					if err := tx.PutResource(row); err != nil {
						return err
					}
				}
				return nil
			}))

			discover := func() []string {
				t.Helper()
				out, err := (ResourceGroupsResources{Tagging: ResourceTaggingResources{Backends: backends}}).Stack(ctx, "members")
				if err != nil || out.ARN != stackID {
					t.Fatalf("stack discovery failed: %+v %v", out, err)
				}
				arns := make([]string, 0, len(out.Resources))
				for _, row := range out.Resources {
					arns = append(arns, row.ARN)
				}
				return arns
			}
			want := []string{
				ownedVPCARN,
				"arn:aws:events:us-east-1:123456789012:rule/owned-rule",
				"arn:aws:iam::123456789012:role/owned-role",
				ownedKey.ARN(),
				ownedKey.ARN() + ":live",
				"arn:aws:s3:::owned-bucket",
				"arn:aws:sqs:us-east-1:123456789012:owned-queue",
			}
			if got := discover(); !slices.Equal(got, want) {
				t.Fatalf("private owner membership = %v; want %v", got, want)
			}

			// Native delete/recreate keeps the same public identity and ledger token,
			// and copies forged public markers; the new native rows are foreign.
			update("ec2 recreate", backends.EC2.Update(ctx, func(tx ec2.Transaction) error {
				key := ec2.ResourceKey{Scope: ec2Scope, ID: ownedVPC.PhysicalID}
				if err := tx.DeleteVPC(key); err != nil {
					return err
				}
				return tx.PutVPC(ec2.VPCRecord{Key: key, Data: ec2api.Vpc{VpcId: new(ec2api.String(key.ID)), CidrBlock: new(ec2api.String("10.0.0.0/16")), Tags: vpcTags(forged(ownedVPC))}})
			}))
			update("s3 recreate", backends.S3.Update(ctx, func(tx s3.Transaction) error {
				key := s3.BucketKey{Partition: "aws", Name: "owned-bucket"}
				if err := tx.DeleteBucket(key); err != nil {
					return err
				}
				if err := tx.PutBucket(s3.BucketRecord{Key: key, AccountID: "123456789012", Region: "us-east-1", Incarnation: "owned-bucket-2", Created: at}); err != nil {
					return err
				}
				var tags []s3.Tag
				for k, v := range forged(ownedBucket) {
					tags = append(tags, s3.Tag{Key: k, Value: v})
				}
				return tx.ReplaceBucketTags(key, tags)
			}))
			update("sqs recreate", backends.SQS.Update(ctx, func(tx sqs.Transaction) error {
				key := sqs.QueueKey{Partition: "aws", Account: "123456789012", Region: "us-east-1", Name: "owned-queue"}
				if err := tx.DeleteQueue(key); err != nil {
					return err
				}
				return tx.PutQueue(sqs.QueueRecord{Key: key, ID: "queue-owned-2", Tags: queueTags(forged(ownedQueue)), Created: at, Modified: at})
			}))
			update("iam recreate", backends.IAM.Update(ctx, func(tx iam.WriteTx) error {
				if err := tx.DeleteRole(iamScope, "owned-role"); err != nil {
					return err
				}
				return tx.PutRole(iamScope, role("owned-role", "", forged(ownedRole)))
			}))
			if backend == "sqlite" {
				open()
			}
			want = []string{
				"arn:aws:events:us-east-1:123456789012:rule/owned-rule",
				ownedKey.ARN(),
				ownedKey.ARN() + ":live",
			}
			if got := discover(); !slices.Equal(got, want) {
				t.Fatalf("native recreation retained stack membership: %v; want %v", got, want)
			}
		})
	}
}
