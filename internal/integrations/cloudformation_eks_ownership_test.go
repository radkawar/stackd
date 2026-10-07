package integrations

import (
	"database/sql"
	"errors"
	"maps"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	eksapi "stackd/internal/awsapi/eks"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/eks"
	"stackd/internal/services/iam"
	"stackd/storage/sqlite"
	eksdb "stackd/storage/sqlite/eks"
)

// Real EKS and IAM owners exercise the deterministic native control paths.
// The retained cluster control-state fixture is not a guest/readiness assertion.
func TestCloudFormationEKSNativeControlPrivateOwnership(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{cfnEKSAccessEntryType, cfnEKSPodIdentityType} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
				identity := iam.NewWithConfig(iam.Config{})
				t.Cleanup(func() { _ = identity.Close() })
				repo := eks.Repository(eks.NewMemoryRepository(nil))
				var db *sql.DB
				path := filepath.Join(t.TempDir(), "eks.sqlite")
				open := func() {
					var err error
					db, err = sqlite.Open(root, path)
					if err != nil {
						t.Fatal(err)
					}
					repo = eksdb.New(db)
				}
				if backend == "sqlite" {
					open()
					t.Cleanup(func() { _ = db.Close() })
				}
				key := eks.Key{Scope: eks.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "native-controls"}
				if err := repo.Update(root, func(tx eks.Transaction) error {
					return tx.PutCluster(eks.Cluster{Key: key, ID: "retained-control-incarnation", Status: "ACTIVE", AuthenticationMode: "API", KubernetesVersion: "1.33"})
				}); err != nil {
					t.Fatal(err)
				}
				manual := clock.NewManual(time.Unix(123456, 0))
				var service *eks.Service
				var commands StepFunctionsCommands
				start := func() {
					service = eks.New(eks.Config{Repository: repo, Authorizer: authorization.New(identity, nil), Principals: EKSPrincipals{IAM: identity}, Clock: manual})
					commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"eks": service, "iam": identity})
				}
				start()
				t.Cleanup(func() { _ = service.Close() })
				user, err := cfnComputeCall[iamapi.CreateUserResponse](root, commands, "iam", "CreateUser", map[string]any{"UserName": "application"})
				if err != nil {
					t.Fatal(err)
				}
				actorUser, err := cfnComputeCall[iamapi.CreateUserResponse](root, commands, "iam", "CreateUser", map[string]any{"UserName": "deployer"})
				if err != nil {
					t.Fatal(err)
				}
				role, err := cfnComputeCall[iamapi.CreateRoleResponse](root, commands, "iam", "CreateRole", map[string]any{"RoleName": "pod-role", "AssumeRolePolicyDocument": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}]}`})
				if err != nil {
					t.Fatal(err)
				}
				actor := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: cfnComputeValue(actorUser.User.Arn), PrincipalID: cfnComputeValue(actorUser.User.UserId)})
				policy := func(document string) {
					t.Helper()
					if err := cfnComputeRun(root, commands, "iam", "PutUserPolicy", map[string]any{"UserName": "deployer", "PolicyName": "eks-current", "PolicyDocument": document}); err != nil {
						t.Fatal(err)
					}
				}
				policy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["eks:*","iam:PassRole"],"Resource":"*"}]}`)
				r := cloudformation.ResourceRequest{Scope: cloudformation.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Type: kind, StackID: "arn:aws:cloudformation:us-east-1:111111111111:stack/native/1", LogicalID: "Resource", Token: "incarnation-1", Tags: map[string]string{"team": "native"}, Properties: cloudformation.Properties{"ClusterName": key.Name}}
				var handler cloudformation.ResourceHandler
				if kind == cfnEKSAccessEntryType {
					r.Properties["PrincipalArn"] = cfnComputeValue(user.User.Arn)
					r.Properties["KubernetesGroups"] = []any{"developers"}
					handler = cfnEKSAccessEntry{commands}
				} else {
					r.Properties["Namespace"] = "default"
					r.Properties["ServiceAccount"] = "application"
					r.Properties["RoleArn"] = cfnComputeValue(role.Role.Arn)
					handler = cfnEKSPodIdentity{commands}
				}
				result, err := handler.Create(actor, r)
				if err != nil {
					t.Fatal(err)
				}
				r.PhysicalID = result.PhysicalID
				recoverer := handler.(cloudformation.ResourceCreationRecoverer)
				replay := r
				replay.PhysicalID = ""
				recovered, err := recoverer.RecoverCreation(actor, replay)
				if err != nil || recovered.PhysicalID != result.PhysicalID {
					t.Fatalf("lost reply: %#v %v", recovered, err)
				}
				if again, err := handler.Create(actor, replay); err != nil || again.PhysicalID != result.PhysicalID {
					t.Fatalf("native replay: %#v %v", again, err)
				}
				var arn string
				if kind == cfnEKSAccessEntryType {
					arn = result.Ref
				} else {
					arn = result.PhysicalID
				}
				if kind == cfnEKSPodIdentityType {
					wrongMetadata := awsctx.FromContext(root)
					wrongMetadata.Region = "us-west-2"
					outside := awsctx.WithMetadata(t.Context(), wrongMetadata)
					outsideRequest := r
					outsideRequest.CloudControl = true
					outsideRequest.Previous = maps.Clone(r.Properties)
					if _, err = handler.Update(outside, outsideRequest); err == nil {
						t.Fatal("foreign-scope association ARN aliased current native identity")
					}
				}
				tags, err := cfnComputeCall[eksapi.ListTagsForResourceResponse](root, commands, "eks", "ListTagsForResource", map[string]any{"resourceArn": arn})
				if err != nil {
					t.Fatal(err)
				}
				for tag := range tags.Tags {
					if string(tag) == cfnComputeTagPrefix+"incarnation" || string(tag) == cfnComputeTagPrefix+"stack-id" || string(tag) == cfnComputeTagPrefix+"logical-id" {
						t.Fatal("adapter emitted ownership markers")
					}
				}
				if err = cfnComputeRun(root, commands, "eks", "TagResource", map[string]any{"resourceArn": arn, "tags": map[string]string{cfnComputeTagPrefix + "incarnation": "counterfeit", cfnComputeTagPrefix + "stack-id": r.StackID, cfnComputeTagPrefix + "logical-id": r.LogicalID}}); err != nil {
					t.Fatal(err)
				}
				if err = cfnComputeRun(root, commands, "eks", "UntagResource", map[string]any{"resourceArn": arn, "tagKeys": []string{"team", cfnComputeTagPrefix + "incarnation", cfnComputeTagPrefix + "stack-id", cfnComputeTagPrefix + "logical-id"}}); err != nil {
					t.Fatal(err)
				}
				r.Previous = maps.Clone(r.Properties)
				if _, err = handler.Update(actor, r); err != nil {
					t.Fatalf("private no-op after marker removal: %v", err)
				}
				cc := r
				cc.CloudControl = true
				cc.Properties = maps.Clone(r.Properties)
				cc.Properties["Tags"] = []any{map[string]any{"Key": "customer", "Value": "green"}}
				if _, err = handler.Update(root, cc); err != nil {
					t.Fatalf("ordinary Cloud Control update: %v", err)
				}
				if err = service.CloudFormationOwned(actor, r.Type, cfnNativeComputeClaim(r), r.PhysicalID); err != nil {
					t.Fatalf("Cloud Control transferred private claim: %v", err)
				}
				if backend == "sqlite" {
					if err = service.Close(); err != nil {
						t.Fatal(err)
					}
					if err = db.Close(); err != nil {
						t.Fatal(err)
					}
					open()
					start()
					if kind == cfnEKSAccessEntryType {
						handler = cfnEKSAccessEntry{commands}
					} else {
						handler = cfnEKSPodIdentity{commands}
					}
					recoverer = handler.(cloudformation.ResourceCreationRecoverer)
				}
				policy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["eks:*","iam:PassRole"],"Resource":"*"},{"Effect":"Deny","Action":"eks:*","Resource":"*"}]}`)
				if _, err = recoverer.RecoverCreation(actor, replay); err == nil || cfnCSMissing(err) {
					t.Fatalf("revoked IAM certified recovery: %v", err)
				}
				if _, err = handler.Update(actor, r); err == nil {
					t.Fatal("revoked IAM allowed no-op")
				}
				if err = handler.Delete(actor, r); err == nil {
					t.Fatal("revoked IAM deleted")
				}
				// Explicit denial precedes the private fence even for a foreign incarnation.
				denied := eks.WithCloudFormationMutation(actor, r.Type, cfnNativeComputeClaim(r)+"-foreign", r.PhysicalID)
				err = cfnComputeRun(denied, commands, "eks", "TagResource", map[string]any{"resourceArn": arn, "tags": map[string]string{"probe": "denied"}})
				var wire *awswire.Error
				if !errors.As(err, &wire) || wire.Code != "AccessDenied" {
					t.Fatalf("ownership fence preceded current IAM: %v", err)
				}
				policy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["eks:*","iam:PassRole"],"Resource":"*"}]}`)
				if err = handler.Delete(root, cc); err != nil {
					t.Fatal(err)
				}
				policy(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"eks:*","Resource":"*"}]}`)
				if err = handler.Delete(actor, r); err == nil {
					t.Fatal("revoked IAM certified absent native deletion")
				}
				policy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["eks:*","iam:PassRole"],"Resource":"*"}]}`)
				if _, err = recoverer.RecoverCreation(root, replay); err == nil || cfnCSMissing(err) {
					t.Fatalf("deleted incarnation readmitted: %v", err)
				}
				native := map[string]any{"clusterName": key.Name, "tags": map[string]string{cfnComputeTagPrefix + "stack-id": r.StackID, cfnComputeTagPrefix + "logical-id": r.LogicalID, cfnComputeTagPrefix + "incarnation": r.Token}}
				var replacementARN, replacementID string
				if kind == cfnEKSAccessEntryType {
					native["principalArn"] = r.Properties["PrincipalArn"]
					out, createErr := cfnComputeCall[eksapi.CreateAccessEntryResponse](root, commands, "eks", "CreateAccessEntry", native)
					if createErr != nil {
						t.Fatal(createErr)
					}
					replacementARN = cfnComputeValue(out.AccessEntry.AccessEntryArn)
				} else {
					native["namespace"] = "default"
					native["serviceAccount"] = "application"
					native["roleArn"] = r.Properties["RoleArn"]
					out, createErr := cfnComputeCall[eksapi.CreatePodIdentityAssociationResponse](root, commands, "eks", "CreatePodIdentityAssociation", native)
					if createErr != nil {
						t.Fatal(createErr)
					}
					replacementARN = cfnComputeValue(out.Association.AssociationArn)
					replacementID = cfnComputeValue(out.Association.AssociationId)
				}
				if replacementARN == arn {
					t.Fatal("native recreation reused immutable incarnation")
				}
				err = handler.Delete(root, r)
				if kind == cfnEKSAccessEntryType && err == nil {
					t.Fatal("stale reusable access identifier passed private fence")
				}
				if kind == cfnEKSPodIdentityType {
					out, describeErr := cfnComputeCall[eksapi.DescribePodIdentityAssociationResponse](root, commands, "eks", "DescribePodIdentityAssociation", map[string]any{"clusterName": key.Name, "associationId": replacementID})
					if describeErr != nil || cfnComputeValue(out.Association.AssociationArn) != replacementARN {
						t.Fatalf("stale deletion changed replacement: %v", describeErr)
					}
				} else {
					out, describeErr := cfnComputeCall[eksapi.DescribeAccessEntryResponse](root, commands, "eks", "DescribeAccessEntry", map[string]any{"clusterName": key.Name, "principalArn": r.Properties["PrincipalArn"]})
					if describeErr != nil || cfnComputeValue(out.AccessEntry.AccessEntryArn) != replacementARN {
						t.Fatalf("stale deletion changed replacement: %v", describeErr)
					}
				}
				second := replay
				second.Token = "incarnation-2"
				if _, err = handler.Create(root, second); err == nil {
					t.Fatal("counterfeit public markers adopted ordinary native creation")
				}
				if _, err = service.CloudFormationCreation(root, second.Type, cfnNativeComputeClaim(second)); !errors.Is(err, eks.ErrNotFound) {
					t.Fatalf("failed adoption left private receipt: %v", err)
				}
			})
		}
	}
}

func TestCloudFormationEKSMissingNativeRuntimesRemainHonest(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	repo := eks.NewMemoryRepository(nil)
	key := eks.Key{Scope: eks.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "retained-control"}
	if err := repo.Update(ctx, func(tx eks.Transaction) error {
		return tx.PutCluster(eks.Cluster{Key: key, ID: "retained", Status: "ACTIVE", KubernetesVersion: "1.33"})
	}); err != nil {
		t.Fatal(err)
	}
	service := eks.New(eks.Config{Repository: repo})
	t.Cleanup(func() { _ = service.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"eks": service})
	cases := []struct {
		kind       string
		handler    cloudformation.ResourceHandler
		properties cloudformation.Properties
	}{
		{cfnEKSClusterType, cfnEKSCluster{commands}, cloudformation.Properties{"Name": "new-control", "RoleArn": "arn:aws:iam::111111111111:role/cluster", "ResourcesVpcConfig": map[string]any{"SubnetIds": []any{"subnet-a", "subnet-b"}}}},
		{cfnEKSNodegroupType, cfnEKSNodegroup{commands}, cloudformation.Properties{"ClusterName": key.Name, "NodegroupName": "workers", "NodeRole": "arn:aws:iam::111111111111:role/workers", "Subnets": []any{"subnet-a", "subnet-b"}}},
		{cfnEKSAddonType, cfnEKSAddon{commands}, cloudformation.Properties{"ClusterName": key.Name, "AddonName": "coredns"}},
		{cfnEKSFargateProfileType, cfnEKSFargateProfile{commands}, cloudformation.Properties{"ClusterName": key.Name, "FargateProfileName": "pods", "PodExecutionRoleArn": "arn:aws:iam::111111111111:role/pods", "Selectors": []any{map[string]any{"Namespace": "default"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			r := cloudformation.ResourceRequest{Type: tc.kind, StackID: "stack", LogicalID: "Resource", Token: "unique", Properties: tc.properties}
			if _, err := tc.handler.Create(ctx, r); err == nil {
				t.Fatal("absent native runtime reported success")
			}
			if _, err := service.CloudFormationCreation(ctx, r.Type, cfnNativeComputeClaim(r)); !errors.Is(err, eks.ErrNotFound) {
				t.Fatalf("rejected runtime admission left receipt: %v", err)
			}
		})
	}
}
