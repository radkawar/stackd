package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroups"
	rgtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroups/types"

	"stackd"
	"stackd/clock"
)

const (
	cloudFormationKMSAliasAccount = "123456789012"
	cloudFormationKMSAliasRegion  = "us-east-1"
	cloudFormationKMSAliasName    = "alias/cfn-owned-key"
	cloudFormationKMSAliasARN     = "arn:aws:kms:us-east-1:123456789012:alias/cfn-owned-key"
)

// These are local ownership regressions, not a replay of native AWS captures.
func TestCloudFormationKMSAliasStackDiscovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCloudFormationKMSAliasStack(t, backend)
			aliasQuery := f.stackQuery(t, "AWS::KMS::Alias")
			allQuery := f.stackQuery(t, "AWS::AllSupported")
			alias := map[string]string{cloudFormationKMSAliasARN: "AWS::KMS::Alias"}
			key := map[string]string{f.keyARN: "AWS::KMS::Key"}
			owned := map[string]string{f.keyARN: "AWS::KMS::Key", cloudFormationKMSAliasARN: "AWS::KMS::Alias"}
			f.assertMembers(t, aliasQuery, alias)
			f.assertMembers(t, allQuery, owned)

			// Alias eligibility is stack-only: it must not leak into tag queries,
			// even though its target key has a matching customer tag.
			f.assertMembers(t, &rgtypes.ResourceQuery{Type: rgtypes.QueryTypeTagFilters10,
				Query: aws.String(`{"ResourceTypeFilters":["AWS::AllSupported"],"TagFilters":[{"Key":"owner-test","Values":["kms-alias"]}]}`)}, key)
			_, err := f.groups(cloudFormationKMSAliasRegion, cloudFormationKMSAliasAccount).SearchResources(t.Context(), &resourcegroups.SearchResourcesInput{
				ResourceQuery: &rgtypes.ResourceQuery{Type: rgtypes.QueryTypeTagFilters10,
					Query: aws.String(`{"ResourceTypeFilters":["AWS::KMS::Alias"],"TagFilters":[{"Key":"owner-test","Values":["kms-alias"]}]}`)},
			})
			assertAPIError(t, err, "BadRequestException")

			for _, scope := range []struct{ account, region string }{
				{"111111111111", cloudFormationKMSAliasRegion},
				{cloudFormationKMSAliasAccount, "us-west-2"},
			} {
				out, err := f.groups(scope.region, scope.account).SearchResources(t.Context(), &resourcegroups.SearchResourcesInput{ResourceQuery: aliasQuery})
				if err != nil {
					t.Fatal(err)
				}
				if len(out.ResourceIdentifiers) != 0 || len(out.QueryErrors) != 1 || out.QueryErrors[0].ErrorCode != rgtypes.QueryErrorCodeCloudformationStackNotExisting {
					t.Fatalf("stack alias escaped account/region scope: %+v", out)
				}
			}

			f.clients = f.reopen()
			f.assertMembers(t, aliasQuery, alias)
			f.assertAliasTarget(t, f.keyID)
			alternate, err := f.kms().CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			alternateID := aws.ToString(alternate.KeyMetadata.KeyId)
			if _, err := f.kms().UpdateAlias(t.Context(), &kms.UpdateAliasInput{AliasName: aws.String(cloudFormationKMSAliasName), TargetKeyId: aws.String(alternateID)}); err != nil {
				t.Fatal(err)
			}
			f.assertAliasTarget(t, alternateID)
			f.assertMembers(t, aliasQuery, alias)
			f.clients = f.reopen()
			f.assertAliasTarget(t, alternateID)
			f.assertMembers(t, allQuery, owned)

			// A native retarget preserves this alias incarnation; delete/create
			// does not, even when both the name and target key are identical.
			f.replaceAlias(t, alternateID)
			f.assertMembers(t, aliasQuery, map[string]string{})
			f.assertMembers(t, allQuery, key)
			f.clients = f.reopen()
			f.assertAliasTarget(t, alternateID)
			f.assertMembers(t, aliasQuery, map[string]string{})
			f.assertMembers(t, allQuery, key)
		})
	}
}

func TestCloudFormationKMSAliasRejectsForeignReplacement(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCloudFormationKMSAliasStack(t, backend)
			alternate, err := f.kms().CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			alternateID := aws.ToString(alternate.KeyMetadata.KeyId)

			// Ownership metadata must not change the native duplicate contract.
			_, err = f.kms().CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: aws.String(cloudFormationKMSAliasName), TargetKeyId: aws.String(alternateID)})
			assertAPIError(t, err, "AlreadyExistsException")
			f.assertAliasTarget(t, f.keyID)
			f.replaceAlias(t, f.keyID)
			f.clients = f.reopen()

			_, err = f.cfn().UpdateStack(t.Context(), &cloudformation.UpdateStackInput{
				StackName: aws.String(f.stackID), TemplateBody: aws.String(cloudFormationKMSAliasTemplate(t, alternateID)), DisableRollback: aws.Bool(true),
			})
			if err != nil {
				t.Fatal(err)
			}
			f.wait(t, cfntypes.StackStatusUpdateFailed)
			f.assertResourceStatus(t, cfntypes.ResourceStatusUpdateFailed)
			f.assertAliasTarget(t, f.keyID)

			if _, err := f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(f.stackID)}); err != nil {
				t.Fatal(err)
			}
			f.wait(t, cfntypes.StackStatusDeleteFailed)
			f.assertResourceStatus(t, cfntypes.ResourceStatusDeleteFailed)
			f.assertAliasTarget(t, f.keyID)
			f.clients = f.reopen()
			f.assertAliasTarget(t, f.keyID)
			f.assertMembers(t, f.stackQuery(t, "AWS::KMS::Alias"), map[string]string{})
		})
	}
}

type cloudFormationKMSAliasStack struct {
	clients                cloudClients
	reopen                 func() cloudClients
	source                 *clock.Manual
	stackID, keyID, keyARN string
}

func newCloudFormationKMSAliasStack(t *testing.T, backend string) *cloudFormationKMSAliasStack {
	t.Helper()
	f := &cloudFormationKMSAliasStack{source: clock.NewManual(time.Date(2031, 4, 5, 6, 7, 8, 0, time.UTC))}
	f.clients, f.reopen = retainedCloud(t, backend, stackd.Config{AccountID: cloudFormationKMSAliasAccount, Clock: f.source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return startPublicCloud(t, config)
	})
	created, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{
		StackName: aws.String("kms-alias-owner"), TemplateBody: aws.String(cloudFormationKMSAliasTemplate(t, map[string]string{"Ref": "Key"})),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.stackID = aws.ToString(created.StackId)
	stack := f.wait(t, cfntypes.StackStatusCreateComplete)
	for _, output := range stack.Outputs {
		switch aws.ToString(output.OutputKey) {
		case "KeyID":
			f.keyID = aws.ToString(output.OutputValue)
		case "KeyARN":
			f.keyARN = aws.ToString(output.OutputValue)
		}
	}
	if f.keyID == "" || f.keyARN == "" {
		t.Fatalf("stack did not expose its KMS key: %+v", stack.Outputs)
	}
	f.assertAliasTarget(t, f.keyID)
	return f
}

func cloudFormationKMSAliasTemplate(t *testing.T, target any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{
			"Key": map[string]any{"Type": "AWS::KMS::Key", "Properties": map[string]any{
				"Tags": []map[string]string{{"Key": "owner-test", "Value": "kms-alias"}},
			}},
			"Alias": map[string]any{"Type": "AWS::KMS::Alias", "DependsOn": "Key", "Properties": map[string]any{
				"AliasName": cloudFormationKMSAliasName, "TargetKeyId": target,
			}},
		},
		"Outputs": map[string]any{
			"KeyID":  map[string]any{"Value": map[string]string{"Ref": "Key"}},
			"KeyARN": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Key", "Arn"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func (f *cloudFormationKMSAliasStack) cfn() *cloudformation.Client {
	return cloudFormationClient(f.clients, cloudFormationKMSAliasRegion, cloudFormationKMSAliasAccount, "test")
}

func (f *cloudFormationKMSAliasStack) kms() *kms.Client {
	return kms.New(kms.Options{Region: cloudFormationKMSAliasRegion, BaseEndpoint: aws.String(f.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(cloudFormationKMSAliasAccount, "test", ""), HTTPClient: f.clients.server.Client(), RetryMaxAttempts: 1})
}

func (f *cloudFormationKMSAliasStack) groups(region, account string) *resourcegroups.Client {
	return resourcegroups.New(resourcegroups.Options{Region: region, BaseEndpoint: aws.String(f.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: f.clients.server.Client(), RetryMaxAttempts: 1})
}

func (f *cloudFormationKMSAliasStack) wait(t *testing.T, wanted cfntypes.StackStatus) cfntypes.Stack {
	t.Helper()
	for range 100 {
		if _, err := f.clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1000); err != nil {
			t.Fatal(err)
		}
		out, err := f.cfn().DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: aws.String(f.stackID)})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Stacks) != 1 {
			t.Fatalf("expected the requested stack, got %+v", out.Stacks)
		}
		stack := out.Stacks[0]
		if stack.StackStatus == wanted {
			return stack
		}
		if !cloudFormationTransient(map[string]any{"Stacks": []any{map[string]any{"StackStatus": string(stack.StackStatus)}}}) {
			t.Fatalf("wanted %s, got %s: %s", wanted, stack.StackStatus, aws.ToString(stack.StackStatusReason))
		}
		advanceClock(t, f.source, time.Second)
	}
	t.Fatalf("stack did not reach %s after draining service jobs", wanted)
	return cfntypes.Stack{}
}

func (f *cloudFormationKMSAliasStack) assertAliasTarget(t *testing.T, keyID string) {
	t.Helper()
	out, err := f.kms().ListAliases(t.Context(), &kms.ListAliasesInput{KeyId: aws.String(keyID)})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Aliases) != 1 || aws.ToString(out.Aliases[0].AliasName) != cloudFormationKMSAliasName || aws.ToString(out.Aliases[0].AliasArn) != cloudFormationKMSAliasARN || aws.ToString(out.Aliases[0].TargetKeyId) != keyID {
		t.Fatalf("expected %s to target %s, got %+v", cloudFormationKMSAliasARN, keyID, out.Aliases)
	}
}

func (f *cloudFormationKMSAliasStack) replaceAlias(t *testing.T, keyID string) {
	t.Helper()
	if _, err := f.kms().DeleteAlias(t.Context(), &kms.DeleteAliasInput{AliasName: aws.String(cloudFormationKMSAliasName)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.kms().CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: aws.String(cloudFormationKMSAliasName), TargetKeyId: aws.String(keyID)}); err != nil {
		t.Fatal(err)
	}
	f.assertAliasTarget(t, keyID)
}

func (f *cloudFormationKMSAliasStack) assertResourceStatus(t *testing.T, wanted cfntypes.ResourceStatus) {
	t.Helper()
	out, err := f.cfn().DescribeStackResource(t.Context(), &cloudformation.DescribeStackResourceInput{StackName: aws.String(f.stackID), LogicalResourceId: aws.String("Alias")})
	if err != nil {
		t.Fatal(err)
	}
	if out.StackResourceDetail == nil || out.StackResourceDetail.ResourceStatus != wanted {
		t.Fatalf("expected alias resource status %s, got %+v", wanted, out.StackResourceDetail)
	}
}

func (f *cloudFormationKMSAliasStack) stackQuery(t *testing.T, kind string) *rgtypes.ResourceQuery {
	t.Helper()
	body, err := json.Marshal(map[string]any{"ResourceTypeFilters": []string{kind}, "StackIdentifier": f.stackID})
	if err != nil {
		t.Fatal(err)
	}
	return &rgtypes.ResourceQuery{Type: rgtypes.QueryTypeCloudformationStack10, Query: aws.String(string(body))}
}

func (f *cloudFormationKMSAliasStack) assertMembers(t *testing.T, query *rgtypes.ResourceQuery, wanted map[string]string) {
	t.Helper()
	input := &resourcegroups.SearchResourcesInput{ResourceQuery: query}
	got := map[string]string{}
	for range 100 {
		out, err := f.groups(cloudFormationKMSAliasRegion, cloudFormationKMSAliasAccount).SearchResources(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.QueryErrors) != 0 {
			t.Fatalf("resource query failed: %+v", out.QueryErrors)
		}
		for _, resource := range out.ResourceIdentifiers {
			arn := aws.ToString(resource.ResourceArn)
			if _, duplicate := got[arn]; duplicate {
				t.Fatalf("resource query returned duplicate ARN %s", arn)
			}
			got[arn] = aws.ToString(resource.ResourceType)
		}
		if out.NextToken == nil {
			if !reflect.DeepEqual(got, wanted) {
				t.Fatalf("wanted resources %v, got %v", wanted, got)
			}
			return
		}
		input.NextToken = out.NextToken
	}
	t.Fatal("resource query pagination did not terminate")
}
