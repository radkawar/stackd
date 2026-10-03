package stackd_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroups"
	rgtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroups/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"stackd"
	"stackd/clock"
	ec2api "stackd/internal/awsapi/ec2"
	"stackd/storage"
	ec2store "stackd/storage/ec2"
	commands "stackd/storage/ssmcommands"
)

// Seed owner state only to exercise selection/authorization deterministically.
// This does not simulate agent execution; the guest smoke runs the official agent.
func TestSSMResourceGroupsCurrentMembershipAuthorityAndRetention(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			const account = "123456789012"
			source := clock.NewManual(time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC))
			stores := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "groups.db")
			closeDB := func() {}
			if backend == "sqlite" {
				stores, closeDB = openSQLiteBackends(t, path)
			}
			var active atomic.Pointer[stackd.Stack]
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { active.Load().ServeHTTP(w, r) }))
			open := func() {
				cloud, err := stackd.New(stackd.Config{Storage: stores, Clock: source, PublicEndpoint: server.URL})
				if err != nil {
					t.Fatal(err)
				}
				active.Store(cloud)
			}
			open()
			t.Cleanup(func() { server.Close(); _ = active.Load().Close(); closeDB() })
			clients := cloudClients{server}
			groups := resourcegroups.New(resourcegroups.Options{Region: "us-east-1", BaseEndpoint: new(server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			root := clients.ssm("us-east-1", account, "test")
			query := func(value string) *rgtypes.ResourceQuery {
				return &rgtypes.ResourceQuery{Type: rgtypes.QueryTypeTagFilters10, Query: new(fmt.Sprintf(`{"ResourceTypeFilters":["AWS::EC2::Instance"],"TagFilters":[{"Key":"team","Values":[%q]}]}`, value))}
			}
			_, err := groups.CreateGroup(ctx, &resourcegroups.CreateGroupInput{Name: new("command-members"), ResourceQuery: query("selected")})
			if err != nil {
				t.Fatal(err)
			}
			seed := func(id, team, state string, managed bool) {
				t.Helper()
				key := ec2store.ResourceKey{Scope: ec2store.Scope{Partition: "aws", AccountID: account, Region: "us-east-1"}, ID: id}
				err := stores.EC2.Update(ctx, func(tx ec2store.Transaction) error {
					return tx.PutInstance(ec2store.InstanceRecord{Key: key, Data: ec2api.Instance{InstanceId: new(ec2api.String(id)), State: &ec2api.InstanceState{Name: new(ec2api.InstanceStateName(state))}, Tags: ec2api.TagList{{Key: new(ec2api.String("team")), Value: new(ec2api.String(team))}}}})
				})
				if err != nil {
					t.Fatal(err)
				}
				if managed {
					err = stores.SSMCommands.Update(ctx, func(tx commands.Transaction) error {
						return tx.PutNode(commands.Node{Key: commands.Key{Scope: commands.Scope{Partition: "aws", AccountID: account, Region: "us-east-1"}, ID: id}, RegisteredAt: source.Now(), LastPing: source.Now(), PlatformType: "Linux"})
					})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			const first = "i-00000000000000001"
			const second = "i-00000000000000002"
			seed(first, "selected", "running", true)
			seed(second, "excluded", "running", true)
			seed("i-00000000000000003", "selected", "stopped", true)
			seed("i-00000000000000004", "selected", "running", false)
			input := func(name string) *ssm.SendCommandInput {
				return &ssm.SendCommandInput{DocumentName: new("AWS-RunShellScript"), Parameters: map[string][]string{"commands": {"printf group-member"}}, Targets: []ssmtypes.Target{{Key: new("resource-groups:Name"), Values: []string{name}}, {Key: new("resource-groups:ResourceTypeFilters"), Values: []string{"AWS::EC2::Instance"}}}}
			}
			send := func(c *ssm.Client, name string) string {
				t.Helper()
				out, err := c.SendCommand(ctx, input(name))
				if err != nil {
					t.Fatal(err)
				}
				return aws.ToString(out.Command.CommandId)
			}
			selected := func(id string, want ...string) {
				t.Helper()
				out, err := root.ListCommandInvocations(ctx, &ssm.ListCommandInvocationsInput{CommandId: new(id)})
				if err != nil {
					t.Fatal(err)
				}
				got := make([]string, 0, len(out.CommandInvocations))
				for _, v := range out.CommandInvocations {
					got = append(got, aws.ToString(v.InstanceId))
				}
				if len(got) != len(want) || len(got) > 0 && !reflect.DeepEqual(got, want) {
					t.Fatalf("selection got %v want %v", got, want)
				}
			}
			accepted := send(root, "command-members")
			selected(accepted, first)
			seed(first, "excluded", "running", true)
			seed(second, "selected", "running", true)
			selected(send(root, "command-members"), second)
			selected(accepted, first)
			_, err = groups.UpdateGroupQuery(ctx, &resourcegroups.UpdateGroupQueryInput{Group: new("command-members"), ResourceQuery: query("excluded")})
			if err != nil {
				t.Fatal(err)
			}
			selected(send(root, "command-members"), first)
			if err = active.Load().Close(); err != nil {
				t.Fatal(err)
			}
			closeDB()
			if backend == "sqlite" {
				stores, closeDB = openSQLiteBackends(t, path)
			}
			open()
			selected(accepted, first)
			selected(send(root, "command-members"), first)
			for _, c := range []*ssm.Client{clients.ssm("us-west-2", account, "test"), clients.ssm("us-east-1", "222233334444", "test")} {
				out, err := c.SendCommand(ctx, input("command-members"))
				if err != nil {
					t.Fatal(err)
				}
				if out.Command.TargetCount != 0 {
					t.Fatalf("scope leak: %+v", out.Command)
				}
			}
			selected(send(root, "command-members-absent"))
			_, key, secret := clients.user(t, account, "group-command-caller")
			iamClient := clients.iam(account, "test", "")
			caller := clients.ssm("us-east-1", key, secret)
			// The SSM consumer uses ListGroupResources, not interactive query permissions.
			putUserPolicy(t, iamClient, "group-command-caller", `{"Statement":[{"Effect":"Allow","Action":["ssm:SendCommand","resource-groups:ListGroupResources"],"Resource":"*"},{"Effect":"Deny","Action":["tag:GetResources","resource-groups:GetGroupQuery","resource-groups:GetGroup"],"Resource":"*"}]}`)
			selected(send(caller, "command-members"), first)
			putUserPolicy(t, iamClient, "group-command-caller", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":["ssm:SendCommand","resource-groups:ListGroupResources"],"Resource":"*"},{"Effect":"Deny","Action":"ssm:SendCommand","Resource":"arn:aws:ec2:us-east-1:%s:instance/%s"}]}`, account, first))
			_, err = caller.SendCommand(ctx, input("command-members"))
			assertAPIError(t, err, "AccessDeniedException")
			putUserPolicy(t, iamClient, "group-command-caller", `{"Statement":[{"Effect":"Allow","Action":"ssm:SendCommand","Resource":"*"}]}`)
			denied := send(caller, "command-members")
			selected(denied)
			list, err := root.ListCommands(ctx, &ssm.ListCommandsInput{CommandId: new(denied)})
			if err != nil {
				t.Fatal(err)
			}
			if len(list.Commands) != 1 || list.Commands[0].Status != ssmtypes.CommandStatusFailed || aws.ToString(list.Commands[0].StatusDetails) != "AccessDenied" {
				t.Fatalf("group denial: %+v", list)
			}
			for _, extra := range []ssmtypes.Target{{Key: new("tag:team"), Values: []string{"selected"}}, {Key: new("InstanceIds"), Values: []string{first}}, {Key: new("resource-groups:Name"), Values: []string{"command-members"}}} {
				in := input("command-members")
				in.Targets = append(in.Targets, extra)
				_, err = root.SendCommand(ctx, in)
				assertAPIError(t, err, "ValidationException")
			}
			in := input("command-members")
			in.Targets[1].Values = []string{"AWS::S3::Bucket"}
			_, err = root.SendCommand(ctx, in)
			assertAPIError(t, err, "ValidationException")
			in = input("command-members")
			in.Targets[1].Values = []string{"AWS::SSM::ManagedInstance"}
			out, err := root.SendCommand(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			selected(aws.ToString(out.Command.CommandId))
			in = input("command-members")
			in.Targets[1].Values = []string{"AWS::EC2::Instance", "AWS::S3::Bucket"}
			out, err = root.SendCommand(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			selected(aws.ToString(out.Command.CommandId), first)
			in = input("command-members")
			in.Targets[1].Values = []string{"AWS::EC2::Instance", "AWS::EC2::Instance"}
			_, err = root.SendCommand(ctx, in)
			assertAPIError(t, err, "ValidationException")
		})
	}
}
