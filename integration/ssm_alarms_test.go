package stackd_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"stackd"
	"stackd/clock"
	ec2api "stackd/internal/awsapi/ec2"
	"stackd/storage"
	ec2store "stackd/storage/ec2"
	commands "stackd/storage/ssmcommands"
)

// Nodes are seeded only to keep undelivered work deterministic. Real official-agent
// execution and already-running process survival are proved by the guest smoke.
func TestSSMAlarmsAdmissionCurrentAuthorityAndRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			const account = "123456789012"
			const node = "i-00000000000000001"
			source := clock.NewManual(time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC))
			stores := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "alarms.db")
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
			reopen := func() {
				if err := active.Load().Close(); err != nil {
					t.Fatal(err)
				}
				closeDB()
				if backend == "sqlite" {
					stores, closeDB = openSQLiteBackends(t, path)
				}
				open()
			}
			drain := func() {
				if _, err := active.Load().RunDueJobs(ctx, 1000); err != nil {
					t.Fatal(err)
				}
			}
			advance := func() {
				if err := source.Advance(6 * time.Second); err != nil {
					t.Fatal(err)
				}
				drain()
			}
			clients := cloudClients{server}
			root := clients.ssm("us-east-1", account, "test")
			roles := clients.iam(account, "test", "")
			alarms := metricsClient(clients, account)
			if err := stores.EC2.Update(ctx, func(tx ec2store.Transaction) error {
				return tx.PutInstance(ec2store.InstanceRecord{Key: ec2store.ResourceKey{Scope: ec2store.Scope{Partition: "aws", AccountID: account, Region: "us-east-1"}, ID: node}, Data: ec2api.Instance{InstanceId: new(ec2api.String(node)), State: &ec2api.InstanceState{Name: new(ec2api.InstanceStateName("running"))}}})
			}); err != nil {
				t.Fatal(err)
			}
			if err := stores.SSMCommands.Update(ctx, func(tx commands.Transaction) error {
				return tx.PutNode(commands.Node{Key: commands.Key{Scope: commands.Scope{Partition: "aws", AccountID: account, Region: "us-east-1"}, ID: node}, RegisteredAt: source.Now(), LastPing: source.Now(), PlatformType: "Linux"})
			}); err != nil {
				t.Fatal(err)
			}
			putAlarm := func(name string) {
				_, err := alarms.PutMetricAlarm(ctx, &cloudwatch.PutMetricAlarmInput{AlarmName: &name, Namespace: new("SSMAlarmTest"), MetricName: new("health"), ComparisonOperator: cwtypes.ComparisonOperatorGreaterThanThreshold, Threshold: new(float64(1)), EvaluationPeriods: new(int32(1)), Period: new(int32(86400)), Statistic: cwtypes.StatisticSum, TreatMissingData: new("ignore")})
				if err != nil {
					t.Fatal(err)
				}
			}
			setState := func(name string, state cwtypes.StateValue) {
				if _, err := alarms.SetAlarmState(ctx, &cloudwatch.SetAlarmStateInput{AlarmName: &name, StateValue: state, StateReason: new("alarm regression")}); err != nil {
					t.Fatal(err)
				}
			}
			input := func(name string, ignore bool) *ssm.SendCommandInput {
				return &ssm.SendCommandInput{DocumentName: new("AWS-RunShellScript"), InstanceIds: []string{node}, Parameters: map[string][]string{"commands": {"printf eligible"}, "executionTimeout": {"300"}}, TimeoutSeconds: new(int32(60)), AlarmConfiguration: &ssmtypes.AlarmConfiguration{Alarms: []ssmtypes.Alarm{{Name: &name}}, IgnorePollAlarmFailure: ignore}}
			}
			send := func(client *ssm.Client, name string, ignore bool) string {
				out, err := client.SendCommand(ctx, input(name, ignore))
				if err != nil {
					t.Fatal(err)
				}
				if out.Command.AlarmConfiguration == nil || len(out.Command.AlarmConfiguration.Alarms) != 1 || aws.ToString(out.Command.AlarmConfiguration.Alarms[0].Name) != name || out.Command.AlarmConfiguration.IgnorePollAlarmFailure != ignore {
					t.Fatalf("retained config: %+v", out.Command)
				}
				return aws.ToString(out.Command.CommandId)
			}
			read := func(id string) ssmtypes.Command {
				out, err := root.ListCommands(ctx, &ssm.ListCommandsInput{CommandId: &id})
				if err != nil || len(out.Commands) != 1 {
					t.Fatalf("command: %+v %v", out, err)
				}
				return out.Commands[0]
			}
			assertTrigger := func(id, name, state string) {
				c := read(id)
				details := "FailedDueToAlarm"
				if state == "UNKNOWN" {
					details = "FailedDueToUnknownAlarmState"
				}
				if c.Status != ssmtypes.CommandStatusFailed || aws.ToString(c.StatusDetails) != details || c.CompletedCount != 1 || c.ErrorCount != 0 || c.DeliveryTimedOutCount != 0 || len(c.TriggeredAlarms) != 1 || aws.ToString(c.TriggeredAlarms[0].Name) != name || string(c.TriggeredAlarms[0].State) != state {
					t.Fatalf("triggered command: %+v", c)
				}
				out, err := root.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{CommandId: &id, InstanceId: new(node)})
				if err != nil {
					t.Fatal(err)
				}
				if out.Status != ssmtypes.CommandInvocationStatusFailed || aws.ToString(out.StatusDetails) != "Terminated" || out.ResponseCode != -1 || aws.ToString(out.StandardOutputContent) != "" {
					t.Fatalf("terminated invocation: %+v", out)
				}
			}
			putAlarm("guard")
			setState("guard", cwtypes.StateValueOk)
			_, key, secret := clients.user(t, account, "alarm-caller")
			caller := clients.ssm("us-east-1", key, secret)
			putUserPolicy(t, roles, "alarm-caller", `{"Statement":[{"Effect":"Allow","Action":"ssm:SendCommand","Resource":"*"}]}`)
			_, err := caller.SendCommand(ctx, input("guard", false))
			assertAPIError(t, err, "AccessDeniedException")
			putUserPolicy(t, roles, "alarm-caller", `{"Statement":[{"Effect":"Allow","Action":"ssm:SendCommand","Resource":"*"},{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"*","Condition":{"StringEquals":{"iam:AWSServiceName":"ssm.amazonaws.com"}}},{"Effect":"Deny","Action":"cloudwatch:DescribeAlarms","Resource":"*"}]}`)
			pending := send(caller, "guard", false)
			// Once IAM owns the linked role, the caller no longer needs creation or
			// CloudWatch rights. Monitoring does not use a saved caller policy.
			putUserPolicy(t, roles, "alarm-caller", `{"Statement":[{"Effect":"Allow","Action":"ssm:SendCommand","Resource":"*"},{"Effect":"Deny","Action":["cloudwatch:DescribeAlarms","iam:CreateServiceLinkedRole"],"Resource":"*"}]}`)
			second := send(caller, "guard", false)
			reopen()
			setState("guard", cwtypes.StateValueAlarm)
			advance()
			assertTrigger(pending, "guard", "ALARM")
			assertTrigger(second, "guard", "ALARM")
			reopen()
			assertTrigger(pending, "guard", "ALARM")
			for _, ignore := range []bool{false, true} {
				_, err = root.SendCommand(ctx, input("guard", ignore))
				assertAPIError(t, err, "ValidationException")
			}
			for _, state := range []cwtypes.StateValue{cwtypes.StateValueOk, cwtypes.StateValueInsufficientData} {
				setState("guard", state)
				id := send(root, "guard", false)
				advance()
				if c := read(id); c.Status != ssmtypes.CommandStatusPending || len(c.TriggeredAlarms) != 0 {
					t.Fatalf("eligible alarm: %+v", c)
				}
				if _, err = root.CancelCommand(ctx, &ssm.CancelCommandInput{CommandId: &id}); err != nil {
					t.Fatal(err)
				}
				setState("guard", cwtypes.StateValueAlarm)
				advance()
				if c := read(id); c.Status != ssmtypes.CommandStatusCancelled || len(c.TriggeredAlarms) != 0 {
					t.Fatalf("alarm reopened cancellation: %+v", c)
				}
			}
			_, err = root.SendCommand(ctx, input("absent", false))
			assertAPIError(t, err, "ValidationException")
			ignored := send(root, "absent", true)
			advance()
			reopen()
			advance()
			if c := read(ignored); c.Status != ssmtypes.CommandStatusPending || len(c.TriggeredAlarms) != 0 {
				t.Fatalf("ignored missing alarm: %+v", c)
			}
			putAlarm("absent")
			setState("absent", cwtypes.StateValueAlarm)
			advance()
			assertTrigger(ignored, "absent", "ALARM")
			putAlarm("deleted")
			setState("deleted", cwtypes.StateValueOk)
			deleted := send(root, "deleted", false)
			if _, err = alarms.DeleteAlarms(ctx, &cloudwatch.DeleteAlarmsInput{AlarmNames: []string{"deleted"}}); err != nil {
				t.Fatal(err)
			}
			reopen()
			advance()
			assertTrigger(deleted, "deleted", "UNKNOWN")
			// IAM deletion must share the retained command owner's usage transaction.
			setState("guard", cwtypes.StateValueOk)
			live := send(root, "guard", false)
			deletion, err := roles.DeleteServiceLinkedRole(ctx, &iam.DeleteServiceLinkedRoleInput{RoleName: new("AWSServiceRoleForAmazonSSM")})
			if err != nil {
				t.Fatal(err)
			}
			drain()
			status := waitOrganizationRoleDeletion(t, roles, deletion.DeletionTaskId)
			if status.Status != iamtypes.DeletionTaskStatusTypeFailed || status.Reason == nil || len(status.Reason.RoleUsageList) != 1 || aws.ToString(status.Reason.RoleUsageList[0].Region) != "us-east-1" {
				t.Fatalf("active monitoring did not protect SLR: %+v, reason %+v", status, status.Reason)
			}
			if _, err = root.CancelCommand(ctx, &ssm.CancelCommandInput{CommandId: &live}); err != nil {
				t.Fatal(err)
			}
			deletion, err = roles.DeleteServiceLinkedRole(ctx, &iam.DeleteServiceLinkedRoleInput{RoleName: new("AWSServiceRoleForAmazonSSM")})
			if err != nil {
				t.Fatal(err)
			}
			drain()
			status = waitOrganizationRoleDeletion(t, roles, deletion.DeletionTaskId)
			if status.Status != iamtypes.DeletionTaskStatusTypeFailed || status.Reason == nil || len(status.Reason.RoleUsageList) != 0 {
				t.Fatalf("settled monitoring must release usage without bypassing live IAM sessions: %+v, reason %+v", status, status.Reason)
			}
			if err = source.Advance(time.Hour + time.Second); err != nil {
				t.Fatal(err)
			}
			deletion, err = roles.DeleteServiceLinkedRole(ctx, &iam.DeleteServiceLinkedRoleInput{RoleName: new("AWSServiceRoleForAmazonSSM")})
			if err != nil {
				t.Fatal(err)
			}
			drain()
			status = waitOrganizationRoleDeletion(t, roles, deletion.DeletionTaskId)
			if status.Status != iamtypes.DeletionTaskStatusTypeSucceeded {
				t.Fatalf("settled monitoring retained SLR usage: %+v", status)
			}
			_, err = caller.SendCommand(ctx, input("guard", false))
			assertAPIError(t, err, "AccessDeniedException")
			for _, name := range []string{"", " ", fmt.Sprintf("%0256d", 1)} {
				_, err = root.SendCommand(ctx, input(name, false))
				assertAPIError(t, err, "ValidationException")
			}
			tooMany := input("guard", false)
			tooMany.AlarmConfiguration.Alarms = append(tooMany.AlarmConfiguration.Alarms, ssmtypes.Alarm{Name: new("absent")})
			_, err = root.SendCommand(ctx, tooMany)
			assertAPIError(t, err, "ValidationException")
		})
	}
}
