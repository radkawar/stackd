package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/autoscaling"
	ec2api "stackd/internal/awsapi/ec2"
	snsapi "stackd/internal/awsapi/sns"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awscatalog"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	asg "stackd/internal/services/autoscaling"
	"stackd/internal/services/ec2"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/iam"
	"stackd/internal/services/sns"
	"stackd/internal/services/sqs"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlasg "stackd/storage/sqlite/autoscaling"
	sqlec2 "stackd/storage/sqlite/ec2"
	sqljournal "stackd/storage/sqlite/journal"
)

type autoScalingFixture struct {
	domain       *memory.Domain
	clock        *clock.Manual
	root, caller context.Context
	iam          iam.Repository
	role         iam.Role
	user         iam.User
	roles        ServiceRoles
	group        asg.GroupRecord
	ec2          *ec2.Service
	queues       *sqs.Service
	topics       *sns.Service
	adapter      *AutoScaling
	commands     StepFunctionsCommands
	events       journal.Storage
}

func newAutoScalingFixture(t *testing.T) *autoScalingFixture {
	t.Helper()
	f := &autoScalingFixture{domain: memory.NewDomain(), clock: clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))}
	f.root = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012", RequestID: "origin-request"})
	f.group = asg.GroupRecord{Key: asg.GroupKey{Scope: asg.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "workers"}, ID: "00000000-0000-4000-8000-000000000001"}
	f.role = iam.Role{Arn: "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling", RoleName: "AWSServiceRoleForAutoScaling", RoleId: "AROAASGEXECUTION", MaxSessionDuration: 3600,
		AssumeRolePolicyDocument: `{"Statement":{"Effect":"Allow","Principal":{"Service":"autoscaling.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:SourceArn":"` + f.group.Key.ARN(f.group.ID) + `"}}}}`,
		IdentityPolicies:         iam.IdentityPolicies{Inline: map[string]string{"execute": `{"Statement":{"Effect":"Allow","Action":["ec2:Describe*","sqs:SendMessage","sns:Publish"],"Resource":"*"}}`}}}
	f.user = iam.User{Arn: "arn:aws:iam::123456789012:user/deployer", UserName: "deployer", UserId: "AIDAASGDEPLOYER", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
	f.group.Data.ServiceLinkedRoleARN = new(api.ResourceName(f.role.Arn))
	f.caller = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: f.user.Arn, PrincipalID: f.user.UserId, UserName: f.user.UserName, RequestID: "origin-request"})
	f.iam = iam.NewMemoryRepository(f.domain)
	f.update(t)
	credentials := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(f.iam, nil), Clock: f.clock})
	owner := iam.NewWithConfig(iam.Config{Repository: f.iam, Credentials: credentials, Clock: f.clock})
	authorizer := authorization.NewWithClock(owner, nil, f.clock)
	f.roles = ServiceRoles{IAM: owner, Credentials: credentials, Authorizer: authorizer}
	f.events = journal.NewMemory(f.domain)
	f.ec2 = ec2.New(ec2.Config{Repository: ec2.NewMemoryRepository(f.domain), Authorizer: authorizer, Clock: f.clock, Recorder: apievents.New(f.events)})
	f.queues = sqs.NewWithConfig(sqs.Config{Repository: sqs.NewMemoryRepository(f.domain), Authorizer: authorizer, Clock: f.clock})
	endpoint := httptest.NewUnstartedServer(nil)
	f.topics = sns.New(sns.Config{Repository: sns.NewMemoryRepository(f.domain), Authorizer: authorizer, Clock: f.clock, Delivery: SNSSubscriptions{SQS: f.queues}, PublicEndpoint: "http://" + endpoint.Listener.Addr().String()})
	endpoint.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !f.topics.ServeSigningCertificate(w, r) {
			f.topics.ServeHTTP(w, r)
		}
	})
	endpoint.Start()
	t.Cleanup(endpoint.Close)
	t.Cleanup(func() { f.ec2.Close(); f.topics.Close(); f.queues.Close() })
	f.adapter = &AutoScaling{EC2: f.ec2, Roles: f.roles}
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": f.ec2, "sqs": f.queues, "sns": f.topics})
	return f
}

func (f *autoScalingFixture) update(t *testing.T) {
	t.Helper()
	if err := f.iam.Update(f.root, func(tx iam.WriteTx) error {
		scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
		if err := tx.PutRole(scope, f.role); err != nil {
			return err
		}
		return tx.PutUser(scope, f.user)
	}); err != nil {
		t.Fatal(err)
	}
}
func (f *autoScalingFixture) call(t *testing.T, service, operation string, input any) any {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	out, rejected := f.commands.Call(f.root, service, operation, body)
	if rejected != nil {
		t.Fatalf("%s %s: %v", service, operation, rejected)
	}
	return out.Output
}

func TestAutoScalingScopedTemplatesPlacementAndCurrentRole(t *testing.T) {
	f := newAutoScalingFixture(t)
	vpc := f.call(t, "ec2", "CreateVpc", map[string]any{"CidrBlock": "10.71.0.0/16"}).(*ec2api.CreateVpcResult).Vpc
	subnet := f.call(t, "ec2", "CreateSubnet", map[string]any{"VpcId": *vpc.VpcId, "CidrBlock": "10.71.1.0/24", "AvailabilityZone": "us-east-1a"}).(*ec2api.CreateSubnetResult).Subnet
	template := f.call(t, "ec2", "CreateLaunchTemplate", map[string]any{"LaunchTemplateName": "workers", "LaunchTemplateData": map[string]any{"InstanceType": "t3.nano"}}).(*ec2api.CreateLaunchTemplateResult).LaunchTemplate
	f.call(t, "ec2", "CreateLaunchTemplateVersion", map[string]any{"LaunchTemplateId": *template.LaunchTemplateId, "SourceVersion": "1", "LaunchTemplateData": map[string]any{"InstanceType": "t3.micro"}})
	spec := api.LaunchTemplateSpecification{LaunchTemplateName: new(api.LaunchTemplateName("workers")), Version: new(api.XmlStringMaxLen255("$Latest"))}
	if _, err := f.adapter.Template(f.caller, spec); err == nil {
		t.Fatal("caller without EC2 Describe permission read launch template")
	}
	service, err := f.adapter.Context(f.caller, f.group)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := f.adapter.Template(service, spec)
	if err != nil {
		t.Fatal(err)
	}
	if autoScalingString(resolved.LaunchTemplateId) != string(*template.LaunchTemplateId) || autoScalingString(resolved.LaunchTemplateName) != "workers" || autoScalingString(resolved.Version) != "2" {
		t.Fatalf("alias did not resolve to native identity and numeric version: %#v", resolved)
	}
	selected, err := f.adapter.Placement(service, []string{string(*subnet.SubnetId)}, []string{"us-east-1a"})
	if err != nil || len(selected) != 1 || autoScalingString(selected[0].VpcId) != string(*vpc.VpcId) {
		t.Fatalf("real subnet not resolved: %#v %v", selected, err)
	}
	if _, err := f.adapter.Placement(service, nil, []string{"us-east-1a"}); err == nil {
		t.Fatal("custom subnet silently became a default subnet")
	}
	if _, err := f.adapter.Placement(service, []string{string(*subnet.SubnetId)}, []string{"us-east-1b"}); err == nil {
		t.Fatal("mismatched subnet/AZ accepted")
	}
	other := f.group
	other.Key.Region = "us-west-2"
	metadata := awsctx.FromContext(service)
	metadata.Region = other.Key.Region
	if _, err := f.adapter.Template(awsctx.WithMetadata(service, metadata), spec); err == nil {
		t.Fatal("template crossed its regional scope")
	}
	f.role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Deny","Principal":{"Service":"autoscaling.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	f.update(t)
	if _, err := f.adapter.Context(f.caller, f.group); err == nil {
		t.Fatal("cached session bypassed current role trust")
	}
	f.role.IdentityPolicies.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":"ec2:DescribeSubnets","Resource":"*"}}`
	f.update(t)
	if _, err := f.adapter.Placement(service, []string{string(*subnet.SubnetId)}, nil); err == nil {
		t.Fatal("issued context bypassed current role policy")
	}
}

func TestAutoScalingTemplateValidationKeepsNativeRejectedAudit(t *testing.T) {
	f := newAutoScalingFixture(t)
	template := f.call(t, "ec2", "CreateLaunchTemplate", map[string]any{"LaunchTemplateName": "invalid-version", "LaunchTemplateData": map[string]any{"InstanceType": "t3.nano"}}).(*ec2api.CreateLaunchTemplateResult).LaunchTemplate
	groups := asg.NewMemoryRepository(f.domain)
	ctx, err := apievents.Reserve(f.caller)
	if err != nil {
		t.Fatal(err)
	}
	err = groups.Attempt(ctx, func(tx asg.Transaction) error {
		service, err := f.adapter.Context(tx.Context(), f.group)
		if err != nil {
			return err
		}
		_, err = f.adapter.Template(service, api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255(*template.LaunchTemplateId)), Version: new(api.XmlStringMaxLen255("999999"))})
		return err
	})
	var rejected *awswire.Error
	var completion interface{ RecordRejection(context.Context) error }
	if !errors.As(err, &rejected) || rejected.Code != "ValidationError" || rejected.StatusCode != 400 || !errors.As(err, &completion) {
		t.Fatalf("native ASG template validation contract lost: %v", err)
	}
	if err := completion.RecordRejection(ctx); err != nil {
		t.Fatal(err)
	}
	records, err := f.events.Read(f.root, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range records {
		call := event.APICallCompleted
		if call != nil && call.EventName == "DescribeLaunchTemplateVersions" {
			count++
			if call.ErrorCode != "Client.InvalidLaunchTemplateId.VersionNotFound" || call.ErrorMessage != rejected.Message || event.ParentEventID != apievents.EventID(ctx) {
				t.Fatalf("EC2 template rejection changed: %#v", event)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected one retained native template rejection, got %d", count)
	}
}

func TestAutoScalingNotificationsUsePassRoleCurrentTrustAndRealDestinations(t *testing.T) {
	f := newAutoScalingFixture(t)
	queue := f.call(t, "sqs", "CreateQueue", map[string]any{"QueueName": "hooks"}).(*sqsapi.CreateQueueOutput)
	queueARN := "arn:aws:sqs:us-east-1:123456789012:hooks"
	hook := asg.HookRecord{Key: asg.HookKey{GroupKey: f.group.Key, Name: "launch"}, GroupID: f.group.ID, Data: api.LifecycleHook{RoleARN: new(api.XmlStringMaxLen255(f.role.Arn)), NotificationTargetARN: new(api.NotificationTargetResourceName(queueARN))}}
	adapter := AutoScalingEvents{SQS: f.queues, SNS: f.topics, Roles: f.roles, Clock: f.clock}
	testMessage := []byte(`{"Event":"autoscaling:TEST_NOTIFICATION","LifecycleHookName":"launch"}`)
	if err := adapter.Notify(f.caller, hook, testMessage); err == nil {
		t.Fatal("lifecycle TEST_NOTIFICATION bypassed caller PassRole")
	}
	f.user.IdentityPolicies.Inline["pass"] = `{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"` + f.role.Arn + `","Condition":{"StringEquals":{"iam:PassedToService":"autoscaling.amazonaws.com"},"ArnEquals":{"iam:AssociatedResourceArn":"` + f.group.Key.ARN(f.group.ID) + `"}}}}`
	f.update(t)
	var notificationError *awswire.Error
	if err := adapter.Notify(f.caller, hook, testMessage); !errors.As(err, &notificationError) || notificationError.Code != "ValidationError" {
		t.Fatalf("SendMessage-only notification role must fail native hook admission: %v", err)
	}
	f.role.IdentityPolicies.Inline["lookup"] = `{"Statement":{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}}`
	f.update(t)
	if err := adapter.Notify(f.caller, hook, testMessage); err != nil {
		t.Fatal(err)
	}
	received, rejected := f.queues.ReceiveFromQueue(f.root, queueARN, &sqsapi.ReceiveMessageInput{})
	if rejected != nil || len(received.Messages) != 1 {
		t.Fatalf("native SQS notification absent: %#v %v", received, rejected)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(*received.Messages[0].Body), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["Event"] != "autoscaling:TEST_NOTIFICATION" || payload["AutoScalingGroupARN"] != f.group.Key.ARN(f.group.ID) || payload["AccountId"] != f.group.Key.AccountID || payload["Service"] != "AWS Auto Scaling" {
		t.Fatalf("incorrect SQS test envelope: %#v", payload)
	}
	// A later hook invocation uses the hook role, not the original deployer's
	// now-revoked PassRole authority. The destination's current denial still wins.
	delete(f.user.IdentityPolicies.Inline, "pass")
	f.update(t)
	lifecycleMessage := []byte(`{"LifecycleTransition":"autoscaling:EC2_INSTANCE_LAUNCHING","LifecycleActionToken":"pending-action","Action":"Launch","Origin":"EC2","Destination":"AutoScalingGroup"}`)
	if err := adapter.Notify(f.caller, hook, lifecycleMessage); err != nil {
		t.Fatal(err)
	}
	f.role.IdentityPolicies.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`
	f.update(t)
	if err := adapter.Notify(f.caller, hook, lifecycleMessage); err == nil {
		t.Fatal("notification ignored the current role destination denial")
	}
	delete(f.role.IdentityPolicies.Inline, "deny")
	f.update(t)
	topic := f.call(t, "sns", "CreateTopic", map[string]any{"Name": "hooks"}).(*snsapi.CreateTopicOutput)
	f.call(t, "sqs", "SetQueueAttributes", map[string]any{"QueueUrl": *queue.QueueUrl, "Attributes": map[string]string{"Policy": `{"Statement":{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"` + queueARN + `","Condition":{"ArnEquals":{"aws:SourceArn":"` + string(*topic.TopicArn) + `"}}}}`}})
	f.call(t, "sns", "Subscribe", map[string]any{"TopicArn": *topic.TopicArn, "Protocol": "sqs", "Endpoint": queueARN, "Attributes": map[string]string{"RawMessageDelivery": "true"}})
	hook.Data.NotificationTargetARN = new(api.NotificationTargetResourceName(*topic.TopicArn))
	if err := adapter.Notify(f.caller, hook, lifecycleMessage); err != nil {
		t.Fatal(err)
	}
	if _, err := f.topics.JobDriver().RunDue(f.root, 20); err != nil {
		t.Fatal(err)
	}
	received, rejected = f.queues.ReceiveFromQueue(f.root, queueARN, &sqsapi.ReceiveMessageInput{MaxNumberOfMessages: new(sqsapi.NullableInteger(10))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	found := false
	for _, message := range received.Messages {
		body := string(*message.Body)
		if strings.Contains(body, "LifecycleActionToken: pending-action\n") && strings.Contains(body, "Service: AWS Auto Scaling\n") && strings.Contains(body, "Action: Launch\n") && strings.Contains(body, "Origin: EC2\n") && strings.Contains(body, "Destination: AutoScalingGroup\n") {
			found = true
		}
	}
	if !found {
		t.Fatalf("SNS did not deliver the documented key-value notification: %#v", received.Messages)
	}
	f.role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Deny","Principal":{"Service":"autoscaling.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	f.update(t)
	if err := adapter.Notify(f.caller, hook, lifecycleMessage); err == nil {
		t.Fatal("notification reused cached credentials after current trust was revoked")
	}
}

func TestAutoScalingServiceEventsShareTransactionAndCausality(t *testing.T) {
	f := newAutoScalingFixture(t)
	bus := eventbridge.NewMemoryRepository(f.domain)
	groups := asg.NewMemoryRepository(f.domain)
	adapter := AutoScalingEvents{Publisher: eventbridge.ServicePublisher{Repository: bus, Events: f.events, Clock: f.clock}, Clock: f.clock}
	ctx, err := apievents.Reserve(f.caller)
	if err != nil {
		t.Fatal(err)
	}
	abort := errors.New("abort enclosing group transition")
	if err := groups.Attempt(ctx, func(tx asg.Transaction) error {
		if err := adapter.Publish(tx.Context(), f.group, "EC2 Instance Launch Successful", []byte(`{"AutoScalingGroupName":"workers"}`)); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	records, err := f.events.Read(f.root, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range records {
		if event.EventBridgeAccepted.EventID != "" {
			t.Fatal("rolled-back group transition leaked EventBridge event")
		}
	}
	if err := groups.Update(ctx, func(tx asg.Transaction) error {
		return adapter.Publish(tx.Context(), f.group, "EC2 Instance Launch Successful", []byte(`{"AutoScalingGroupName":"workers"}`))
	}); err != nil {
		t.Fatal(err)
	}
	records, err = f.events.Read(f.root, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var accepted journal.Event
	for _, event := range records {
		if event.EventBridgeAccepted.EventID != "" {
			accepted = event
		}
	}
	if accepted.EventBridgeAccepted.EventID == "" || accepted.ParentEventID != apievents.EventID(ctx) {
		t.Fatalf("service event lost causal origin: %#v", accepted)
	}
	if err := bus.View(f.root, func(r eventbridge.Reader) error {
		event, err := r.Event(accepted.EventBridgeAccepted.EventID)
		if err != nil {
			return err
		}
		if event.Source != "aws.autoscaling" || event.DetailType != "EC2 Instance Launch Successful" || len(event.Resources) != 1 || event.Resources[0] != f.group.Key.ARN(f.group.ID) || event.Time != f.clock.Now() {
			t.Fatalf("incorrect native service event: %#v", event)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAutoScalingEC2RejectedAuditSurvivesEnclosingRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newAutoScalingFixture(t)
			var groups asg.Repository = asg.NewMemoryRepository(f.domain)
			events := f.events
			adapter := f.adapter
			if backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "rejection.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				groups, events = sqlasg.New(db), sqljournal.New(db)
				compute := ec2.New(ec2.Config{Repository: sqlec2.New(db), Authorizer: f.roles.Authorizer, Clock: f.clock, Recorder: apievents.New(events)})
				t.Cleanup(func() { compute.Close() })
				adapter = &AutoScaling{EC2: compute, Roles: f.roles}
			}
			parent := asg.New(asg.Config{Repository: groups, Clock: f.clock, Recorder: apievents.New(events)})
			ctx, err := apievents.Reserve(f.caller)
			if err != nil {
				t.Fatal(err)
			}
			err = groups.Attempt(ctx, func(tx asg.Transaction) error {
				_, err := adapter.Placement(tx.Context(), []string{"subnet-0123456789abcdef0"}, nil)
				return err
			})
			var rejected *awswire.Error
			var completion interface{ RecordRejection(context.Context) error }
			if !errors.As(err, &rejected) || !errors.As(err, &completion) {
				t.Fatalf("native dependency rejection lost: %v", err)
			}
			if err := completion.RecordRejection(ctx); err != nil {
				t.Fatal(err)
			}
			model, _ := awscatalog.LookupService("autoscaling")
			operation, _ := model.Operation("CreateAutoScalingGroup")
			request := awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &api.CreateAutoScalingGroupType{AutoScalingGroupName: new(api.XmlStringMaxLen255(f.group.Key.Name))}}
			if err := parent.RecordRequestError(ctx, request, rejected); err != nil {
				t.Errorf("parent rejection recording failed after child completion: %v", err)
			}
			records, err := events.Read(f.root, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			childCount, parentCount := 0, 0
			for _, event := range records {
				call := event.APICallCompleted
				if call == nil {
					continue
				}
				switch call.EventName {
				case "DescribeSubnets":
					childCount++
					if call.EventID == apievents.EventID(ctx) || call.EventID == "" {
						t.Errorf("child rejection reused parent outcome identity %q", call.EventID)
					}
					if call.ErrorCode != "Client."+rejected.Code || event.ParentEventID != apievents.EventID(ctx) {
						t.Errorf("native rejection changed: %#v", event)
					}
				case "CreateAutoScalingGroup":
					parentCount++
					if call.EventID != apievents.EventID(ctx) || call.ErrorCode != rejected.Code {
						t.Errorf("parent rejection changed: %#v", event)
					}
				}
			}
			if childCount != 1 || parentCount != 1 {
				t.Fatalf("expected one retained child and parent rejection, got child=%d parent=%d", childCount, parentCount)
			}
		})
	}
}

func TestAutoScalingEC2InitializationIsNotImpairment(t *testing.T) {
	for _, test := range []struct {
		name, system, guest string
		healthy             bool
	}{
		{"initializing-system", "", "passed", true},
		{"initializing-guest", "passed", "", true},
		{"insufficient-data", "insufficient-data", "insufficient-data", true},
		{"passed", "passed", "passed", true},
		{"impaired-system", "failed", "passed", false},
		{"impaired-guest", "passed", "failed", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAutoScalingFixture(t)
			repository := ec2.NewMemoryRepository(f.domain)
			compute := ec2.New(ec2.Config{Repository: repository, Authorizer: f.roles.Authorizer, Clock: f.clock})
			t.Cleanup(func() { compute.Close() })
			f.adapter.EC2 = compute
			key := ec2.ResourceKey{Scope: ec2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: "i-12345678"}
			record := ec2.InstanceRecord{Key: key, ReservationID: "r-12345678", Data: ec2api.Instance{
				InstanceId: new(ec2api.String(key.ID)),
				State:      &ec2api.InstanceState{Code: new(ec2api.Integer(16)), Name: new(ec2api.InstanceStateName("running"))},
			}, Health: ec2.InstanceHealthRecord{
				System: ec2.InstanceStatusCheck{Status: ec2api.StatusType(test.system)},
				Guest:  ec2.InstanceStatusCheck{Status: ec2api.StatusType(test.guest)},
			}}
			if err := repository.Update(f.root, func(tx ec2.Transaction) error {
				if err := tx.PutReservation(ec2.ReservationRecord{Key: ec2.ResourceKey{Scope: key.Scope, ID: record.ReservationID}, InstanceIDs: []string{key.ID}}); err != nil {
					return err
				}
				return tx.PutInstance(record)
			}); err != nil {
				t.Fatal(err)
			}
			service, err := f.adapter.Context(f.caller, f.group)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := f.adapter.Observe(service, []string{key.ID})
			if err != nil {
				t.Fatal(err)
			}
			if len(observed) != 1 || observed[0].Healthy != test.healthy {
				t.Fatalf("native EC2 status interpretation: system=%q guest=%q observations=%+v", test.system, test.guest, observed)
			}
		})
	}
}
