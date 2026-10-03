package stackd_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	ebsdomain "stackd/internal/services/ebs"
)

type asgControlRow struct {
	Label, Service, Operation, Code, Caller string
	Input, Output                           json.RawMessage
	StartedAt                               time.Time `json:"started_at"`
	HTTPStatus                              int       `json:"http_status"`
}

type asgControlFixture struct {
	Account, Region string
	Calls           []asgControlRow
}

func asgFixture(t *testing.T, name string) asgControlFixture {
	t.Helper()
	var fixture asgControlFixture
	awsReadFixture(t, "autoscaling/"+name+".json", &fixture)
	return fixture
}

func (f asgControlFixture) row(t *testing.T, label string) asgControlRow {
	t.Helper()
	for _, row := range f.Calls {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("native Auto Scaling row %q missing", label)
	return asgControlRow{}
}

// Zone IDs can overlap across accounts (native az6 -> local az1, native az1
// -> local az2). Replace simultaneously, never recursively through local IDs.
func asgReplace(value string, bindings map[string]string) string {
	keys := make([]string, 0, len(bindings))
	for key := range bindings {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	pairs := make([]string, 0, 2*len(keys))
	for _, key := range keys {
		pairs = append(pairs, key, bindings[key])
	}
	return strings.NewReplacer(pairs...).Replace(value)
}

func asgClient(c cloudClients, region string, identity aws.Credentials, transport aws.HTTPClient) *autoscaling.Client {
	return autoscaling.New(autoscaling.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken), HTTPClient: transport, RetryMaxAttempts: 1})
}

func asgRoot() aws.Credentials {
	return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}
}

func asgEC2(c cloudClients, region string) *ec2.Client {
	return ec2.New(ec2.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

// Query's empty collection envelope decodes as nil; botocore's capture renders
// the same collection as []. All other fields, including absent pointers and
// explicit zero/false values, are compared through the independent Go SDK shape.
func asgCompare(t *testing.T, path string, want, got any, bindings map[string]string) {
	t.Helper()
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		if !ok || len(expected) != len(actual) {
			t.Fatalf("%s native fields %#v; got %#v", path, expected, got)
		}
		keys := make([]string, 0, len(expected))
		for key := range expected {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			value, present := actual[key]
			if !present {
				t.Fatalf("%s.%s missing", path, key)
			}
			if key == "CreatedTime" && expected[key] != nil {
				before, beforeOK := expected[key].(string)
				after, afterOK := value.(string)
				stamp, err := time.Parse(time.RFC3339Nano, after)
				if !beforeOK || !afterOK || err != nil || stamp.IsZero() {
					t.Fatalf("%s.%s invalid creation timestamp: %#v", path, key, value)
				}
				aasBind(t, bindings, before, after)
				continue
			}
			if key == "VPCZoneIdentifier" && expected[key] != nil {
				before := strings.Split(asgReplace(expected[key].(string), bindings), ",")
				after := strings.Split(value.(string), ",")
				slices.Sort(before)
				slices.Sort(after)
				if !slices.Equal(before, after) {
					t.Fatalf("%s.%s native subnets %v; got %v", path, key, before, after)
				}
				continue
			}
			asgCompare(t, path+"."+key, expected[key], value, bindings)
		}
	case []any:
		actual, ok := got.([]any)
		if got == nil && len(expected) == 0 {
			return
		}
		if !ok || len(expected) != len(actual) {
			t.Fatalf("%s native list %#v; got %#v", path, expected, got)
		}
		// These APIs return sets; termination policy and step adjustment order
		// remains significant and is deliberately not normalized.
		field := path[strings.LastIndex(path, ".")+1:]
		switch field {
		case "Tags", "AvailabilityZones", "AvailabilityZoneIds", "SuspendedProcesses", "LifecycleHooks", "EnabledMetrics", "Metrics", "Granularities", "Processes", "TerminationPolicyTypes":
			key := func(v any, native bool) string {
				data, _ := json.Marshal(v)
				if native {
					return asgReplace(string(data), bindings)
				}
				return string(data)
			}
			slices.SortFunc(expected, func(a, b any) int { return strings.Compare(key(a, true), key(b, true)) })
			slices.SortFunc(actual, func(a, b any) int { return strings.Compare(key(a, false), key(b, false)) })
		}
		for i, value := range expected {
			asgCompare(t, fmt.Sprintf("%s[%d]", path, i), value, actual[i], bindings)
		}
	case string:
		actual, ok := got.(string)
		if !ok {
			t.Fatalf("%s native %q; got %#v", path, expected, got)
		}
		before, after := aasIdentity.FindAllString(expected, -1), aasIdentity.FindAllString(actual, -1)
		if len(before) != len(after) {
			t.Fatalf("%s native identity shape %q; got %q", path, expected, actual)
		}
		for i, id := range before {
			aasBind(t, bindings, id, after[i])
		}
		if relocated := asgReplace(expected, bindings); relocated != actual {
			t.Fatalf("%s native %q; got %q", path, relocated, actual)
		}
	case nil:
		if actual, ok := got.([]any); ok && len(actual) == 0 {
			return
		}
		if got != nil {
			t.Fatalf("%s native absent; got %#v", path, got)
		}
	default:
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s native %#v; got %#v", path, want, got)
		}
	}
}

func asgReplay(t *testing.T, c cloudClients, region string, row asgControlRow, bindings map[string]string, identity aws.Credentials) {
	t.Helper()
	wire := &awstest.WireClient{Client: c.server.Client()}
	actual, err := awstest.CallSDK(t.Context(), asgClient(c, region, identity, wire), row.Operation, json.RawMessage(asgReplace(string(row.Input), bindings)))
	if row.Code != "Success" {
		assertAPIError(t, err, row.Code)
	} else if err != nil {
		t.Fatal(err)
	}
	if wire.Status != row.HTTPStatus {
		t.Fatalf("HTTP status %d, native %d; body %s", wire.Status, row.HTTPStatus, wire.Body)
	}
	if err != nil {
		return
	}
	expected := reflect.New(reflect.TypeOf(actual).Elem()).Interface()
	if err := awstest.DecodeSDK(row.Output, expected); err != nil {
		t.Fatal(err)
	}
	asgCompare(t, row.Label, ec2NetworkDocument(t, expected), ec2NetworkDocument(t, actual), bindings)
}

// Dependencies are real production EC2/IAM/STS resources. Only generated IDs
// are relocated; no executor is installed and every selected launch is either
// desired-zero or explicitly suspended before increasing desired capacity.
func asgPrerequisite(t *testing.T, c cloudClients, region string, row asgControlRow, bindings map[string]string, sessions map[string]aws.Credentials) {
	t.Helper()
	var client any
	switch row.Service {
	case "ec2":
		client = asgEC2(c, region)
	case "iam":
		client = c.iam("test", "test", "")
	case "sts":
		client = c.sts("test", "test", "")
	default:
		t.Fatalf("unsupported prerequisite %s", row.Service)
	}
	out, err := awstest.CallSDK(t.Context(), client, row.Operation, json.RawMessage(asgReplace(string(row.Input), bindings)))
	if row.Code != "Success" {
		assertAPIError(t, err, row.Code)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	native := ecsControlBody(t, row.Output)
	switch actual := out.(type) {
	case *ec2.CreateVpcOutput:
		aasBind(t, bindings, native["Vpc"].(map[string]any)["VpcId"].(string), aws.ToString(actual.Vpc.VpcId))
	case *ec2.CreateSubnetOutput:
		subnet := native["Subnet"].(map[string]any)
		aasBind(t, bindings, subnet["SubnetId"].(string), aws.ToString(actual.Subnet.SubnetId))
		aasBind(t, bindings, subnet["AvailabilityZoneId"].(string), aws.ToString(actual.Subnet.AvailabilityZoneId))
	case *ec2.CreateSecurityGroupOutput:
		aasBind(t, bindings, native["GroupId"].(string), aws.ToString(actual.GroupId))
	case *ec2.CreateLaunchTemplateOutput:
		aasBind(t, bindings, native["LaunchTemplate"].(map[string]any)["LaunchTemplateId"].(string), aws.ToString(actual.LaunchTemplate.LaunchTemplateId))
	case *sts.AssumeRoleOutput:
		input := ecsControlBody(t, row.Input)
		sessions[input["RoleSessionName"].(string)] = aws.Credentials{AccessKeyID: aws.ToString(actual.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(actual.Credentials.SecretAccessKey), SessionToken: aws.ToString(actual.Credentials.SessionToken)}
	}
}

func asgControlNetwork(t *testing.T, c cloudClients, f asgControlFixture, bindings map[string]string) {
	t.Helper()
	client := asgEC2(c, f.Region)
	vpc, err := client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.238.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	group := ecsControlBody(t, f.row(t, "describe-created").Output)["AutoScalingGroups"].([]any)[0].(map[string]any)
	subnets := strings.Split(group["VPCZoneIdentifier"].(string), ",")
	for i, id := range subnets {
		zone := group["AvailabilityZones"].([]any)[i].(string)
		subnet, err := client.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: aws.String(fmt.Sprintf("10.238.%d.0/24", i)), AvailabilityZone: &zone})
		if err != nil {
			t.Fatal(err)
		}
		aasBind(t, bindings, id, aws.ToString(subnet.Subnet.SubnetId))
		aasBind(t, bindings, group["AvailabilityZoneIds"].([]any)[i].(string), aws.ToString(subnet.Subnet.AvailabilityZoneId))
	}
}

func asgAssertServiceRole(t *testing.T, c cloudClients, account string) {
	t.Helper()
	role, err := c.iam("test", "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("AWSServiceRoleForAutoScaling")})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(role.Role.Arn) != "arn:aws:iam::"+account+":role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling" {
		t.Fatalf("Auto Scaling did not retain its authoritative IAM role: %+v", role.Role)
	}
}

// A real completed EBS snapshot and registered AMI satisfy EC2 admission.
// This empty image is a control-plane prerequisite, not a bootable guest;
// actual launches are excluded from these fast tests and proved separately.
func asgRetainedCloud(t *testing.T, backend string, fixture asgControlFixture, source *clock.Manual, bindings map[string]string, opened func(*stackd.Stack)) (cloudClients, func() cloudClients) {
	t.Helper()
	var active *stackd.Stack
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		cloud, server := startPublicCloud(t, config)
		active = cloud
		if opened != nil {
			opened(cloud)
		}
		return cloud, server
	})
	direct := ebs.New(ebs.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
	snapshot, err := direct.StartSnapshot(t.Context(), &ebs.StartSnapshotInput{VolumeSize: aws.Int64(8)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := direct.CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: snapshot.SnapshotId, ChangedBlocksCount: aws.Int32(0)}); err != nil {
		t.Fatal(err)
	}
	source.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
	if _, err := active.RunDueJobs(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	image, err := asgEC2(clients, fixture.Region).RegisterImage(t.Context(), &ec2.RegisterImageInput{Name: aws.String("asg-control-image"), Architecture: ec2types.ArchitectureValuesX8664, VirtualizationType: aws.String("hvm"), RootDeviceName: aws.String("/dev/xvda"), BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String("/dev/xvda"), Ebs: &ec2types.EbsBlockDevice{SnapshotId: snapshot.SnapshotId, VolumeSize: aws.Int32(8), VolumeType: ec2types.VolumeTypeGp3, DeleteOnTermination: aws.Bool(true)}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Calls {
		if row.Operation == "CreateLaunchTemplate" {
			template := ecsControlBody(t, row.Input)["LaunchTemplateData"].(map[string]any)
			bindings[template["ImageId"].(string)] = aws.ToString(image.ImageId)
			break
		}
	}
	return clients, reopen
}

func TestAutoScalingNativeControlsAcrossReopen(t *testing.T) {
	fixture := asgFixture(t, "controls")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Calls[0].StartedAt.Add(-time.Minute))
			bindings := map[string]string{}
			clients, reopen := asgRetainedCloud(t, backend, fixture, source, bindings, nil)
			asgControlNetwork(t, clients, fixture, bindings)
			for _, row := range fixture.Calls {
				// The repeated native post-delete observations include transient
				// deletion states. Compare the final empty inventory, not latency.
				if row.Label == "confirm-group-absent" && len(ecsControlBody(t, row.Output)["AutoScalingGroups"].([]any)) != 0 {
					continue
				}
				if row.StartedAt.After(source.Now()) {
					source.Advance(row.StartedAt.Sub(source.Now()))
				}
				if !t.Run(row.Label, func(t *testing.T) {
					if row.Service == "autoscaling" {
						asgReplay(t, clients, fixture.Region, row, bindings, asgRoot())
					} else {
						asgPrerequisite(t, clients, fixture.Region, row, bindings, nil)
					}
					if row.Label == "create-group" {
						asgAssertServiceRole(t, clients, fixture.Account)
					}
				}) {
					return
				}
				if row.Code == "Success" && !strings.HasPrefix(row.Operation, "Describe") {
					clients = reopen()
				}
			}
		})
	}
}

func TestAutoScalingNativeAdmissionAcrossReopen(t *testing.T) {
	fixture := asgFixture(t, "lifecycle_native")
	labels := []string{
		"owned-vpc", "owned-subnet", "owned-group", "owned-guest-role", "owned-profile", "owned-profile-role", "owned-launcher-role", "owned-launch-template-v1",
		"create-main-zero", "main-zero-initial", "bounded-asg-launcher-policy", "allowed-assume", "allowed-create-zero", "allowed-delete-zero",
		"denied-run-assume", "denied-run-create-zero", "denied-pass-assume", "denied-pass-create-zero",
		"denied-run-update-capacity-only", "denied-run-update-template", "denied-pass-update-capacity-only", "denied-pass-update-template",
		"invalid-create-min-over-max", "invalid-create-desired-over-max", "invalid-create-negative-min", "invalid-create-missing-template-version",
		"invalid-desired-negative", "invalid-desired-over-max", "invalid-update-min-over-max",
		"schedule-retired-time-only", "schedule-retired-time-described", "schedule-retired-time-delete", "delete-nonexistent-policy",
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.row(t, "owned-vpc").StartedAt.Add(-time.Minute))
			bindings := map[string]string{"arn:aws:iam::" + fixture.Account + ":user/Delegated": "arn:aws:iam::" + fixture.Account + ":root"}
			clients, reopen := asgRetainedCloud(t, backend, fixture, source, bindings, nil)
			sessions := map[string]aws.Credentials{"owner": asgRoot()}
			for _, label := range labels {
				row := fixture.row(t, label)
				if row.StartedAt.After(source.Now()) {
					source.Advance(row.StartedAt.Sub(source.Now()))
				}
				if !t.Run(label, func(t *testing.T) {
					if row.Service == "autoscaling" {
						asgReplay(t, clients, fixture.Region, row, bindings, sessions[row.Caller])
					} else {
						asgPrerequisite(t, clients, fixture.Region, row, bindings, sessions)
					}
				}) {
					return
				}
				if row.Code == "Success" && row.Service != "sts" && !strings.HasPrefix(row.Operation, "Describe") {
					clients = reopen()
				}
			}
			// The recovery capture used the same two create-time hook
			// specifications. Relocate only its owned group name; no instance
			// lifecycle transition or retained capacity is fabricated here.
			main := ecsControlBody(t, fixture.row(t, "create-main-zero").Input)["AutoScalingGroupName"].(string)
			hooks := fixture.row(t, "recovery/owned-hook-inventory-at-final-boundary")
			recovery := ecsControlBody(t, hooks.Input)["AutoScalingGroupName"].(string)
			bindings[recovery] = main
			t.Run("create-time-hooks-retained-after-reopen", func(t *testing.T) {
				clients = reopen()
				asgReplay(t, clients, fixture.Region, hooks, bindings, asgRoot())
			})
			for _, label := range []string{"recovery/delete-nonexistent-hook", "recovery/delete-nonexistent-schedule"} {
				t.Run(label, func(t *testing.T) {
					asgReplay(t, clients, fixture.Region, fixture.row(t, label), bindings, asgRoot())
				})
			}
			// Failed admissions must not leave groups behind, and rejected
			// configuration updates must preserve the original native inventory.
			t.Run("rejected-admissions-leave-only-main", func(t *testing.T) {
				row := fixture.row(t, "main-zero-initial")
				row.Input = json.RawMessage(`{}`)
				asgReplay(t, clients, fixture.Region, row, bindings, asgRoot())
			})
		})
	}
}

func TestAutoScalingNativeCatalogs(t *testing.T) {
	fixture := asgFixture(t, "lifecycle_native")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account})
			for _, label := range []string{"recovery/catalog-describe_metric_collection_types", "recovery/catalog-describe_termination_policy_types", "recovery/catalog-describe_scaling_process_types"} {
				t.Run(label, func(t *testing.T) {
					asgReplay(t, clients, fixture.Region, fixture.row(t, label), map[string]string{}, asgRoot())
				})
				clients = reopen()
			}
		})
	}
}
