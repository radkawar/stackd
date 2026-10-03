package stackd_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

const eventPermissionOwner = "123456789012"
const eventPermissionMember = "222222222222"
const eventPermissionMemberRole = "OrganizationAccountAccessRole"

type eventPermissionObservation struct {
	Case, Action, Actor, Service, Code string
	Input                              json.RawMessage
	Output                             map[string]any
}

type eventPermissionPolicy struct {
	Version   string
	Statement []map[string]any
}

type eventPermissionReplay struct {
	cloud          *stackd.Stack
	clients        cloudClients
	rows           map[string]eventPermissionObservation
	actors         map[string]aws.Credentials
	roleIDs        map[string]string
	creator        []string
	administration []string
	restart        func()
	clock          *clock.Manual
}

func eventPermissionBackends(t *testing.T, run func(*testing.T, *eventPermissionReplay)) {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/eventbridge/permissions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations     []eventPermissionObservation
		CreatorAuthority struct {
			Observations []eventPermissionObservation
		} `json:"creator_authority"`
		AdministrationAuthority struct {
			Observations []eventPermissionObservation
		} `json:"permission_administration_authority"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := &eventPermissionReplay{
				rows: make(map[string]eventPermissionObservation), roleIDs: make(map[string]string),
				actors: map[string]aws.Credentials{"owner": {AccessKeyID: eventPermissionOwner, SecretAccessKey: "test"}},
				clock:  clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)),
			}
			for _, row := range fixture.Observations {
				f.rows[row.Case] = row
			}
			for _, row := range fixture.CreatorAuthority.Observations {
				row.Service = "events"
				f.rows[row.Case] = row
				f.creator = append(f.creator, row.Case)
			}
			for _, row := range fixture.AdministrationAuthority.Observations {
				f.rows[row.Case] = row
				if row.Actor == "member" || strings.HasPrefix(row.Case, "wildcard-") || row.Case == "grant-member-create" {
					f.administration = append(f.administration, row.Case)
				}
			}
			path := filepath.Join(t.TempDir(), "permissions.sqlite")
			backends := storage.NewMemory()
			closeStack, closeDatabase := func() {}, func() {}
			f.restart = func() {
				closeStack()
				closeDatabase()
				if backend == "sqlite" {
					backends, closeDatabase = openSQLiteBackends(t, path)
				}
				f.cloud, f.clients, closeStack = startEventDeliveryCloud(t, backends, f.clock)
			}
			f.restart()
			run(t, f)
		})
	}
}

func (f *eventPermissionReplay) eventClient(actor string) *eventbridge.Client {
	c := f.actors[actor]
	return eventbridge.New(eventbridge.Options{Region: "us-east-1", BaseEndpoint: aws.String(f.clients.server.URL), HTTPClient: f.clients.server.Client(), RetryMaxAttempts: 1,
		Credentials: credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)})
}

func (f *eventPermissionReplay) invoke(t *testing.T, name string) any {
	t.Helper()
	row, exists := f.rows[name]
	if !exists {
		t.Fatalf("native permission row %q is missing", name)
	}
	actor := f.actors[row.Actor]
	var client any
	switch row.Service {
	case "events":
		client = f.eventClient(row.Actor)
	case "iam":
		client = f.clients.iam(actor.AccessKeyID, actor.SecretAccessKey, actor.SessionToken)
	case "sts":
		client = f.clients.sts(actor.AccessKeyID, actor.SecretAccessKey, actor.SessionToken)
	default:
		t.Fatalf("permission replay does not select service %q", row.Service)
	}
	output, err := awstest.CallSDK(t.Context(), client, row.Action, row.Input)
	code := "Success"
	if err != nil {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			t.Fatal(err)
		}
		code = apiErr.ErrorCode()
	}
	if code != row.Code {
		t.Fatalf("%s: native=%s local=%s: %v", name, row.Code, code, err)
	}
	if err != nil {
		return nil
	}
	switch output := output.(type) {
	case *iam.CreateRoleOutput:
		native := row.Output["Role"].(map[string]any)
		f.roleIDs[native["RoleId"].(string)] = aws.ToString(output.Role.RoleId)
		if aws.ToString(output.Role.Arn) != native["Arn"] || aws.ToString(output.Role.RoleName) != native["RoleName"] {
			t.Fatalf("%s: role identity differs: %+v", name, output.Role)
		}
	case *sts.AssumeRoleOutput:
		c := output.Credentials
		f.actors["owned-role"] = aws.Credentials{AccessKeyID: aws.ToString(c.AccessKeyId), SecretAccessKey: aws.ToString(c.SecretAccessKey), SessionToken: aws.ToString(c.SessionToken)}
		if aws.ToString(output.AssumedRoleUser.Arn) != row.Output["AssumedRoleUser"].(map[string]any)["Arn"] {
			t.Fatalf("%s: session principal differs: %+v", name, output.AssumedRoleUser)
		}
	}
	if row.Service == "events" {
		encoded, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		var actual map[string]any
		if err := json.Unmarshal(encoded, &actual); err != nil {
			t.Fatal(err)
		}
		got, want := f.normalizeOutput(actual), f.normalizeOutput(row.Output)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: native=%v\nlocal=%v", name, want, got)
		}
	}
	return output
}

// Only generated identifiers, service timestamps, and SDK metadata vary. Policy
// principals keep their identity across role recreation rather than normalizing
// every role ID to one placeholder.
func (f *eventPermissionReplay) normalizeOutput(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any)
		for key, value := range v {
			if value == nil || key == "ResultMetadata" {
				continue
			}
			switch key {
			case "CreationTime", "LastModifiedTime":
				out[key] = "<time>"
			case "EventId":
				if value != "" {
					out[key] = "<event-id>"
				}
			case "Policy":
				document := value.(string)
				for native, actual := range f.roleIDs {
					document = strings.ReplaceAll(document, native, actual)
				}
				var policy any
				if json.Unmarshal([]byte(document), &policy) == nil {
					out[key] = policy
				} else {
					out[key] = document
				}
			default:
				out[key] = f.normalizeOutput(value)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, value := range v {
			out[i] = f.normalizeOutput(value)
		}
		return out
	default:
		return v
	}
}

func (f *eventPermissionReplay) createMember(t *testing.T) {
	t.Helper()
	member := f.clients.iam(eventPermissionMember, "test", "")
	var input iam.CreateRoleInput
	if err := json.Unmarshal(f.rows["create-owned-role"].Input, &input); err != nil {
		t.Fatal(err)
	}
	input.RoleName = aws.String(eventPermissionMemberRole)
	role, err := member.CreateRole(t.Context(), &input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.AttachRolePolicy(t.Context(), &iam.AttachRolePolicyInput{RoleName: role.Role.RoleName, PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")}); err != nil {
		t.Fatal(err)
	}
	session, err := f.clients.sts(eventPermissionOwner, "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("stackd-events-permissions"), DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal(err)
	}
	c := session.Credentials
	f.actors["member"] = aws.Credentials{AccessKeyID: aws.ToString(c.AccessKeyId), SecretAccessKey: aws.ToString(c.SecretAccessKey), SessionToken: aws.ToString(c.SessionToken)}
}

func (f *eventPermissionReplay) policy(t *testing.T, name string) (eventbridge.PutPermissionInput, eventPermissionPolicy) {
	t.Helper()
	var input eventbridge.PutPermissionInput
	if err := json.Unmarshal(f.rows[name].Input, &input); err != nil {
		t.Fatal(err)
	}
	var policy eventPermissionPolicy
	if err := json.Unmarshal([]byte(aws.ToString(input.Policy)), &policy); err != nil {
		t.Fatal(err)
	}
	return input, policy
}

func TestEventBridgeNativeMemberBusPermissionsSDK(t *testing.T) {
	eventPermissionBackends(t, func(t *testing.T, f *eventPermissionReplay) {
		f.createMember(t)
		for _, name := range []string{
			"create-bus", "create-authorization-bus", "member-events-without-resource-grant", "grant-member-filtered-events",
			"member-events-allowed", "member-events-wrong-source", "member-events-wrong-detail-type", "member-mixed-authorized-events",
			"grant-only-bus-invocations", "member-direct-events-bus-invocation-true", "grant-member-strict-creator", "member-create-strict-creator",
			"grant-member-creator-if-exists", "member-create-creator-if-exists", "owner-describe-member-rule", "member-describe-own-rule",
			"member-disable-own-rule", "member-put-own-target", "member-list-own-targets", "member-remove-own-target", "owner-create-rule",
			"member-update-owner-rule", "member-describe-owner-rule", "member-delete-owner-rule", "member-delete-own-rule", "owner-delete-rule",
		} {
			if !t.Run(name, func(t *testing.T) {
				// Both the bus grant and the IAM-issued caller survive reopening.
				if name == "member-events-allowed" || name == "member-describe-own-rule" {
					f.restart()
				}
				before := acceptedPermissionEvents(t, f.cloud)
				f.invoke(t, name)
				if name == "member-mixed-authorized-events" && acceptedPermissionEvents(t, f.cloud) != before {
					t.Fatal("request-level denial committed an authorized entry from the rejected batch")
				}
			}) {
				return
			}
		}
	})
}

func acceptedPermissionEvents(t *testing.T, cloud *stackd.Stack) int {
	t.Helper()
	rows, err := cloud.Events(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range rows {
		if row.EventBridgeAccepted.EventID != "" {
			count++
		}
	}
	return count
}

func TestEventBridgeNativeRolePrincipalLifetimeSDK(t *testing.T) {
	eventPermissionBackends(t, func(t *testing.T, f *eventPermissionReplay) {
		for _, name := range []string{
			"create-owned-role", "create-role-bus", "full-existing-role-principal", "describe-role-before-delete", "assume-original-role", "original-role-events",
			"delete-owned-role", "describe-role-deleted-after-sixty-seconds", "recreate-owned-role", "assume-recreated-role", "describe-role-after-recreate",
			"recreated-role-events-before-rebind", "recreated-role-events-after-sixty-seconds", "describe-role-after-sixty-seconds", "resubmit-identical-role-policy",
			"describe-role-after-identical-policy", "recreated-role-events-after-identical-policy", "remove-bound-role-statement", "describe-after-role-statement-removed",
			"rebind-role-principal", "describe-role-after-rebind", "recreated-role-events-after-rebind",
		} {
			if !t.Run(name, func(t *testing.T) {
				if name == "describe-role-deleted-after-sixty-seconds" || name == "recreated-role-events-after-sixty-seconds" {
					if err := f.clock.Advance(time.Minute); err != nil {
						t.Fatal(err)
					}
				}
				if name == "original-role-events" || name == "describe-role-deleted-after-sixty-seconds" || name == "recreated-role-events-after-identical-policy" || name == "recreated-role-events-after-rebind" {
					f.restart()
				}
				f.invoke(t, name)
			}) {
				return
			}
		}
	})
}

func TestEventBridgeNativeCreatorAuthoritySDK(t *testing.T) {
	eventPermissionBackends(t, func(t *testing.T, f *eventPermissionReplay) {
		f.createMember(t)
		for _, name := range f.creator {
			if !t.Run(name, func(t *testing.T) { f.invoke(t, name) }) {
				return
			}
		}
	})
}

func TestEventBridgeNativePermissionAdministrationSDK(t *testing.T) {
	eventPermissionBackends(t, func(t *testing.T, f *eventPermissionReplay) {
		f.createMember(t)
		// Service tests own the initial exact-action grammar rejections. These
		// rows add real caller identity: member names stay in the member account,
		// and accepted wildcard bus denies do not control owner administration.
		for _, name := range f.administration {
			if !t.Run(name, func(t *testing.T) {
				if name == "wildcard-owner-remove-missing" || name == "wildcard-delete-owner" {
					f.restart()
				}
				f.invoke(t, name)
			}) {
				return
			}
		}
	})
}

// Native account and role-principal grants above cover different IAM paths.
// These additional integration checks exercise their shared authorization
// boundary using the captured allow/deny documents; they are not extra native
// invocation observations in permissions.json.
func TestEventBridgeAccountGrantAndExplicitDeniesSDK(t *testing.T) {
	eventPermissionBackends(t, func(t *testing.T, f *eventPermissionReplay) {
		f.createMember(t)
		bus := f.invoke(t, "create-bus").(*eventbridge.CreateEventBusOutput)
		f.invoke(t, "simple-first")
		var input eventbridge.PutEventsInput
		if err := json.Unmarshal(f.rows["member-events-allowed"].Input, &input); err != nil {
			t.Fatal(err)
		}
		input.Entries[0].EventBusName = bus.EventBusArn
		publish := func(t *testing.T, actor, code string) {
			t.Helper()
			out, err := f.eventClient(actor).PutEvents(t.Context(), &input)
			if code != "Success" {
				assertAPIError(t, err, code)
			} else if err != nil || out.FailedEntryCount != 0 || len(out.Entries) != 1 || aws.ToString(out.Entries[0].EventId) == "" {
				t.Fatalf("%s event publication failed: %+v, %v", actor, out, err)
			}
		}
		member := f.clients.iam(eventPermissionMember, "test", "")
		t.Run("account-grant-still-requires-caller-allow", func(t *testing.T) {
			publish(t, "member", "Success")
			if _, err := member.DetachRolePolicy(t.Context(), &iam.DetachRolePolicyInput{RoleName: aws.String(eventPermissionMemberRole), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")}); err != nil {
				t.Fatal(err)
			}
			publish(t, "member", "AccessDeniedException")
			if _, err := member.AttachRolePolicy(t.Context(), &iam.AttachRolePolicyInput{RoleName: aws.String(eventPermissionMemberRole), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")}); err != nil {
				t.Fatal(err)
			}
			publish(t, "member", "Success")
		})
		t.Run("caller-explicit-deny", func(t *testing.T) {
			_, policy := f.policy(t, "full-deny")
			// An identity policy gets its principal from the role attachment.
			delete(policy.Statement[0], "Principal")
			document, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			putRolePolicy(t, member, eventPermissionMemberRole, string(document))
			publish(t, "member", "AccessDeniedException")
			publish(t, "owner", "Success")
			if _, err := member.DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: aws.String(eventPermissionMemberRole), PolicyName: aws.String("access")}); err != nil {
				t.Fatal(err)
			}
			publish(t, "member", "Success")
		})
		t.Run("bus-owner-explicit-deny-survives-reopen", func(t *testing.T) {
			input, allow := f.policy(t, "full-two-statements")
			_, deny := f.policy(t, "full-deny")
			allow.Statement = append(allow.Statement, deny.Statement...)
			document, err := json.Marshal(allow)
			if err != nil {
				t.Fatal(err)
			}
			input.Policy = aws.String(string(document))
			if _, err := f.eventClient("owner").PutPermission(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
			f.restart()
			publish(t, "member", "AccessDeniedException")
			publish(t, "owner", "Success")
		})
	})
}
