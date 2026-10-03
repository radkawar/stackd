package eventbridge_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awstest"
	service "stackd/internal/services/eventbridge"
)

type permissionCase struct {
	Case, Action, Code, Actor, Service string
	Input                              json.RawMessage
	Output                             map[string]any
}

type permissionCapture struct {
	Observations   []permissionCase
	PolicyLanguage struct {
		Observations []permissionCase
	} `json:"policy_language"`
	ActionAdmission struct {
		Observations []permissionCase
	} `json:"action_admission"`
	AdministrationAuthority struct {
		Observations []permissionCase
	} `json:"permission_administration_authority"`
}

func permissionFixture(t *testing.T) permissionCapture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/eventbridge/permissions.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture permissionCapture
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	return capture
}

type permissionAccounts map[string]map[string]bool

func (a permissionAccounts) AccountExists(_ context.Context, partition, account string) (bool, error) {
	return a[partition][account], nil
}

func permissionOutput(t *testing.T, input any) any {
	t.Helper()
	switch input := input.(type) {
	case map[string]any:
		for key, item := range input {
			if key == "Policy" {
				if raw, ok := item.(string); ok {
					var document any
					if err := json.Unmarshal([]byte(raw), &document); err != nil {
						t.Fatal(err)
					}
					// AWS reorders statements between policy reads; IAM policy
					// statement order does not change their authorization meaning.
					statements := document.(map[string]any)["Statement"].([]any)
					sort.Slice(statements, func(i, j int) bool {
						return statements[i].(map[string]any)["Sid"].(string) < statements[j].(map[string]any)["Sid"].(string)
					})
					input[key] = document
				}
			} else {
				input[key] = permissionOutput(t, item)
			}
		}
	case []any:
		for i, item := range input {
			input[i] = permissionOutput(t, item)
		}
	}
	return input
}

func replayPermission(t *testing.T, client *sdk.Client, row permissionCase) {
	t.Helper()
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
		t.Fatalf("%s: native=%s local=%s error=%v", row.Case, row.Code, code, err)
	}
	if code != "Success" {
		return
	}
	var actual map[string]any
	if err := json.Unmarshal([]byte(mustJSON(t, output)), &actual); err != nil {
		t.Fatal(err)
	}
	got := permissionOutput(t, normalized(actual))
	want := permissionOutput(t, normalized(row.Output))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: native=%s local=%s", row.Case, mustJSON(t, want), mustJSON(t, got))
	}
}

func TestNativePermissionAdministration(t *testing.T) {
	capture := permissionFixture(t)
	backends(t, func(t *testing.T, b *backend) {
		c := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
		s := service.NewWithConfig(service.Config{Repository: b.repository, Clock: c, Accounts: permissionAccounts{"aws": {"123456789012": true, "222222222222": true}}})
		t.Cleanup(func() { _ = s.Close() })
		client := sdkClient(t, s)
		// Replay only administration: the fixture also records real IAM,
		// cross-account caller and regional behaviors owned by other tests.
		for _, row := range capture.Observations {
			if row.Case == "clear-before-role" {
				break
			}
			if row.Service != "events" || row.Actor != "owner" || row.Case == "full-propagating-role-principal" {
				continue
			}
			// This account's quota is 30720. Test the documented default below;
			// do not claim that its larger accepted policies replay unchanged.
			if strings.HasPrefix(row.Case, "full-compact-bytes-") || row.Case == "describe-after-size" {
				continue
			}
			if !t.Run(row.Case, func(t *testing.T) { replayPermission(t, client, row) }) {
				return
			}
		}
		var request struct{ EventBusName string }
		if err := json.Unmarshal(capture.PolicyLanguage.Observations[0].Input, &request); err != nil {
			t.Fatal(err)
		}
		if _, err := client.CreateEventBus(t.Context(), &sdk.CreateEventBusInput{Name: &request.EventBusName}); err != nil {
			t.Fatal(err)
		}
		for _, row := range capture.PolicyLanguage.Observations {
			if !t.Run(row.Case, func(t *testing.T) { replayPermission(t, client, row) }) {
				return
			}
		}
		if err := json.Unmarshal(capture.ActionAdmission.Observations[0].Input, &request); err != nil {
			t.Fatal(err)
		}
		if _, err := client.CreateEventBus(t.Context(), &sdk.CreateEventBusInput{Name: &request.EventBusName}); err != nil {
			t.Fatal(err)
		}
		for _, row := range capture.ActionAdmission.Observations {
			if !t.Run("action-admission/"+row.Case, func(t *testing.T) { replayPermission(t, client, row) }) {
				return
			}
		}
		for _, row := range capture.AdministrationAuthority.Observations {
			if row.Actor != "owner" {
				continue
			}
			if !t.Run("administration-authority/"+row.Case, func(t *testing.T) { replayPermission(t, client, row) }) {
				return
			}
		}
		for _, row := range capture.Observations {
			if row.Case != "full-compact-bytes-10240" && row.Case != "full-compact-bytes-10241" {
				continue
			}
			if row.Case == "full-compact-bytes-10241" {
				row.Code = "PolicyLengthExceededException"
			}
			t.Run("default-quota/"+row.Case, func(t *testing.T) { replayPermission(t, client, row) })
		}
	})
}

// IAM owns the identities; this boundary test changes its current resolution
// while replaying the native policy operations against both repositories.
type permissionIdentity struct {
	current atomic.Pointer[authorization.Principal]
}

func (*permissionIdentity) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{}, nil
}

func (i *permissionIdentity) ResolvePrincipal(_ context.Context, reference string) (authorization.Principal, error) {
	p := i.current.Load()
	if p != nil && (p.ARN == reference || p.ID == reference) {
		return *p, nil
	}
	return authorization.Principal{}, authorization.ErrInvalidPrincipal
}

func TestPermissionPrincipalBindingLifecycle(t *testing.T) {
	capture := permissionFixture(t)
	rows := make(map[string]permissionCase, len(capture.Observations))
	for _, row := range capture.Observations {
		rows[row.Case] = row
	}
	principal := func(name string) *authorization.Principal {
		role := rows[name].Output["Role"].(map[string]any)
		return &authorization.Principal{ARN: role["Arn"].(string), ID: role["RoleId"].(string)}
	}
	backends(t, func(t *testing.T, b *backend) {
		c := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
		identities := &permissionIdentity{}
		identities.current.Store(principal("create-owned-role"))
		s := service.NewWithConfig(service.Config{Repository: b.repository, Clock: c, PolicyBinder: authorization.NewWithClock(identities, nil, c)})
		t.Cleanup(func() { _ = s.Close() })
		client := sdkClient(t, s)
		for _, name := range []string{"create-role-bus", "full-existing-role-principal", "describe-role-before-delete"} {
			replayPermission(t, client, rows[name])
		}
		var request struct{ EventBusName string }
		if err := json.Unmarshal(rows["full-existing-role-principal"].Input, &request); err != nil {
			t.Fatal(err)
		}
		key := service.BusKey{Scope: service.Scope{Partition: "aws", Region: "us-east-1", Account: "123456789012"}, Name: request.EventBusName}
		read := func() service.BusRecord {
			t.Helper()
			var bus service.BusRecord
			if err := b.repository.View(t.Context(), func(r service.Reader) error {
				var err error
				bus, err = r.Bus(key)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return bus
		}
		before := read()
		identities.current.Store(nil)
		if err := c.Advance(time.Minute); err != nil {
			t.Fatal(err)
		}
		replayPermission(t, client, rows["describe-role-deleted-after-sixty-seconds"])
		identities.current.Store(principal("recreate-owned-role"))
		replayPermission(t, client, rows["describe-role-after-recreate"])
		replayPermission(t, client, rows["resubmit-identical-role-policy"])
		replayPermission(t, client, rows["describe-role-after-identical-policy"])
		if after := read(); !reflect.DeepEqual(after.Policy, before.Policy) || !after.Modified.Equal(before.Modified) {
			t.Fatalf("unchanged policy refreshed its binding or time: before=%+v after=%+v", before, after)
		}
		for _, name := range []string{"remove-bound-role-statement", "describe-after-role-statement-removed", "rebind-role-principal", "describe-role-after-rebind"} {
			replayPermission(t, client, rows[name])
		}
		after := read()
		current := principal("recreate-owned-role")
		if after.Policy.PrincipalIDs[current.ARN] != current.ID || !after.Modified.After(before.Modified) {
			t.Fatalf("re-added policy did not bind the current identity: %+v", after)
		}
	})
}
