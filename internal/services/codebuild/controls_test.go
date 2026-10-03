package codebuild

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	runtime "stackd/compute/codebuild"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func controlContext() context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "111122223333", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111122223333:root", PrincipalID: "111122223333"})
}

func TestFleetARNIdentifiesIncarnation(t *testing.T) {
	ctx := controlContext()
	// No controller is started: this checks admission and identity, not capacity.
	s := New(Config{Executor: &runtime.DockerExecutor{}, FleetImage: "owned-build-image"})
	t.Cleanup(func() { s.Close() })
	create := func() api.Fleet {
		t.Helper()
		var out *api.CreateFleetOutput
		err := s.repository.Update(ctx, func(tx Transaction) error {
			var err error
			out, err = s.createFleet(tx.Context(), tx, &api.CreateFleetInput{Name: new(api.FleetName("reserved")), BaseCapacity: new(api.FleetCapacity(1)), ComputeType: new(api.ComputeType("BUILD_GENERAL1_SMALL")), EnvironmentType: new(api.EnvironmentType("LINUX_CONTAINER"))})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		fleet := *out.Fleet
		if _, err := uuid.Parse(value(fleet.Id)); err != nil {
			t.Fatalf("fleet ID is not a UUID: %q", value(fleet.Id))
		}
		want := "arn:aws:codebuild:us-east-1:111122223333:fleet/reserved:" + value(fleet.Id)
		if value(fleet.Arn) != want {
			t.Fatalf("fleet ARN lost its incarnation: got %q, want %q", value(fleet.Arn), want)
		}
		return fleet
	}
	first := create()
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		out, err := s.listFleets(tx.Context(), tx, &api.ListFleetsInput{})
		if err != nil {
			return err
		}
		if len(out.Fleets) != 1 || string(out.Fleets[0]) != value(first.Arn) {
			t.Fatalf("listing lost incarnation: %+v", out.Fleets)
		}
		_, err = s.deleteFleet(tx.Context(), tx, &api.DeleteFleetInput{Arn: first.Arn})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Model the completed native release, then recreate the same logical name.
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteFleet(FleetKey{scopeFor(ctx), "reserved"}) }); err != nil {
		t.Fatal(err)
	}
	second := create()
	if value(first.Arn) == value(second.Arn) {
		t.Fatal("recreated fleet reused the deleted ARN")
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		out, err := s.batchGetFleets(tx.Context(), tx, &api.BatchGetFleetsInput{Names: api.FleetNames{api.NonEmptyString(value(first.Arn)), api.NonEmptyString(value(second.Arn))}})
		if err != nil {
			return err
		}
		if len(out.Fleets) != 1 || value(out.Fleets[0].Arn) != value(second.Arn) || len(out.FleetsNotFound) != 1 || string(out.FleetsNotFound[0]) != value(first.Arn) {
			t.Fatalf("fleet lookup crossed incarnations: %+v", out)
		}
		_, err = s.deleteFleet(tx.Context(), tx, &api.DeleteFleetInput{Arn: first.Arn})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("stale fleet deletion returned %v", err)
		}
		current, err := tx.Fleet(FleetKey{scopeFor(ctx), "reserved"})
		if err == nil && value(current.Data.Status.StatusCode) == "DELETING" {
			t.Fatal("stale ARN deleted the replacement fleet")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

var errCredentialEncryptionReached = errors.New("credential encryption reached")

type rejectCredentialEncryption struct{}

func (rejectCredentialEncryption) Seal(context.Context, string, string, string) ([]byte, error) {
	return nil, errCredentialEncryptionReached
}
func (rejectCredentialEncryption) Open(context.Context, string, []byte) (string, string, error) {
	return "", "", errCredentialEncryptionReached
}

func TestSourceCredentialUsernameRequiresBitbucketBasicAuth(t *testing.T) {
	cases := []struct {
		name, server, auth string
		username           *api.NonEmptyString
	}{
		{"other-provider-username", "GITHUB", "PERSONAL_ACCESS_TOKEN", new(api.NonEmptyString("build-user"))},
		{"other-auth-username", "BITBUCKET", "PERSONAL_ACCESS_TOKEN", new(api.NonEmptyString("build-user"))},
		{"missing-bitbucket-username", "BITBUCKET", "BASIC_AUTH", nil},
		{"basic-auth-other-provider", "GITHUB", "BASIC_AUTH", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := controlContext()
			s := New(Config{Cipher: rejectCredentialEncryption{}})
			t.Cleanup(func() { s.Close() })
			err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.importSourceCredentials(tx.Context(), tx, &api.ImportSourceCredentialsInput{ServerType: new(api.ServerType(tc.server)), AuthType: new(api.AuthType(tc.auth)), Username: tc.username, Token: new(api.SensitiveNonEmptyString("nonsecret-test-token"))})
				return err
			})
			var rejected *awswire.Error
			if !errors.As(err, &rejected) || rejected.Code != "InvalidInputException" {
				t.Fatalf("invalid provider/auth username reached credential persistence: %v", err)
			}
		})
	}
}

func TestFleetARNLookupUsesFullStoredIdentity(t *testing.T) {
	ctx := controlContext()
	s := New(Config{})
	t.Cleanup(func() { s.Close() })
	arn := "arn:aws:codebuild:us-east-1:111122223333:fleet/reserved:00000000-0000-4000-8000-000000000001"
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutFleet(FleetRecord{Key: FleetKey{scopeFor(ctx), "reserved"}, Data: api.Fleet{Arn: new(api.NonEmptyString(arn)), Id: new(api.NonEmptyString("00000000-0000-4000-8000-000000000001")), Name: new(api.FleetName("reserved"))}})
	}); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{arn, "reserved", strings.Replace(arn, "111122223333", "444455556666", 1), strings.TrimSuffix(arn, ":00000000-0000-4000-8000-000000000001")} {
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			out, err := s.batchGetFleets(tx.Context(), tx, &api.BatchGetFleetsInput{Names: api.FleetNames{api.NonEmptyString(input)}})
			if err != nil {
				return err
			}
			if input == arn || input == "reserved" {
				if len(out.Fleets) != 1 || value(out.Fleets[0].Arn) != arn {
					t.Fatalf("current fleet not resolved by %q: %+v", input, out)
				}
			} else if len(out.FleetsNotFound) != 1 || string(out.FleetsNotFound[0]) != input || len(out.Fleets) != 0 {
				t.Fatalf("foreign or incomplete ARN matched current fleet: %+v", out)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQueuedBuildRejectsReplacementFleet(t *testing.T) {
	s, queued := seededBuild(t)
	fleet := FleetKey{Scope: queued.Key.Scope, Name: "reserved"}
	queued.FleetARN = fleet.ARN("00000000-0000-4000-8000-000000000001")
	queued.Data.CurrentPhase = new(api.String("QUEUED"))
	queued.Data.TimeoutInMinutes = new(api.WrapperInt(5))
	queued.Data.Phases = api.BuildPhases{{PhaseType: new(api.BuildPhaseType("QUEUED")), StartTime: queued.Data.StartTime}}
	if err := s.repository.Update(context.Background(), func(tx Transaction) error {
		if err := tx.PutBuild(queued); err != nil {
			return err
		}
		return tx.PutFleet(FleetRecord{Key: fleet, Data: api.Fleet{Arn: new(api.NonEmptyString(fleet.ARN("00000000-0000-4000-8000-000000000002"))), BaseCapacity: new(api.FleetCapacity(1)), Status: &api.FleetStatus{StatusCode: new(api.FleetStatusCode("ACTIVE"))}}})
	}); err != nil {
		t.Fatal(err)
	}
	if ready, err := s.controller.claim(queued.Key); err != nil || ready {
		t.Fatalf("obsolete fleet blocked reconciliation or used replacement: ready=%v error=%v", ready, err)
	}
	got, err := s.controller.load(queued.Key)
	if err != nil {
		t.Fatal(err)
	}
	if !complete(got) || value(got.Data.BuildStatus) != "FAILED" || !got.Deadline.IsZero() || got.FleetARN != queued.FleetARN {
		t.Fatalf("obsolete fleet build did not fail before execution: %+v", got)
	}
}

func TestNativeBuildAuditSensitiveFields(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/cloudtrail/codebuild_build_history.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		CloudTrail struct {
			Events []struct {
				Label string `json:"call_label"`
				Event struct {
					Name     string          `json:"eventName"`
					Response json.RawMessage `json:"responseElements"`
				} `json:"event"`
			} `json:"events"`
		} `json:"cloudtrail"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"failure_start", "success_stop_terminal"} {
		t.Run(label, func(t *testing.T) {
			for _, row := range fixture.CloudTrail.Events {
				if !strings.HasPrefix(row.Label, "codebuild:"+label+":") {
					continue
				}
				var output api.StartBuildOutput
				var expected map[string]any
				if err := json.Unmarshal(row.Event.Response, &output); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(row.Event.Response, &expected); err != nil {
					t.Fatal(err)
				}
				if output.Build.Source.Buildspec != nil {
					output.Build.Source.Buildspec = new(api.String("version: 0.2\n# private build commands"))
				}
				for i := range output.Build.Environment.EnvironmentVariables {
					output.Build.Environment.EnvironmentVariables[i] = api.EnvironmentVariable{Name: new(api.NonEmptyString("PRIVATE_NAME")), Value: new(api.String("private-environment-value")), Type: new(api.EnvironmentVariableType("PLAINTEXT"))}
				}
				for i := range output.Build.ExportedEnvironmentVariables {
					output.Build.ExportedEnvironmentVariables[i] = api.ExportedEnvironmentVariable{Name: new(api.NonEmptyString("PRIVATE_EXPORT")), Value: new(api.String("private-exported-value"))}
				}
				model, _ := awscatalog.LookupService("codebuild")
				operation, _ := model.Operation(row.Event.Name)
				input, err := api.NewInput(row.Event.Name)
				if err != nil {
					t.Fatal(err)
				}
				call, err := auditProjection(row.Event.Name).Call(model, operation, input, &output, nil)
				if err != nil {
					t.Fatal(err)
				}
				var actual map[string]any
				if err := json.Unmarshal(call.ResponseElements, &actual); err != nil {
					t.Fatal(err)
				}
				got, want := actual["build"].(map[string]any), expected["build"].(map[string]any)
				for name, pair := range map[string][2]any{
					"buildspec":   {got["source"].(map[string]any)["buildspec"], want["source"].(map[string]any)["buildspec"]},
					"environment": {got["environment"].(map[string]any)["environmentVariables"], want["environment"].(map[string]any)["environmentVariables"]},
					"exported":    {got["exportedEnvironmentVariables"], want["exportedEnvironmentVariables"]},
				} {
					if !reflect.DeepEqual(pair[0], pair[1]) {
						t.Fatalf("%s disclosure differs from native: got %#v, want %#v", name, pair[0], pair[1])
					}
				}
				return
			}
			t.Fatalf("missing native disclosure fixture %s", label)
		})
	}
}
