package codepipeline

import (
	"testing"

	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
)

func TestPipelineVariableAdmissionAndResolution(t *testing.T) {
	variable := func(name, value string) api.PipelineVariable {
		return api.PipelineVariable{Name: new(api.PipelineVariableName(name)), Value: new(api.PipelineVariableValue(value))}
	}
	for _, tc := range []struct {
		name             string
		overrides        api.PipelineVariableList
		value            string
		failed, rejected bool
	}{
		{name: "missing-required", failed: true},
		{name: "empty-overrides", overrides: api.PipelineVariableList{}, failed: true},
		{name: "unknown-only", overrides: api.PipelineVariableList{variable("Unknown", "ignored")}, failed: true},
		{name: "case-sensitive", overrides: api.PipelineVariableList{variable("alpha", "ignored")}, failed: true},
		{name: "required-and-defaults", overrides: api.PipelineVariableList{variable("Alpha", "release")}},
		{name: "unknown-ignored", overrides: api.PipelineVariableList{variable("Unknown", "ignored"), variable("Alpha", "release")}},
		{name: "literal-nested-reference", overrides: api.PipelineVariableList{variable("Alpha", "#{codepipeline.PipelineExecutionId}")}, value: "#{codepipeline.PipelineExecutionId}"},
		{name: "duplicate", overrides: api.PipelineVariableList{variable("Alpha", "first"), variable("Alpha", "second")}, rejected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == "" {
				tc.value = "release"
			}
			s, ctx, v, d := kernelFixture(t, "QUEUED")
			d.Declaration.Variables = api.PipelineVariableDeclarationList{
				{Name: new(api.PipelineVariableName("Zulu")), DefaultValue: new(api.PipelineVariableValue("default"))},
				{Name: new(api.PipelineVariableName("Alpha"))},
			}
			d.Declaration.Stages[1].Actions[0].Configuration["CustomData"] = "#{variables.Alpha}/#{variables.Zulu}/#{codepipeline.PipelineExecutionId}"
			origin := awsctx.FromContext(ctx)
			origin.InvokedBy = "events.amazonaws.com"
			origin.ServicePrincipal.SourceARN = "arn:aws:events:us-east-1:111122223333:rule/release"
			ctx = awsctx.WithMetadata(ctx, origin)
			var id string
			err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutDefinition(d); err != nil {
					return err
				}
				out, err := s.startPipeline(tx, &api.StartPipelineExecutionInput{Name: new(api.PipelineName(v.Name)), Variables: tc.overrides})
				if err == nil {
					id = text(out.PipelineExecutionId)
				}
				return err
			})
			if tc.rejected {
				if err == nil || wireError(err).Code != "ValidationException" {
					t.Fatalf("duplicate variable admission: %v", err)
				}
				if err := s.repository.View(ctx, func(r Reader) error {
					rows, err := r.Executions(v.Scope, v.Incarnation)
					if len(rows) != 0 {
						t.Fatal("rejected variables admitted an execution")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			e := retainedNotification(t, s, ctx, v, id)
			if e.TriggerType != "CloudWatchEvent" || e.TriggerDetail != origin.ServicePrincipal.SourceARN {
				t.Fatalf("variable binding lost EventBridge attribution: %+v", e)
			}
			if tc.failed {
				if e.Status != "Failed" || e.Summary != "Values for required variables haven't been provided: Alpha" || !e.Due.IsZero() || e.Variables != nil || len(e.Actions) != 0 {
					t.Fatalf("missing required variable did not retain native terminal failure: %+v", e)
				}
				return
			}
			if e.Status != "InProgress" || len(e.Variables) != 2 || text(e.Variables[0].Name) != "Zulu" || text(e.Variables[0].ResolvedValue) != "default" || text(e.Variables[1].Name) != "Alpha" || text(e.Variables[1].ResolvedValue) != tc.value {
				t.Fatalf("execution bindings changed: %+v", e)
			}
			*d.Declaration.Variables[0].DefaultValue = "updated"
			for i := range tc.overrides {
				*tc.overrides[i].Value = "mutated"
			}
			resolved, err := resolveConfiguration(d, e, d.Declaration.Stages[1].Actions[0], nil)
			if err != nil || resolved["CustomData"] != api.ActionConfigurationValue(tc.value+"/default/"+id) {
				t.Fatalf("action rebound mutated defaults or request values: %+v %v", resolved, err)
			}
		})
	}
}

func TestPipelineVariableDefinitionAdmission(t *testing.T) {
	s, ctx, _, d := kernelFixture(t, "SUPERSEDED")
	s.roles = approvalAdmissionRoles{}
	d.Declaration.PipelineType = new(api.PipelineType("V2"))
	d.Declaration.Variables = api.PipelineVariableDeclarationList{{Name: new(api.PipelineVariableName("Target"))}}
	source := &d.Declaration.Stages[0].Actions[0]
	source.Configuration = api.ActionConfigurationMap{"S3Bucket": "source", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}
	source.OutputArtifacts = api.OutputArtifactList{{Name: new(api.ArtifactName("Source"))}}
	d.Declaration.Stages[1].Actions[0].Configuration["CustomData"] = "#{variables.Target}"
	for _, tc := range []struct {
		name     string
		change   func(*api.PipelineDeclaration)
		rejected bool
	}{
		{name: "required-variable", change: func(*api.PipelineDeclaration) {}},
		{name: "implicit-v2", change: func(d *api.PipelineDeclaration) { d.PipelineType = nil }},
		{name: "notification-reference", change: func(d *api.PipelineDeclaration) {
			d.Stages[1].Actions[0].Configuration["NotificationArn"] = "#{variables.Target}"
		}},
		{name: "v1", rejected: true, change: func(d *api.PipelineDeclaration) { d.PipelineType = new(api.PipelineType("V1")) }},
		{name: "duplicate-name", rejected: true, change: func(d *api.PipelineDeclaration) { d.Variables = append(d.Variables, d.Variables[0]) }},
		{name: "source-reference", rejected: true, change: func(d *api.PipelineDeclaration) {
			d.Stages[0].Actions[0].Configuration["S3ObjectKey"] = "#{variables.Target}"
		}},
		{name: "undeclared-reference", rejected: true, change: func(d *api.PipelineDeclaration) {
			d.Stages[1].Actions[0].Configuration["CustomData"] = "#{variables.Missing}"
		}},
		{name: "reserved-namespace", rejected: true, change: func(d *api.PipelineDeclaration) {
			d.Stages[0].Actions[0].Namespace = new(api.ActionNamespace("variables"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			declaration := CloneDeclaration(d.Declaration)
			tc.change(&declaration)
			err := s.repository.Update(ctx, func(tx Transaction) error {
				admitted, err := s.admitDefinition(tx, &declaration, 1)
				if err == nil && text(admitted.Declaration.PipelineType) != "V2" {
					t.Fatalf("pipeline variables did not select V2: %+v", admitted.Declaration)
				}
				return err
			})
			if tc.rejected {
				if err == nil || wireError(err).Code != "InvalidStructureException" {
					t.Fatalf("invalid variable definition was admitted: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	d.Declaration.Name = new(api.PipelineName("required-creation"))
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := s.createPipeline(tx, &api.CreatePipelineInput{Pipeline: &d.Declaration}); err != nil {
			return err
		}
		pipeline, err := findPipeline(tx, scopeFor(ctx), "required-creation")
		if err != nil {
			return err
		}
		rows, err := tx.Executions(pipeline.Scope, pipeline.Incarnation)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Status != "Failed" || rows[0].TriggerType != "CreatePipeline" || !rows[0].Due.IsZero() || rows[0].Variables != nil {
			t.Fatalf("creation did not retain its failed required-variable execution: %+v", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPipelineVariableTokenReplayValidation(t *testing.T) {
	s, ctx, v, d := kernelFixture(t, "SUPERSEDED")
	d.Declaration.Variables = api.PipelineVariableDeclarationList{
		{Name: new(api.PipelineVariableName("Alpha"))},
		{Name: new(api.PipelineVariableName("Zulu")), DefaultValue: new(api.PipelineVariableValue("default"))},
	}
	variable := func(name, value string) api.PipelineVariable {
		return api.PipelineVariable{Name: new(api.PipelineVariableName(name)), Value: new(api.PipelineVariableValue(value))}
	}
	source := func(action, value string) api.SourceRevisionOverrideList {
		return api.SourceRevisionOverrideList{{ActionName: new(api.ActionName(action)), RevisionType: new(api.SourceRevisionType("S3_OBJECT_VERSION_ID")), RevisionValue: new(api.Revision(value))}}
	}
	input := api.StartPipelineExecutionInput{
		Name: new(api.PipelineName(v.Name)), ClientRequestToken: new(api.ClientRequestToken("retained-token")),
		Variables:       api.PipelineVariableList{variable("Alpha", "first"), variable("Zulu", "override")},
		SourceRevisions: source("Source", "first-version"),
	}
	var id string
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutDefinition(d); err != nil {
			return err
		}
		out, err := s.startPipeline(tx, &input)
		if err == nil {
			id = text(out.PipelineExecutionId)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		variables api.PipelineVariableList
		source    api.SourceRevisionOverrideList
		rejected  bool
	}{
		{name: "reordered", variables: api.PipelineVariableList{variable("Zulu", "override"), variable("Alpha", "first")}},
		{name: "changed-value", variables: api.PipelineVariableList{variable("Alpha", "changed")}},
		{name: "missing-required"},
		{name: "unknown-only", variables: api.PipelineVariableList{variable("Unknown", "ignored")}},
		{name: "changed-source", source: source("Source", "second-version")},
		{name: "duplicate-before-replay", variables: api.PipelineVariableList{variable("Alpha", "one"), variable("Alpha", "two")}, rejected: true},
		{name: "invalid-source-before-replay", source: source("Missing", "version"), rejected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := input
			request.Variables = tc.variables
			request.SourceRevisions = tc.source
			err := s.repository.Update(ctx, func(tx Transaction) error {
				out, err := s.startPipeline(tx, &request)
				if err == nil && text(out.PipelineExecutionId) != id {
					t.Fatal("token replay admitted a different execution")
				}
				return err
			})
			if tc.rejected {
				if err == nil || wireError(err).Code != "ValidationException" {
					t.Fatalf("invalid token replay was accepted: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		if len(rows) != 1 || text(rows[0].Variables[0].ResolvedValue) != "first" || text(rows[0].Variables[1].ResolvedValue) != "override" || text(rows[0].SourceOverrides[0].RevisionValue) != "first-version" {
			t.Fatalf("token replay changed retained execution bindings: %+v", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPipelineVariableNamespaceWithoutDeclarations(t *testing.T) {
	for _, empty := range []bool{false, true} {
		for _, assigned := range []bool{false, true} {
			s, ctx, _, d := kernelFixture(t, "SUPERSEDED")
			s.roles = approvalAdmissionRoles{}
			d.Declaration.PipelineType = new(api.PipelineType("V2"))
			if empty {
				d.Declaration.Variables = api.PipelineVariableDeclarationList{}
			}
			source := &d.Declaration.Stages[0].Actions[0]
			source.Configuration = api.ActionConfigurationMap{"S3Bucket": "source", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}
			source.OutputArtifacts = api.OutputArtifactList{{Name: new(api.ArtifactName("Source"))}}
			if assigned {
				source.Namespace = new(api.ActionNamespace("variables"))
			}
			d.Declaration.Stages[1].Actions[0].Configuration["CustomData"] = "#{variables.VersionId}"
			err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.admitDefinition(tx, &d.Declaration, 1)
				return err
			})
			if !assigned {
				if err == nil || wireError(err).Code != "InvalidActionDeclarationException" {
					t.Fatalf("missing namespace: empty=%v error=%v", empty, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("unused pipeline namespace was reserved: empty=%v error=%v", empty, err)
			}
			e := Execution{Actions: []ActionExecution{{StageIndex: 0, ActionIndex: 0, Status: "Succeeded", OutputVariables: api.OutputVariablesMap{"VersionId": "source-version"}}}}
			resolved, err := resolveConfiguration(d, e, d.Declaration.Stages[1].Actions[0], nil)
			if err != nil || resolved["CustomData"] != "source-version" {
				t.Fatalf("action-owned variables namespace stopped resolving: %+v %v", resolved, err)
			}
		}
	}
}
