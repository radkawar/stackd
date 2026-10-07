package codepipeline

import (
	"fmt"
	"regexp"
	"slices"
	api "stackd/internal/awsapi/codepipeline"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

func registerDefinitions(s *Service) {
	register(s, "CreatePipeline", s.createPipeline)
	register(s, "UpdatePipeline", s.updatePipeline)
	register(s, "GetPipeline", s.getPipeline)
	register(s, "DeletePipeline", s.deletePipeline)
	register(s, "ListPipelines", s.listPipelines)
}
func (s *Service) createPipeline(tx Transaction, in *api.CreatePipelineInput) (*api.CreatePipelineOutput, error) {
	sc := scopeFor(tx.Context())
	name := ""
	if in.Pipeline != nil {
		name = text(in.Pipeline.Name)
	}
	tags, err := tagMap(in.Tags)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(tx.Context(), "CreatePipeline", ARN(sc, name), nil); err != nil {
		return nil, err
	}
	rows, err := tx.Pipelines(sc)
	if err != nil {
		return nil, err
	}
	for _, v := range rows {
		if v.Name == name {
			return nil, failure("PipelineNameInUseException", "Pipeline already exists: "+name)
		}
	}
	d, err := s.admitDefinition(tx, in.Pipeline, 1)
	if err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	v := Pipeline{Scope: sc, Name: name, Incarnation: id, Version: 1, CreatedAt: now, UpdatedAt: now, Tags: tags}
	d.Scope = sc
	d.Incarnation = id
	if err = tx.PutPipeline(v); err != nil {
		return nil, err
	}
	if err = tx.PutDefinition(d); err != nil {
		return nil, err
	}
	if err = s.reconcileSourcePolls(tx, v, d); err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(d.Declaration.Stages[0].Actions, pollingEnabled) {
		if _, err = s.startExecution(tx, v, d, "", nil, nil, "CreatePipeline"); err != nil {
			return nil, err
		}
	}
	return &api.CreatePipelineOutput{Pipeline: &d.Declaration, Tags: tagList(tags)}, nil
}
func (s *Service) updatePipeline(tx Transaction, in *api.UpdatePipelineInput) (*api.UpdatePipelineOutput, error) {
	name := ""
	if in.Pipeline != nil {
		name = text(in.Pipeline.Name)
	}
	v, err := s.pipelineFor(tx, "UpdatePipeline", name)
	if err != nil {
		return nil, err
	}
	updateHash, _ := tx.Context().Value(cfnUpdateKey{}).(string)
	if updateHash != "" && v.LastUpdate == updateHash {
		current, err := findDefinition(tx, v, v.Version)
		if err != nil {
			return nil, err
		}
		return &api.UpdatePipelineOutput{Pipeline: &current.Declaration}, nil
	}
	d, err := s.admitDefinition(tx, in.Pipeline, v.Version+1)
	if err != nil {
		return nil, err
	}
	d.Scope = v.Scope
	d.Incarnation = v.Incarnation
	v.Version++
	v.LastUpdate = updateHash
	v.UpdatedAt = s.clock.Now().UTC()
	if err = tx.PutDefinition(d); err != nil {
		return nil, err
	}
	if err = tx.PutPipeline(v); err != nil {
		return nil, err
	}
	if err = s.reconcileSourcePolls(tx, v, d); err != nil {
		return nil, err
	}
	rows, err := tx.Executions(v.Scope, v.Incarnation)
	if err != nil {
		return nil, err
	}
	for _, e := range rows {
		if terminal(e.Status) {
			continue
		}
		e.UpdatedDefinition = true
		e.Due = v.UpdatedAt
		e.Generation++
		if err = tx.PutExecution(e); err != nil {
			return nil, err
		}
	}
	return &api.UpdatePipelineOutput{Pipeline: &d.Declaration}, nil
}
func (s *Service) getPipeline(tx Transaction, in *api.GetPipelineInput) (*api.GetPipelineOutput, error) {
	v, err := s.pipelineFor(tx, "GetPipeline", text(in.Name))
	if err != nil {
		return nil, err
	}
	version := v.Version
	if in.Version != nil {
		version = int32(*in.Version)
	}
	d, err := findDefinition(tx, v, version)
	if err != nil {
		return nil, err
	}
	metadata := &api.PipelineMetadata{PipelineArn: new(api.PipelineArn(ARN(v.Scope, v.Name))), Created: &v.CreatedAt, Updated: &v.UpdatedAt}
	if !v.PollingDisabledAt.IsZero() {
		metadata.PollingDisabledAt = &v.PollingDisabledAt
	}
	return &api.GetPipelineOutput{Pipeline: &d.Declaration, Metadata: metadata}, nil
}
func (s *Service) deletePipeline(tx Transaction, in *api.DeletePipelineInput) (*struct{}, error) {
	sc := scopeFor(tx.Context())
	name := text(in.Name)
	rows, err := tx.Pipelines(sc)
	if err != nil {
		return nil, err
	}
	var tags map[string]string
	for _, v := range rows {
		if v.Name == name {
			tags = v.Tags
		}
	}
	if err = s.authorize(tx.Context(), "DeletePipeline", ARN(sc, name), tags); err != nil {
		return nil, err
	}
	if err = tx.DeletePipeline(sc, name); err != nil {
		return nil, err
	}
	return &struct{}{}, nil
}
func (s *Service) listPipelines(tx Transaction, in *api.ListPipelinesInput) (*api.ListPipelinesOutput, error) {
	sc := scopeFor(tx.Context())
	if err := s.authorize(tx.Context(), "ListPipelines", "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Pipelines(sc)
	if err != nil {
		return nil, err
	}
	start, end, next, err := page(sc, "pipelines", text(in.NextToken), int(value(in.MaxResults)), len(rows))
	if err != nil {
		return nil, err
	}
	out := &api.ListPipelinesOutput{NextToken: next, Pipelines: api.PipelineList{}}
	for _, v := range rows[start:end] {
		d, err := findDefinition(tx, v, v.Version)
		if err != nil {
			return nil, err
		}
		out.Pipelines = append(out.Pipelines, api.PipelineSummary{Name: new(api.PipelineName(v.Name)), Version: new(api.PipelineVersion(v.Version)), PipelineType: d.Declaration.PipelineType, ExecutionMode: d.Declaration.ExecutionMode, Created: &v.CreatedAt, Updated: &v.UpdatedAt})
	}
	return out, nil
}
func (s *Service) pipelineFor(r Reader, action, name string) (Pipeline, error) {
	sc := scopeFor(r.Context())
	v, err := findPipeline(r, sc, name)
	var tags map[string]string
	if err == nil {
		tags = v.Tags
	}
	if denied := s.authorize(r.Context(), action, ARN(sc, name), tags); denied != nil {
		return Pipeline{}, denied
	}
	return v, err
}

var pipelineName = regexp.MustCompile(`^[A-Za-z0-9.@_-]{1,100}$`)

func (s *Service) admitDefinition(tx Transaction, input *api.PipelineDeclaration, version int32) (Definition, error) {
	bad := func(message string) (Definition, error) {
		return Definition{}, failure("InvalidStructureException", message)
	}
	if input == nil {
		return bad("Pipeline is required")
	}
	if !pipelineName.MatchString(text(input.Name)) {
		return bad("Invalid pipeline name")
	}
	sc := scopeFor(tx.Context())
	if !strings.HasPrefix(text(input.RoleArn), "arn:"+sc.Partition+":iam::"+sc.AccountID+":role/") {
		return bad("Pipeline role must belong to this account and partition")
	}
	if s.roles == nil {
		return Definition{}, failure("NotImplementedException", "Pipeline role validation is not configured")
	}
	if err := s.roles.Validate(tx.Context(), text(input.RoleArn), ARN(sc, text(input.Name))); err != nil {
		return Definition{}, err
	}
	// TODO: Comeback — cross-region artifact stores/triggers,
	// automatic stage conditions/rollback and additional providers need real execution owners.
	if len(input.ArtifactStores) > 0 || len(input.Triggers) > 0 {
		return Definition{}, failure("NotImplementedException", "Cross-region stores and triggers are not implemented")
	}
	if input.ArtifactStore == nil || text(input.ArtifactStore.Type) != "S3" || text(input.ArtifactStore.Location) == "" {
		return bad("An S3 artifactStore is required")
	}
	if k := input.ArtifactStore.EncryptionKey; k != nil && (text(k.Type) != "KMS" || text(k.Id) == "") {
		return bad("Artifact encryptionKey must identify a KMS key")
	}
	if len(input.Stages) < 2 || len(input.Stages) > 50 {
		return bad("Pipeline requires between 2 and 50 stages")
	}
	mode := text(input.ExecutionMode)
	if mode == "" {
		mode = "SUPERSEDED"
	}
	kind := text(input.PipelineType)
	if kind == "" {
		kind = "V1"
		if len(input.Variables) > 0 {
			kind = "V2"
		}
	}
	if kind != "V1" && kind != "V2" {
		return bad("Invalid pipeline type")
	}
	if mode != "SUPERSEDED" && mode != "QUEUED" && mode != "PARALLEL" {
		return bad("Invalid execution mode")
	}
	if mode != "SUPERSEDED" && kind != "V2" {
		return bad("QUEUED and PARALLEL require V2")
	}
	if len(input.Variables) > 0 && kind != "V2" {
		return bad("Pipeline variable can only be used with V2 pipelines")
	}
	variables := make(map[string]bool, len(input.Variables))
	for _, variable := range input.Variables {
		name := text(variable.Name)
		if variables[name] {
			return bad("Variable names must be unique. The following variable name is already in use: " + name)
		}
		variables[name] = true
	}
	stages := map[string]bool{}
	outputs := map[string][2]int{}
	namespaces := map[string]bool{"codepipeline": true, "variables": len(variables) > 0}
	for i, stage := range input.Stages {
		if !pipelineName.MatchString(text(stage.Name)) || stages[text(stage.Name)] {
			return bad("Stage names must be valid and unique")
		}
		stages[text(stage.Name)] = true
		if len(stage.Actions) == 0 {
			return bad("Every stage requires actions")
		}
		if stage.BeforeEntry != nil || stage.OnFailure != nil || stage.OnSuccess != nil || len(stage.Blockers) > 0 {
			return Definition{}, failure("NotImplementedException", "Stage conditions and blockers are not implemented")
		}
		names := map[string]bool{}
		for _, a := range stage.Actions {
			if !pipelineName.MatchString(text(a.Name)) || names[text(a.Name)] {
				return bad("Action names must be valid and unique within a stage")
			}
			names[text(a.Name)] = true
			if a.ActionTypeId == nil {
				return bad("Action type is required")
			}
			t := a.ActionTypeId
			category, provider := text(t.Category), text(t.Provider)
			if text(t.Owner) != "AWS" || text(t.Version) != "1" {
				return Definition{}, failure("NotImplementedException", "Only AWS action version 1 is implemented")
			}
			supported := (category == "Source" && provider == "S3") || ((category == "Build" || category == "Test") && provider == "CodeBuild") || (category == "Deploy" && (provider == "AppConfig" || provider == "S3")) || (category == "Approval" && provider == "Manual") || (category == "Invoke" && provider == "Lambda")
			if !supported {
				return Definition{}, failure("NotImplementedException", "Action provider is not implemented: "+provider)
			}
			if (i == 0) != (category == "Source") {
				return bad("Source actions must appear only in the first stage")
			}
			if len(a.Commands) > 0 || len(a.EnvironmentVariables) > 0 || len(a.OutputVariables) > 0 {
				return Definition{}, failure("NotImplementedException", "Action commands and declared environment/output variables are not implemented")
			}
			if a.Namespace != nil {
				n := text(a.Namespace)
				if n == "" || namespaces[n] {
					return bad("Action namespaces must be nonempty, unique and nonreserved")
				}
				namespaces[n] = true
			}
			if a.Region != nil && text(a.Region) != sc.Region {
				return Definition{}, failure("NotImplementedException", "Cross-region actions are not implemented")
			}
			if a.RoleArn != nil && !strings.HasPrefix(text(a.RoleArn), "arn:"+sc.Partition+":iam::"+sc.AccountID+":role/") {
				return Definition{}, failure("NotImplementedException", "Cross-account action roles are not implemented")
			}
			order := int(value(a.RunOrder))
			if a.RunOrder == nil {
				order = 1
			}
			if order < 1 || order > 999 {
				return bad("runOrder must be between 1 and 999")
			}
			for _, o := range a.OutputArtifacts {
				n := text(o.Name)
				if n == "" {
					return bad("Artifact name is required")
				}
				if _, ok := outputs[n]; ok {
					return bad("Output artifact names must be unique")
				}
				if len(o.Files) > 0 {
					return Definition{}, failure("NotImplementedException", "Output artifact file selectors are not implemented")
				}
				outputs[n] = [2]int{i, order}
			}
			switch provider {
			case "S3":
				if category == "Deploy" {
					if len(a.InputArtifacts) != 1 || len(a.OutputArtifacts) != 0 {
						return bad("S3 deployment requires one input and no outputs")
					}
					if err := validateS3Deploy(a); err != nil {
						return Definition{}, err
					}
					break
				}
				if len(a.InputArtifacts) != 0 || len(a.OutputArtifacts) != 1 || a.Configuration["S3Bucket"] == "" || a.Configuration["S3ObjectKey"] == "" {
					return bad("S3 source requires bucket/key, no inputs and one output")
				}
				if pollingEnabled(a) && s.sources == nil {
					return Definition{}, failure("NotImplementedException", "S3 source polling observer is not configured")
				}
			case "CodeBuild":
				if len(a.InputArtifacts) < 1 || len(a.InputArtifacts) > 5 || len(a.OutputArtifacts) > 5 || a.Configuration["ProjectName"] == "" {
					return bad("CodeBuild requires a project, 1–5 inputs and 0–5 outputs")
				}
				if a.Configuration["BatchEnabled"] == "true" {
					return Definition{}, failure("NotImplementedException", "CodeBuild batch actions are not implemented")
				}
			case "AppConfig":
				if len(a.InputArtifacts) != 1 || len(a.OutputArtifacts) != 0 || a.Configuration["Application"] == "" || a.Configuration["Environment"] == "" || a.Configuration["ConfigurationProfile"] == "" || a.Configuration["DeploymentStrategy"] == "" || a.Configuration["InputArtifactConfigurationPath"] == "" {
					return bad("AppConfig requires one input and application/environment/profile/strategy/configuration path")
				}
			case "Lambda":
				if len(a.InputArtifacts) > 5 || len(a.OutputArtifacts) > 5 || a.Configuration["FunctionName"] == "" {
					return Definition{}, failure("InvalidActionDeclarationException", "Lambda requires FunctionName, 0–5 inputs and 0–5 outputs")
				}
				for key := range a.Configuration {
					if key != "FunctionName" && key != "UserParameters" {
						return Definition{}, failure("InvalidActionDeclarationException", "Unknown Lambda configuration key: "+string(key))
					}
				}
			case "Manual":
				if len(a.InputArtifacts) != 0 || len(a.OutputArtifacts) != 0 {
					return bad("Manual approval does not consume or produce artifacts")
				}
				if notification := string(a.Configuration["NotificationArn"]); notification != "" && !variableReference.MatchString(notification) {
					topic, err := arn.Parse(notification)
					if err != nil || topic.Partition == "" || topic.AccountID == "" || topic.Resource == "" {
						return Definition{}, failure("InvalidActionDeclarationException", fmt.Sprintf("The ARN %s you specified for sending notifications for the approval action %s contains a format error.", notification, text(a.Name)))
					}
					if topic.Service != "sns" {
						return Definition{}, failure("InvalidActionDeclarationException", fmt.Sprintf("The ARN %s has been specified for sending notifications for the approval action %s, but the AWS service for this ARN cannot be used to send approval requests.", notification, text(a.Name)))
					}
					if topic.Region != sc.Region {
						return Definition{}, failure("InvalidActionDeclarationException", fmt.Sprintf("The ARN %s has been specified for sending notifications for the approval action %s, but the ARN is not in the same region as the pipeline.", notification, text(a.Name)))
					}
					// Native admission permits other accounts, FIFO names and
					// absent topics. The SNS owner validates publication itself.
				}
			}
		}
	}
	for i, st := range input.Stages {
		for _, a := range st.Actions {
			for key, configured := range a.Configuration {
				for _, match := range variableReference.FindAllStringSubmatch(string(configured), -1) {
					reference := match[1]
					name, pipelineVariable := strings.CutPrefix(reference, "variables.")
					if !pipelineVariable {
						continue
					}
					if len(variables) == 0 {
						if !namespaces["variables"] {
							return Definition{}, failure("InvalidActionDeclarationException", fmt.Sprintf("Valid format for a pipeline execution variable reference is a namespace and a key separated by a period (.). The following pipeline execution variables are referencing a namespace that does not exist.\nStageName=[%s], ActionName=[%s], ActionConfigurationKey=[%s], VariableReferenceText=[%s]", text(st.Name), text(a.Name), key, reference))
						}
						continue
					}
					if text(a.ActionTypeId.Category) == "Source" {
						return bad(fmt.Sprintf("Variables at the pipeline level cannot be used in source actions.\nStageName=[%s], ActionName=[%s], ActionConfigurationKey=[%s], VariableReferenceText=[%s]", text(st.Name), text(a.Name), key, reference))
					}
					if !variables[name] {
						return bad("The referenced variables haven't been declared.\n")
					}
				}
			}
			order := int(value(a.RunOrder))
			if a.RunOrder == nil {
				order = 1
			}
			for _, in := range a.InputArtifacts {
				producer, ok := outputs[text(in.Name)]
				if !ok || producer[0] > i || (producer[0] == i && producer[1] >= order) {
					return bad("Input artifacts must be produced by an earlier action group")
				}
			}
		}
	}
	d := CloneDeclaration(*input)
	d.Version = new(api.PipelineVersion(version))
	d.ExecutionMode = new(api.ExecutionMode(mode))
	d.PipelineType = new(api.PipelineType(kind))
	for i := range d.Stages {
		for j := range d.Stages[i].Actions {
			a := &d.Stages[i].Actions[j]
			if a.RunOrder == nil {
				a.RunOrder = new(api.ActionRunOrder(1))
			}
		}
	}
	return Definition{Declaration: d}, nil
}
