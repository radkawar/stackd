package stepfunctions

import (
	"context"
	"errors"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awswire"
	"stackd/internal/services/stepfunctions/asl"
)

func (s *Service) registerControlOperations() {
	registerMachineMutation(s, "CreateStateMachine", s.createStateMachine)
	registerMachineMutation(s, "UpdateStateMachine", s.updateStateMachine)
	register(s, "DeleteStateMachine", s.deleteStateMachine)
	register(s, "DescribeStateMachine", s.describeStateMachine)
	register(s, "ListStateMachines", s.listStateMachines)
	register(s, "PublishStateMachineVersion", s.publishStateMachineVersion)
	register(s, "DeleteStateMachineVersion", s.deleteStateMachineVersion)
	register(s, "ListStateMachineVersions", s.listStateMachineVersions)
	register(s, "CreateStateMachineAlias", s.createStateMachineAlias)
	register(s, "UpdateStateMachineAlias", s.updateStateMachineAlias)
	register(s, "DeleteStateMachineAlias", s.deleteStateMachineAlias)
	register(s, "DescribeStateMachineAlias", s.describeStateMachineAlias)
	register(s, "ListStateMachineAliases", s.listStateMachineAliases)
	register(s, "CreateActivity", s.createActivity)
	register(s, "DeleteActivity", s.deleteActivity)
	register(s, "DescribeActivity", s.describeActivity)
	register(s, "ListActivities", s.listActivities)
	register(s, "ListTagsForResource", s.listTagsForResource)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ValidateStateMachineDefinition", s.validateStateMachineDefinition)
}

var errConfigureTaskDependencies = errors.New("state machine task dependencies require admission")

type machineTaskDependencies struct {
	revision   RevisionRecord
	configured bool
}

func (d *machineTaskDependencies) require(revision RevisionRecord) error {
	if !revision.NeedsNestedSync && !revision.NeedsECSSync {
		return nil
	}
	if d.configured && d.revision.Machine == revision.Machine && d.revision.Definition == revision.Definition && d.revision.RoleARN == revision.RoleARN {
		return nil
	}
	d.revision, d.configured = revision, false
	return errConfigureTaskDependencies
}

func registerMachineMutation[I, O any](s *Service, action string, fn func(Transaction, *I, *machineTaskDependencies) (*O, error)) {
	s.operations[action] = func(ctx context.Context, input any) (any, *awswire.Error) {
		var dependencies machineTaskDependencies
		for {
			output, err := executeRecordedCommand(s, ctx, action, input.(*I), func(tx Transaction, in *I) (*O, error) {
				return fn(tx, in, &dependencies)
			})
			if !errors.Is(err, errConfigureTaskDependencies) {
				return output, wireError(err)
			}
			// The source transaction has rolled back. Real role assumptions and
			// managed-rule admission commit independently before rechecking the
			// caller and the selected revision in the next source transaction.
			if s.taskDependencies == nil {
				return nil, failure("NotImplementedException", "Step Functions task dependencies are not configured.", 501)
			}
			if err := s.taskDependencies.ConfigureTaskDependencies(ctx, dependencies.revision); err != nil {
				return nil, wireError(err)
			}
			dependencies.configured = true
		}
	}
}

func (s *Service) createStateMachine(tx Transaction, in *api.CreateStateMachineInput, dependencies *machineTaskDependencies) (*api.CreateStateMachineOutput, error) {
	name := value(in.Name)
	if !validResourceName(name) {
		return nil, failure("InvalidName", "Invalid state machine name.", 400)
	}
	typ, err := workflowType(in.Type)
	if err != nil {
		return nil, err
	}
	publish := in.Publish != nil && bool(*in.Publish)
	if in.VersionDescription != nil && !publish {
		return nil, invalid("Version description can only be set when publish is true")
	}
	if err := validDescription(value(in.VersionDescription)); err != nil {
		return nil, err
	}
	if in.RoleArn == nil {
		return nil, invalid("roleArn is required.")
	}
	if err := definitionInput(in.Definition); err != nil {
		return nil, err
	}
	key := MachineKey{Scope: scopeFor(tx.Context()), Name: name}
	tags, err := admitControlTags(in.Tags)
	if err != nil {
		return nil, err
	}
	previous, lookupErr := tx.Machine(key)
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return nil, lookupErr
	}
	if denied := s.authorize(tx, "CreateStateMachine", key.ARN(), previous.Tags, requestTagConditions(tags, nil)); denied != nil {
		return nil, denied
	}
	if previous.Status == "DELETING" {
		return nil, failure("StateMachineDeleting", "State Machine is being deleted: '"+key.ARN()+"'", 400)
	}
	revision := RevisionRecord{Definition: value(in.Definition), RoleARN: value(in.RoleArn), LogLevel: "OFF", EncryptionConfig: EncryptionConfig{EncryptionType: "AWS_OWNED_KEY"}}
	if err := s.admitConfiguration(tx.Context(), &revision, in.LoggingConfiguration, in.TracingConfiguration, in.EncryptionConfiguration); err != nil {
		return nil, err
	}
	if lookupErr == nil {
		current, err := tx.Revision(RevisionKey{Scope: key.Scope, ID: previous.RevisionID})
		if err != nil {
			return nil, err
		}
		matches := previous.Type == typ && sameDefinition(current, revision.Definition) && current.LogLevel == revision.LogLevel && current.LogGroupARN == revision.LogGroupARN && current.IncludeExecutionData == revision.IncludeExecutionData && current.TracingEnabled == revision.TracingEnabled && current.EncryptionConfig == revision.EncryptionConfig
		// Native Create identity follows the current configuration but keeps the
		// first publication's description and response version, not the latest.
		if publish != (previous.NextVersion > 1) || publish && previous.FirstVersionDescription != value(in.VersionDescription) {
			matches = false
		}
		if !matches {
			return nil, failure("StateMachineAlreadyExists", "State Machine Already Exists: '"+key.ARN()+"'", 400)
		}
		out := &api.CreateStateMachineOutput{CreationDate: controlTimestamp(previous.Created), StateMachineArn: new(api.Arn(key.ARN()))}
		if publish {
			out.StateMachineVersionArn = new(api.Arn((VersionKey{Machine: key, MachineID: previous.ID, Number: 1}).ARN()))
		}
		return out, nil
	}
	definition, err := admitDefinition(in.Definition, typ)
	if err != nil {
		return nil, err
	}
	revision.NeedsNestedSync = needsNestedSync(definition)
	revision.NeedsECSSync = needsECSSync(definition)
	if err := s.passRole(tx, revision.RoleARN, key); err != nil {
		return nil, err
	}
	if denied := s.createTagAuthority(tx, key.ARN(), tags); denied != nil {
		return nil, denied
	}
	if publish {
		if denied := s.authorize(tx, "PublishStateMachineVersion", key.ARN(), nil, nil); denied != nil {
			return nil, denied
		}
	}
	count, err := tx.MachineCount(key.Scope)
	if err != nil {
		return nil, err
	}
	if count >= maxRegisteredMachines {
		return nil, failure("StateMachineLimitExceeded", "The maximum number of registered state machines has been reached.", 400)
	}
	now := s.clock.Now().UTC()
	machine := MachineRecord{Key: key, ID: uuid.NewString(), RevisionID: uuid.NewString(), Type: typ, Status: "ACTIVE", Created: now, Version: 1, NextVersion: 1, Tags: tags}
	revision.Key, revision.Machine, revision.MachineID, revision.Created, revision.Initial = RevisionKey{Scope: key.Scope, ID: machine.RevisionID}, key, machine.ID, now, true
	if err := dependencies.require(revision); err != nil {
		return nil, err
	}
	if err := s.configureLogging(tx.Context(), revision); err != nil {
		return nil, err
	}
	sealed, err := s.sealRevision(tx.Context(), revision, "")
	if err != nil {
		return nil, encryptionAdmissionError(err)
	}
	if err := tx.PutRevision(sealed); err != nil {
		return nil, err
	}
	if err := tx.PutMachine(machine); err != nil {
		return nil, err
	}
	s.definitions.Store(revision.Key, definition)
	out := &api.CreateStateMachineOutput{CreationDate: controlTimestamp(now), StateMachineArn: new(api.Arn(key.ARN()))}
	if publish {
		version, err := s.publishRevision(tx, &machine, value(in.VersionDescription), now)
		if err != nil {
			return nil, err
		}
		out.StateMachineVersionArn = new(api.Arn(version.Key.ARN()))
	}
	return out, nil
}

func (s *Service) updateStateMachine(tx Transaction, in *api.UpdateStateMachineInput, dependencies *machineTaskDependencies) (*api.UpdateStateMachineOutput, error) {
	machine, _, err := s.controlMachine(tx, value(in.StateMachineArn), "UpdateStateMachine", true, true)
	if err != nil {
		return nil, err
	}
	if in.Definition == nil && in.RoleArn == nil && in.LoggingConfiguration == nil && in.TracingConfiguration == nil && in.EncryptionConfiguration == nil {
		return nil, failure("MissingRequiredParameter", "Either the definition, the role ARN, the LoggingConfiguration, or the TracingConfiguration must be specified", 400)
	}
	publish := in.Publish != nil && bool(*in.Publish)
	if in.VersionDescription != nil && !publish {
		return nil, invalid("Version description can only be set when publish is true")
	}
	if err := validDescription(value(in.VersionDescription)); err != nil {
		return nil, err
	}
	previous, err := tx.Revision(RevisionKey{Scope: machine.Key.Scope, ID: machine.RevisionID})
	if err != nil {
		return nil, err
	}
	revision := previous
	var definition *asl.Definition
	if in.Definition != nil {
		definition, err = admitDefinition(in.Definition, machine.Type)
		if err != nil {
			return nil, err
		}
		revision.Definition = value(in.Definition)
		revision.NeedsNestedSync = needsNestedSync(definition)
		revision.NeedsECSSync = needsECSSync(definition)
	}
	if in.RoleArn != nil {
		if err := s.passRole(tx, value(in.RoleArn), machine.Key); err != nil {
			return nil, err
		}
		revision.RoleARN = value(in.RoleArn)
	}
	if err := s.admitConfiguration(tx.Context(), &revision, in.LoggingConfiguration, in.TracingConfiguration, in.EncryptionConfiguration); err != nil {
		return nil, err
	}
	if in.EncryptionConfiguration != nil && in.Definition == nil {
		return nil, failure("MissingRequiredParameter", "The definition must be specified when updating the EncryptionConfiguration", 400)
	}
	if publish {
		if denied := s.authorize(tx, "PublishStateMachineVersion", machine.Key.ARN(), machine.Tags, nil); denied != nil {
			return nil, denied
		}
	}
	if definition == nil && revision.Encrypted == nil {
		definition, err = s.compiled(revision)
		if err != nil {
			return nil, err
		}
		revision.NeedsNestedSync = needsNestedSync(definition)
		revision.NeedsECSSync = needsECSSync(definition)
	}
	if err := dependencies.require(revision); err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	comparison := revision
	if in.Definition != nil && previous.Encrypted != nil && sameDefinition(previous, revision.Definition) {
		comparison.Definition = previous.Definition
	}
	if comparison != previous || in.Definition != nil && revision.KMSKeyARN != "" {
		if revision.LogGroupARN != previous.LogGroupARN || revision.LogLevel != previous.LogLevel || revision.RoleARN != previous.RoleARN {
			if err := s.configureLogging(tx.Context(), revision); err != nil {
				return nil, err
			}
		}
		revision.Key.ID, revision.Created, revision.Initial = uuid.NewString(), now, false
		machine.RevisionID, machine.Version = revision.Key.ID, machine.Version+1
		sealed := revision
		if in.Definition != nil {
			sealed, err = s.sealRevision(tx.Context(), revision, "")
			if err != nil {
				return nil, encryptionAdmissionError(err)
			}
		}
		if err := tx.PutRevision(sealed); err != nil {
			return nil, err
		}
		if err := tx.PutMachine(machine); err != nil {
			return nil, err
		}
		if definition != nil {
			s.definitions.Store(revision.Key, definition)
		}
	}
	out := &api.UpdateStateMachineOutput{RevisionId: publicRevisionID(revision), UpdateDate: controlTimestamp(revision.Created)}
	if publish {
		version, err := s.publishRevision(tx, &machine, value(in.VersionDescription), now)
		if err != nil {
			return nil, err
		}
		out.StateMachineVersionArn = new(api.Arn(version.Key.ARN()))
	}
	return out, nil
}

func (s *Service) deleteStateMachine(tx Transaction, in *api.DeleteStateMachineInput) (*api.DeleteStateMachineOutput, error) {
	machine, _, err := s.controlMachine(tx, value(in.StateMachineArn), "DeleteStateMachine", true, false)
	if err != nil {
		if wireError(err).Code == "StateMachineDoesNotExist" {
			return &api.DeleteStateMachineOutput{}, nil
		}
		return nil, err
	}
	if machine.Status != "DELETING" {
		now := s.clock.Now().UTC()
		machine.Status, machine.DeleteAt, machine.Version = "DELETING", &now, machine.Version+1
		if err := tx.PutMachine(machine); err != nil {
			return nil, err
		}
	}
	return &api.DeleteStateMachineOutput{}, nil
}

func (s *Service) describeStateMachine(tx Transaction, in *api.DescribeStateMachineInput) (*api.DescribeStateMachineOutput, error) {
	raw := value(in.StateMachineArn)
	reference, label, err := describeMachineReference(raw)
	if err != nil {
		return nil, err
	}
	machine, qualifier, err := s.controlMachine(tx, reference, "DescribeStateMachine", false, false)
	if err != nil {
		return nil, err
	}
	if in.IncludedData != nil && value(in.IncludedData) != "ALL_DATA" && value(in.IncludedData) != "METADATA_ONLY" {
		return nil, invalid("includedData must be ALL_DATA or METADATA_ONLY.")
	}
	revisionID, created := machine.RevisionID, machine.Created
	var description *api.VersionDescription
	if qualifier != "" {
		number, ok := versionNumber(qualifier)
		if !ok {
			return nil, invalid("DescribeStateMachine does not support alias ARNs.")
		}
		version, err := tx.Version(VersionKey{Machine: machine.Key, MachineID: machine.ID, Number: number})
		if errors.Is(err, ErrNotFound) {
			return nil, machineMissing(raw)
		}
		if err != nil {
			return nil, err
		}
		revisionID, created = version.RevisionID, version.Created
		if version.Description != "" {
			description = new(api.VersionDescription(version.Description))
		}
	}
	revision, err := tx.Revision(RevisionKey{Scope: machine.Key.Scope, ID: revisionID})
	if err != nil {
		return nil, err
	}
	if revision.Encrypted != nil && value(in.IncludedData) == "METADATA_ONLY" && label == "" {
		revision.Definition = "{}"
	} else if revision.Encrypted != nil {
		revision, err = s.openRevision(tx, revision, "")
		if err != nil {
			return nil, err
		}
	}
	typ := machine.Type
	if label != "" {
		definition, err := s.compiled(revision)
		if err != nil {
			return nil, err
		}
		state, scope := findLabelledMap(definition, label, "")
		if state == nil {
			return nil, machineMissing(raw)
		}
		child, err := processorRevision(revision, &FrameRecord{ScopePath: scope}, state)
		if err != nil {
			return nil, err
		}
		revision.Definition, typ = child.Definition, state.Map.ProcessorConfig.ExecutionType
	}
	out := &api.DescribeStateMachineOutput{CreationDate: controlTimestamp(created), Definition: new(api.Definition(revision.Definition)), Description: description, EncryptionConfiguration: encryptionOutput(revision.EncryptionConfig), LoggingConfiguration: loggingOutput(revision), Name: new(api.Name(machine.Key.Name)), RevisionId: publicRevisionID(revision), RoleArn: new(api.Arn(revision.RoleARN)), StateMachineArn: new(api.Arn(raw)), Status: new(api.StateMachineStatus(machine.Status)), TracingConfiguration: &api.TracingConfiguration{Enabled: new(api.Enabled(revision.TracingEnabled))}, Type: new(api.StateMachineType(typ))}
	if label != "" {
		out.Label = new(api.MapRunLabel(label))
	}
	return out, nil
}

func findLabelledMap(definition *asl.Definition, label, scope string) (*asl.State, string) {
	for _, state := range definition.States {
		if state.Map != nil {
			if state.Map.ProcessorConfig.Mode == "DISTRIBUTED" && state.Map.Label == label {
				return state, scope
			}
			if found, path := findLabelledMap(state.Map.Processor, label, processorScope(scope, state.Name)); found != nil {
				return found, path
			}
		}
		if state.Parallel != nil {
			for index, branch := range state.Parallel.Branches {
				if found, path := findLabelledMap(branch, label, branchScope(scope, state.Name, index)); found != nil {
					return found, path
				}
			}
		}
	}
	return nil, ""
}

func (s *Service) listStateMachines(tx Transaction, in *api.ListStateMachinesInput) (*api.ListStateMachinesOutput, error) {
	if denied := s.authorize(tx, "ListStateMachines", "*", nil, nil); denied != nil {
		return nil, denied
	}
	collection := controlCollection(tx, "ListStateMachines", "", "")
	now := s.clock.Now()
	limit, after, err := controlPage(in.NextToken, in.MaxResults, collection, now)
	if err != nil {
		return nil, err
	}
	machines, err := tx.Machines(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	out := &api.ListStateMachinesOutput{StateMachines: api.StateMachineList{}}
	for _, machine := range machines {
		if machine.Key.Name <= after {
			continue
		}
		if len(out.StateMachines) == limit {
			out.NextToken = controlNext(collection, after, now)
			break
		}
		out.StateMachines = append(out.StateMachines, api.StateMachineListItem{CreationDate: controlTimestamp(machine.Created), Name: new(api.Name(machine.Key.Name)), StateMachineArn: new(api.Arn(machine.Key.ARN())), Type: new(api.StateMachineType(machine.Type))})
		after = machine.Key.Name
	}
	return out, nil
}
