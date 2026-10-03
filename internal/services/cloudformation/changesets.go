package cloudformation

import (
	"reflect"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/cloudformation"
)

func (s *Service) registerChangeSets() {
	register(s, "CreateChangeSet", s.createChangeSet)
	register(s, "ExecuteChangeSet", s.executeChangeSet)
	register(s, "DeleteChangeSet", s.deleteChangeSet)
}
func (s *Service) createChangeSet(tx Transaction, in *api.CreateChangeSetInput) (*api.CreateChangeSetOutput, error) {
	if e := supportedInput(in, "ChangeSetName", "ChangeSetType", "ClientToken", "Description", "Parameters", "Capabilities", "RoleARN", "StackName", "Tags", "TemplateBody", "TemplateURL", "UsePreviousTemplate", "DeploymentConfig", "ImportExistingResources", "IncludeNestedStacks"); e != nil {
		return nil, e
	}
	disableRollback, err := deploymentRollback(in.DeploymentConfig, nil)
	if err != nil {
		return nil, err
	}
	// IncludeNestedStacks selects descendants, not a different execution mode.
	// Actual nested resources remain rejected by ParseTemplate; admitted stacks
	// have no descendants and their complete hierarchy is the root change set.
	name := text(in.ChangeSetName)
	if !stackNamePattern.MatchString(name) {
		return nil, invalid("Invalid change set name")
	}
	kind := text(in.ChangeSetType)
	if kind == "" {
		kind = "UPDATE"
	}
	if kind != "CREATE" && kind != "UPDATE" {
		return nil, failure("NotImplementedException", "Only CREATE and UPDATE change sets are implemented.", 501)
	}
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		if kind != "CREATE" || wireError(e).Code != "ValidationError" {
			return nil, e
		}
		name := text(in.StackName)
		if !stackNamePattern.MatchString(name) {
			return nil, invalid("Invalid stack name")
		}
		stack = StackRecord{Scope: scopeFor(tx.Context()), Name: name, Status: "REVIEW_IN_PROGRESS", Created: s.clock.Now()}
		stack.ID = stackARN(stack.Scope, name, uuid.NewString())
	} else if kind == "CREATE" && stack.Status != "REVIEW_IN_PROGRESS" {
		return nil, invalid("Stack already exists; use UPDATE change set type")
	}
	if e = s.authorizeRole(tx, "CreateChangeSet", stack, text(in.RoleARN)); e != nil {
		return nil, e
	}
	hash := requestHash(in)
	sets, e := tx.ChangeSets(stack.ID)
	if e != nil {
		return nil, e
	}
	for _, v := range sets {
		if v.Name == name && !executedChangeSet(v) {
			if text(in.ClientToken) != "" && v.Token == text(in.ClientToken) && v.RequestHash == hash {
				return &api.CreateChangeSetOutput{Id: new(api.ChangeSetId(v.ID)), StackId: new(api.StackId(stack.ID))}, nil
			}
			return nil, failure("AlreadyExistsException", "ChangeSet ["+name+"] already exists")
		}
	}
	if kind == "UPDATE" {
		if e = updateable(stack); e != nil {
			return nil, e
		}
	}
	body, e := s.templateBody(tx.Context(), text(in.TemplateBody), text(in.TemplateURL), truth(in.UsePreviousTemplate), stack.Template)
	if e != nil {
		return nil, e
	}
	t, params, resolved, e := s.prepare(tx, stack, body, in.Parameters, in.Capabilities)
	if e != nil {
		return nil, e
	}
	if truth(in.ImportExistingResources) {
		if err := s.checkAutomaticImports(tx, stack, t, params, resolved); err != nil {
			return nil, err
		}
	}
	tags := stack.Tags
	if in.Tags != nil {
		tags, e = tagsFrom(in.Tags)
		if e != nil {
			return nil, e
		}
	}
	role, e := s.role(tx, stack.ID, text(in.RoleARN), stack.RoleARN)
	if e != nil {
		return nil, e
	}
	changes, e := s.changes(tx, stack, t, params, resolved, tags)
	if e != nil {
		return nil, e
	}
	v := ChangeSetRecord{Scope: stack.Scope, ID: "arn:" + stack.Scope.Partition + ":cloudformation:" + stack.Scope.Region + ":" + stack.Scope.Account + ":changeSet/" + name + "/" + uuid.NewString(), Name: name, StackID: stack.ID, StackName: stack.Name, Type: kind, Status: "CREATE_COMPLETE", ExecutionStatus: "AVAILABLE", Description: text(in.Description), Template: body, RoleARN: role, Token: text(in.ClientToken), RequestHash: hash, Parameters: params, Tags: tags, Capabilities: capabilitiesFrom(in.Capabilities), Changes: changes, Created: s.clock.Now()}
	v.ResolvedParameters = resolved
	v.DisableRollback = disableRollback
	prior, _ := ParseTemplate(stack.Template)
	if kind == "UPDATE" && len(changes) == 0 && prior != nil && reflect.DeepEqual(prior.Outputs, t.Outputs) && prior.Description == t.Description {
		v.Status = "FAILED"
		v.ExecutionStatus = "UNAVAILABLE"
		v.Reason = "The submitted information didn't contain changes. Submit different information to create a change set."
	}
	if kind == "CREATE" {
		stack.Description = t.Description
		if e = tx.PutStack(stack); e != nil {
			return nil, e
		}
	}
	if e = tx.PutChangeSet(v); e != nil {
		return nil, e
	}
	return &api.CreateChangeSetOutput{Id: new(api.ChangeSetId(v.ID)), StackId: new(api.StackId(stack.ID))}, nil
}

// Executed change sets retain immutable ARN-addressed history, but release their
// names and disappear from ListChangeSets. CDK reuses one change-set name.
func executedChangeSet(v ChangeSetRecord) bool {
	return v.ExecutionStatus == "EXECUTE_COMPLETE" || v.ExecutionStatus == "EXECUTE_FAILED"
}

func findChangeSet(r Reader, name, stackName string) (ChangeSetRecord, error) {
	if strings.HasPrefix(name, "arn:") {
		v, e := r.ChangeSet(name)
		if e == nil && v.Scope == scopeFor(r.Context()) {
			if stackName != "" && stackName != v.StackID && stackName != v.StackName {
				return ChangeSetRecord{}, failure("ChangeSetNotFound", "ChangeSet does not exist", 404)
			}
			return v, nil
		}
		return ChangeSetRecord{}, failure("ChangeSetNotFound", "ChangeSet does not exist", 404)
	}
	if stackName == "" {
		return ChangeSetRecord{}, invalid("StackName must be specified when ChangeSetName is not an ARN")
	}
	stack, e := findStack(r, stackName)
	if e != nil {
		return ChangeSetRecord{}, e
	}
	sets, e := r.ChangeSets(stack.ID)
	if e != nil {
		return ChangeSetRecord{}, e
	}
	for _, v := range sets {
		if v.Name == name && !executedChangeSet(v) {
			return v, nil
		}
	}
	return ChangeSetRecord{}, failure("ChangeSetNotFound", "ChangeSet ["+name+"] does not exist", 404)
}
func (s *Service) executeChangeSet(tx Transaction, in *api.ExecuteChangeSetInput) (*api.ExecuteChangeSetOutput, error) {
	if e := supportedInput(in, "ChangeSetName", "StackName", "ClientRequestToken", "DisableRollback"); e != nil {
		return nil, e
	}
	set, e := findChangeSet(tx, text(in.ChangeSetName), text(in.StackName))
	if e != nil {
		return nil, e
	}
	stack, e := findStack(tx, set.StackID)
	if e != nil {
		return nil, e
	}
	authorizationStack := stack
	authorizationStack.RoleARN = set.RoleARN
	if e = s.authorize(tx, "ExecuteChangeSet", authorizationStack); e != nil {
		return nil, e
	}
	hash := requestHash(in)
	replay, e := replayOperation(tx, stack.ID, set.Type, text(in.ClientRequestToken), hash)
	if e != nil {
		return nil, e
	}
	if replay {
		return &api.ExecuteChangeSetOutput{}, nil
	}
	if set.Status != "CREATE_COMPLETE" || set.ExecutionStatus != "AVAILABLE" {
		return nil, failure("InvalidChangeSetStatus", "ChangeSet cannot be executed in its current status")
	}
	if set.Type == "UPDATE" {
		if e = updateable(stack); e != nil {
			return nil, e
		}
	} else if stack.Status != "REVIEW_IN_PROGRESS" {
		return nil, invalid("Stack is not in REVIEW_IN_PROGRESS")
	}
	disableRollback := set.DisableRollback
	if in.DisableRollback != nil {
		disableRollback = truth(in.DisableRollback)
	}
	if e = s.begin(tx, stack, set.Type, set.Template, set.Parameters, set.ResolvedParameters, set.Tags, set.Capabilities, set.RoleARN, text(in.ClientRequestToken), hash, set.ID, disableRollback); e != nil {
		return nil, e
	}
	set.ExecutionStatus = "EXECUTE_IN_PROGRESS"
	if e = tx.PutChangeSet(set); e != nil {
		return nil, e
	}
	return &api.ExecuteChangeSetOutput{}, nil
}
func (s *Service) deleteChangeSet(tx Transaction, in *api.DeleteChangeSetInput) (*api.DeleteChangeSetOutput, error) {
	set, e := findChangeSet(tx, text(in.ChangeSetName), text(in.StackName))
	if e != nil {
		if wireError(e).Code == "ChangeSetNotFound" {
			if e = s.authorize(tx, "DeleteChangeSet", StackRecord{}); e != nil {
				return nil, e
			}
			return &api.DeleteChangeSetOutput{}, nil
		}
		return nil, e
	}
	stack, e := findStack(tx, set.StackID)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "DeleteChangeSet", stack); e != nil {
		return nil, e
	}
	if strings.HasPrefix(set.ExecutionStatus, "EXECUTE_") {
		return nil, failure("InvalidChangeSetStatus", "Cannot delete ChangeSet in execution status "+set.ExecutionStatus)
	}
	if e = tx.DeleteChangeSet(set.ID); e != nil {
		return nil, e
	}
	return &api.DeleteChangeSetOutput{}, nil
}
