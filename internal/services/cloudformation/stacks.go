package cloudformation

import (
	"reflect"
	"slices"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/cloudformation"
	"stackd/internal/awsctx"
)

func (s *Service) registerStacks() {
	register(s, "CreateStack", s.createStack)
	register(s, "UpdateStack", s.updateStack)
	register(s, "DeleteStack", s.deleteStack)
	register(s, "CancelUpdateStack", s.cancelUpdate)
	register(s, "ContinueUpdateRollback", s.continueRollback)
	register(s, "RollbackStack", s.rollbackStack)
	register(s, "UpdateTerminationProtection", s.terminationProtection)
}
func (s *Service) createStack(tx Transaction, in *api.CreateStackInput) (*api.CreateStackOutput, error) {
	if e := supportedInput(in, "StackName", "TemplateBody", "TemplateURL", "Parameters", "Capabilities", "Tags", "RoleARN", "ClientRequestToken", "DisableRollback", "OnFailure", "EnableTerminationProtection", "DeploymentConfig"); e != nil {
		return nil, e
	}
	name := text(in.StackName)
	if !stackNamePattern.MatchString(name) {
		return nil, invalid("Stack name must start with a letter and contain only letters, numbers and hyphens, up to 128 characters")
	}
	hash := requestHash(in)
	existing, e := findStack(tx, name)
	if e == nil {
		if e = s.authorizeRole(tx, "CreateStack", existing, text(in.RoleARN)); e != nil {
			return nil, e
		}
		replay, e := replayOperation(tx, existing.ID, "CREATE", text(in.ClientRequestToken), hash)
		if e != nil {
			return nil, e
		}
		if replay {
			return &api.CreateStackOutput{StackId: new(api.StackId(existing.ID))}, nil
		}
		return nil, failure("AlreadyExistsException", "Stack ["+name+"] already exists")
	}
	if wireError(e).Code != "ValidationError" {
		return nil, e
	}
	stack := StackRecord{Scope: scopeFor(tx.Context()), Name: name, Created: s.clock.Now(), TerminationProtection: truth(in.EnableTerminationProtection)}
	stack.ID = stackARN(stack.Scope, name, uuid.NewString())
	stack.Tags, e = tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorizeRole(tx, "CreateStack", stack, text(in.RoleARN)); e != nil {
		return nil, e
	}
	body, e := s.templateBody(tx.Context(), text(in.TemplateBody), text(in.TemplateURL), false, "")
	if e != nil {
		return nil, e
	}
	t, params, resolved, e := s.prepare(tx, stack, body, in.Parameters, in.Capabilities)
	if e != nil {
		return nil, e
	}
	role, e := s.role(tx, stack.ID, text(in.RoleARN), "")
	if e != nil {
		return nil, e
	}
	disable, e := deploymentRollback(in.DeploymentConfig, in.DisableRollback)
	if e != nil {
		return nil, e
	}
	if (in.DisableRollback != nil || in.DeploymentConfig != nil && in.DeploymentConfig.DisableRollback != nil) && in.OnFailure != nil {
		return nil, invalid("DisableRollback and OnFailure cannot both be specified")
	}
	switch text(in.OnFailure) {
	case "", "ROLLBACK":
	case "DO_NOTHING":
		disable = true
	default:
		return nil, failure("NotImplementedException", "OnFailure DELETE is not implemented.", 501)
	}
	stack.Description = t.Description
	if e = s.begin(tx, stack, "CREATE", body, params, resolved, stack.Tags, capabilitiesFrom(in.Capabilities), role, text(in.ClientRequestToken), hash, "", disable); e != nil {
		return nil, e
	}
	return &api.CreateStackOutput{StackId: new(api.StackId(stack.ID))}, nil
}
func (s *Service) updateStack(tx Transaction, in *api.UpdateStackInput) (*api.UpdateStackOutput, error) {
	if e := supportedInput(in, "StackName", "TemplateBody", "TemplateURL", "UsePreviousTemplate", "Parameters", "Capabilities", "Tags", "RoleARN", "ClientRequestToken", "DisableRollback", "DeploymentConfig"); e != nil {
		return nil, e
	}
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		return nil, e
	}
	if e = s.authorizeRole(tx, "UpdateStack", stack, text(in.RoleARN)); e != nil {
		return nil, e
	}
	hash := requestHash(in)
	replay, e := replayOperation(tx, stack.ID, "UPDATE", text(in.ClientRequestToken), hash)
	if e != nil {
		return nil, e
	}
	if replay {
		return &api.UpdateStackOutput{StackId: new(api.StackId(stack.ID))}, nil
	}
	if e = updateable(stack); e != nil {
		return nil, e
	}
	body, e := s.templateBody(tx.Context(), text(in.TemplateBody), text(in.TemplateURL), truth(in.UsePreviousTemplate), stack.Template)
	if e != nil {
		return nil, e
	}
	t, params, resolved, e := s.prepare(tx, stack, body, in.Parameters, in.Capabilities)
	if e != nil {
		return nil, e
	}
	tags := stack.Tags
	if in.Tags != nil {
		tags, e = tagsFrom(in.Tags)
		if e != nil {
			return nil, e
		}
	}
	changes, e := s.changes(tx, stack, t, params, resolved, tags)
	if e != nil {
		return nil, e
	}
	prior, _ := ParseTemplate(stack.Template)
	if len(changes) == 0 && prior != nil && reflect.DeepEqual(prior.Outputs, t.Outputs) && prior.Description == t.Description {
		return nil, invalid("No updates are to be performed.")
	}
	role, e := s.role(tx, stack.ID, text(in.RoleARN), stack.RoleARN)
	if e != nil {
		return nil, e
	}
	disable, e := deploymentRollback(in.DeploymentConfig, in.DisableRollback)
	if e != nil {
		return nil, e
	}
	if e = s.begin(tx, stack, "UPDATE", body, params, resolved, tags, capabilitiesFrom(in.Capabilities), role, text(in.ClientRequestToken), hash, "", disable); e != nil {
		return nil, e
	}
	return &api.UpdateStackOutput{StackId: new(api.StackId(stack.ID))}, nil
}
func (s *Service) deleteStack(tx Transaction, in *api.DeleteStackInput) (*api.DeleteStackOutput, error) {
	if e := supportedInput(in, "StackName", "RoleARN", "ClientRequestToken", "RetainResources", "DeploymentConfig"); e != nil {
		return nil, e
	}
	if _, e := deploymentRollback(in.DeploymentConfig, nil); e != nil {
		return nil, e
	}
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		if wireError(e).Code != "ValidationError" {
			return nil, e
		}
		if e = s.authorizeRole(tx, "DeleteStack", StackRecord{}, text(in.RoleARN)); e != nil {
			return nil, e
		}
		return &api.DeleteStackOutput{}, nil
	}
	if e = s.authorizeRole(tx, "DeleteStack", stack, text(in.RoleARN)); e != nil {
		return nil, e
	}
	hash := requestHash(in)
	replay, e := replayOperation(tx, stack.ID, "DELETE", text(in.ClientRequestToken), hash)
	if e != nil {
		return nil, e
	}
	if replay || stack.Status == "DELETE_COMPLETE" {
		return &api.DeleteStackOutput{}, nil
	}
	if active(stack) {
		return nil, invalid("Stack cannot be deleted while in " + stack.Status + " state")
	}
	if stack.TerminationProtection {
		return nil, invalid("Stack [" + stack.Name + "] cannot be deleted while TerminationProtection is enabled")
	}
	if len(in.RetainResources) > 0 {
		if stack.Status != "DELETE_FAILED" {
			return nil, invalid("RetainResources can only be specified when deleting a stack in DELETE_FAILED state")
		}
		rows, e := currentResources(tx, stack.ID)
		if e != nil {
			return nil, e
		}
		for _, id := range in.RetainResources {
			v, ok := rows[string(id)]
			if !ok {
				return nil, invalid("Resource to retain does not exist: " + string(id))
			}
			v.DeletionPolicy = "Retain"
			if e = tx.PutResource(v); e != nil {
				return nil, e
			}
		}
	}
	role, e := s.role(tx, stack.ID, text(in.RoleARN), stack.RoleARN)
	if e != nil {
		return nil, e
	}
	if e = s.begin(tx, stack, "DELETE", stack.Template, stack.Parameters, stack.ResolvedParameters, stack.Tags, stack.Capabilities, role, text(in.ClientRequestToken), hash, "", false); e != nil {
		return nil, e
	}
	return &api.DeleteStackOutput{}, nil
}
func (s *Service) cancelUpdate(tx Transaction, in *api.CancelUpdateStackInput) (*api.CancelUpdateStackOutput, error) {
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "CancelUpdateStack", stack); e != nil {
		return nil, e
	}
	token, hash := text(in.ClientRequestToken), requestHash(in)
	replay, e := replayOperation(tx, stack.ID, "CANCEL", token, hash)
	if e != nil {
		return nil, e
	}
	if replay {
		return &api.CancelUpdateStackOutput{}, nil
	}
	if stack.Status != "UPDATE_IN_PROGRESS" {
		return nil, invalid("CancelUpdateStack cannot be called from current stack status")
	}
	op, e := tx.Operation(stack.OperationID)
	if e != nil {
		return nil, e
	}
	op.Cancel = true
	if e = tx.PutOperation(op); e != nil {
		return nil, e
	}
	if token != "" {
		if e = tx.PutOperation(OperationRecord{ID: operationID(stack.ID, "CANCEL", token), StackID: stack.ID, Kind: "CANCEL", Phase: "DONE", Token: token, RequestHash: hash, Started: s.clock.Now(), Due: s.clock.Now(), Caller: awsctx.FromContext(tx.Context())}); e != nil {
			return nil, e
		}
	}
	return &api.CancelUpdateStackOutput{}, nil
}
func (s *Service) continueRollback(tx Transaction, in *api.ContinueUpdateRollbackInput) (*api.ContinueUpdateRollbackOutput, error) {
	if e := supportedInput(in, "StackName", "RoleARN", "ClientRequestToken"); e != nil {
		return nil, e
	}
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		return nil, e
	}
	if e = s.authorizeRole(tx, "ContinueUpdateRollback", stack, text(in.RoleARN)); e != nil {
		return nil, e
	}
	replay, e := replayOperation(tx, stack.ID, "ROLLBACK", text(in.ClientRequestToken), requestHash(in))
	if e != nil {
		return nil, e
	}
	if replay {
		return &api.ContinueUpdateRollbackOutput{}, nil
	}
	if stack.Status != "UPDATE_ROLLBACK_FAILED" {
		return nil, invalid("Rollback can only be continued from UPDATE_ROLLBACK_FAILED")
	}
	if e = s.resumeRollback(tx, stack, text(in.RoleARN), text(in.ClientRequestToken), requestHash(in)); e != nil {
		return nil, e
	}
	return &api.ContinueUpdateRollbackOutput{}, nil
}
func (s *Service) rollbackStack(tx Transaction, in *api.RollbackStackInput) (*api.RollbackStackOutput, error) {
	if e := supportedInput(in, "StackName", "RoleARN", "ClientRequestToken"); e != nil {
		return nil, e
	}
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		return nil, e
	}
	if e = s.authorizeRole(tx, "RollbackStack", stack, text(in.RoleARN)); e != nil {
		return nil, e
	}
	replay, e := replayOperation(tx, stack.ID, "ROLLBACK", text(in.ClientRequestToken), requestHash(in))
	if e != nil {
		return nil, e
	}
	if replay {
		return &api.RollbackStackOutput{StackId: new(api.StackId(stack.ID))}, nil
	}
	if stack.Status != "CREATE_FAILED" && stack.Status != "UPDATE_FAILED" {
		return nil, invalid("RollbackStack requires CREATE_FAILED or UPDATE_FAILED")
	}
	if e = s.resumeRollback(tx, stack, text(in.RoleARN), text(in.ClientRequestToken), requestHash(in)); e != nil {
		return nil, e
	}
	return &api.RollbackStackOutput{StackId: new(api.StackId(stack.ID))}, nil
}
func (s *Service) resumeRollback(tx Transaction, stack StackRecord, requestedRole, token, hash string) error {
	role, e := s.role(tx, stack.ID, requestedRole, stack.RoleARN)
	if e != nil {
		return e
	}
	old, e := tx.Operation(stack.OperationID)
	if e != nil {
		return e
	}
	old.ID = operationID(stack.ID, "ROLLBACK", token)
	old.Token = token
	old.RequestHash = hash
	old.Phase = "ROLLBACK"
	old.Cancel = false
	old.RoleARN = role
	old.Caller = awsctx.FromContext(tx.Context())
	old.Revision++
	old.Due = s.clock.Now()
	stack.OperationID = old.ID
	stack.RoleARN = role
	stack.Status = "UPDATE_ROLLBACK_IN_PROGRESS"
	if old.Kind == "CREATE" {
		stack.Status = "ROLLBACK_IN_PROGRESS"
	}
	if e = s.stackEvent(tx, &stack, token, stack.Status, "User Initiated"); e != nil {
		return e
	}
	if e = tx.PutStack(stack); e != nil {
		return e
	}
	return tx.PutOperation(old)
}
func (s *Service) terminationProtection(tx Transaction, in *api.UpdateTerminationProtectionInput) (*api.UpdateTerminationProtectionOutput, error) {
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "UpdateTerminationProtection", stack); e != nil {
		return nil, e
	}
	stack.TerminationProtection = truth(in.EnableTerminationProtection)
	if e = tx.PutStack(stack); e != nil {
		return nil, e
	}
	return &api.UpdateTerminationProtectionOutput{StackId: new(api.StackId(stack.ID))}, nil
}
func (s *Service) checkExports(r Reader, stack StackRecord, next map[string]OutputValue) error {
	exports, e := r.Exports(stack.Scope)
	if e != nil {
		return e
	}
	desired := map[string]string{}
	for _, v := range next {
		if v.ExportName != "" {
			if _, exists := desired[v.ExportName]; exists {
				return invalid("Duplicate export name " + v.ExportName)
			}
			desired[v.ExportName] = v.Value
		}
	}
	stacks, e := r.Stacks(stack.Scope)
	if e != nil {
		return e
	}
	for _, v := range exports {
		if v.StackID != stack.ID {
			if _, ok := desired[v.Name]; ok {
				return invalid("Export with name " + v.Name + " is already exported by another stack")
			}
			continue
		}
		value, exists := desired[v.Name]
		if exists && value == v.Value {
			continue
		}
		for _, consumer := range stacks {
			if consumer.ID == stack.ID || consumer.Deleted != nil {
				continue
			}
			imports := consumer.Imports
			if active(consumer) && consumer.OperationID != "" {
				op, err := r.Operation(consumer.OperationID)
				if err != nil {
					return err
				}
				if op.Kind != "DELETE" {
					template, err := ParseTemplate(op.Template)
					if err != nil {
						return err
					}
					evaluation, err := s.evaluation(r, consumer, op.Parameters, op.ResolvedParameters)
					if err != nil {
						return err
					}
					evaluator := template.evaluator(evaluation)
					if _, err = template.order(evaluator); err != nil {
						return err
					}
					imports = append(slices.Clone(imports), templateKeys(evaluator.imports)...)
				}
			}
			if slices.Contains(imports, v.Name) {
				return invalid("Export " + v.Name + " cannot be updated as it is in use by " + consumer.Name)
			}
		}
	}
	return nil
}
