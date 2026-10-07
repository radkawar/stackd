package cloudformation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/cloudformation"
	"stackd/internal/awsctx"
)

var stackNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,127}$`)

func requestHash(input any) string {
	b, _ := json.Marshal(input)
	v := sha256.Sum256(b)
	return hex.EncodeToString(v[:])
}
func operationID(stackID, kind, token string) string {
	if token == "" {
		return uuid.NewString()
	}
	return requestHash([]string{stackID, kind, token})
}
func replayOperation(r Reader, stackID, kind, token, hash string) (bool, error) {
	if token == "" {
		return false, nil
	}
	op, e := r.Operation(operationID(stackID, kind, token))
	if errors.Is(e, ErrNotFound) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if op.RequestHash != hash {
		return false, failure("TokenAlreadyExistsException", "A different request already exists with this client request token.")
	}
	return true, nil
}
func bindParameters(t *Template, in api.Parameters, previous map[string]string) (map[string]string, error) {
	values := map[string]string{}
	reuse := map[string]bool{}
	seen := map[string]bool{}
	for _, p := range in {
		k := text(p.ParameterKey)
		if k == "" || seen[k] {
			return nil, invalid("Parameter keys must be nonempty and unique")
		}
		seen[k] = true
		if p.ParameterValue != nil {
			values[k] = text(p.ParameterValue)
		}
		if truth(p.UsePreviousValue) {
			reuse[k] = true
		}
	}
	return t.BindParameters(values, previous, reuse)
}
func tagsFrom(in api.Tags) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range in {
		k := text(v.Key)
		if k == "" || strings.HasPrefix(strings.ToLower(k), "aws:") || strings.HasPrefix(strings.ToLower(k), "stackd:cloudformation:") {
			return nil, invalid("Invalid stack tag key")
		}
		if _, ok := out[k]; ok {
			return nil, invalid("Duplicate stack tag key")
		}
		out[k] = text(v.Value)
	}
	return out, nil
}
func capabilitiesFrom(in api.Capabilities) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, string(v))
	}
	slices.Sort(out)
	return slices.Compact(out)
}
func (s *Service) templateBody(ctx context.Context, body, url string, usePrevious bool, previous string) (string, error) {
	if url != "" {
		if body != "" || usePrevious {
			return "", invalid("TemplateURL cannot be combined with TemplateBody or UsePreviousTemplate")
		}
		if s.templates == nil {
			return "", failure("NotImplementedException", "TemplateURL S3 owner is unavailable.", 501)
		}
		return s.templates.ReadTemplate(ctx, url)
	}
	if usePrevious {
		if body != "" || previous == "" {
			return "", invalid("UsePreviousTemplate requires an existing template and cannot be combined with TemplateBody")
		}
		t, e := ParseTemplate(previous)
		if e != nil {
			return "", e
		}
		if t.LanguageExtensions {
			return "", failure("NotImplementedException", "UsePreviousTemplate with AWS::LanguageExtensions requires retained processed templates.", 501)
		}
		return previous, nil
	}
	if body == "" {
		return "", invalid("TemplateBody must be specified")
	}
	if len(body) > 51200 {
		return "", invalid("TemplateBody exceeds 51200 bytes")
	}
	return body, nil
}
func (s *Service) prepare(r Reader, stack StackRecord, body string, parameters api.Parameters, caps api.Capabilities) (*Template, map[string]string, map[string]string, error) {
	t, e := ParseTemplate(body)
	if e != nil {
		return nil, nil, nil, e
	}
	if e = t.ValidateHandlers(s.handlers); e != nil {
		return nil, nil, nil, e
	}
	provided := capabilitiesFrom(caps)
	for _, required := range t.Capabilities() {
		if !slices.Contains(provided, required) && !(required == "CAPABILITY_IAM" && slices.Contains(provided, "CAPABILITY_NAMED_IAM")) {
			return nil, nil, nil, failure("InsufficientCapabilitiesException", "Requires capabilities : ["+required+"]")
		}
	}
	params, e := bindParameters(t, parameters, stack.Parameters)
	if e != nil {
		return nil, nil, nil, e
	}
	var resolved map[string]string
	for name, parameter := range t.Parameters {
		if !strings.HasPrefix(parameter.Type, "AWS::SSM::Parameter::") {
			continue
		}
		if s.parameters == nil {
			return nil, nil, nil, failure("NotImplementedException", "SSM parameter owner is unavailable.", 501)
		}
		value, err := s.parameters.ResolveParameter(r.Context(), params[name])
		if err != nil {
			return nil, nil, nil, err
		}
		if parameter.Type != "AWS::SSM::Parameter::Name" {
			if resolved == nil {
				resolved = map[string]string{}
			}
			resolved[name] = value
		}
	}
	evaluation, e := s.evaluation(r, stack, params, resolved)
	if e != nil {
		return nil, nil, nil, e
	}
	if e := t.validateResolvedPolicies(evaluation, s.handlers); e != nil {
		return nil, nil, nil, e
	}
	if e := t.ValidateRules(evaluation); e != nil {
		return nil, nil, nil, e
	}
	evaluator := t.evaluator(evaluation)
	if _, e = t.order(evaluator); e != nil {
		return nil, nil, nil, e
	}
	if len(evaluator.imports) > 0 {
		exports, err := r.Exports(stack.Scope)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, export := range exports {
			if !evaluator.imports[export.Name] {
				continue
			}
			provider, err := r.Stack(export.StackID)
			if err != nil {
				return nil, nil, nil, err
			}
			if provider.Status == "DELETE_IN_PROGRESS" || provider.Deleted != nil {
				return nil, nil, nil, invalid("Export " + export.Name + " is being deleted")
			}
		}
	}
	return t, params, resolved, nil
}
func (s *Service) evaluation(r Reader, stack StackRecord, parameters, resolved map[string]string) (Evaluation, error) {
	e := Evaluation{Scope: stack.Scope, StackID: stack.ID, StackName: stack.Name, Parameters: parameters, ResolvedParameters: resolved, Resources: map[string]ResourceResult{}, Imports: map[string]string{}, Context: r.Context(), AvailabilityZones: s.availabilityZones}
	resources, err := r.Resources(stack.ID)
	if err != nil {
		return e, err
	}
	for _, v := range resources {
		if v.Current && v.PhysicalID != "" {
			e.Resources[v.LogicalID] = ResourceResult{PhysicalID: v.PhysicalID, Ref: v.Ref, Attributes: v.Attributes}
		}
	}
	exports, err := r.Exports(stack.Scope)
	if err != nil {
		return e, err
	}
	for _, v := range exports {
		if v.StackID != stack.ID {
			e.Imports[v.Name] = v.Value
		}
	}
	return e, nil
}
func currentResources(r Reader, id string) (map[string]ResourceRecord, error) {
	rows, e := r.Resources(id)
	if e != nil {
		return nil, e
	}
	out := map[string]ResourceRecord{}
	for _, v := range rows {
		if v.Current {
			out[v.LogicalID] = v
		}
	}
	return out, nil
}
func active(stack StackRecord) bool {
	return strings.HasSuffix(stack.Status, "_IN_PROGRESS") || strings.HasSuffix(stack.Status, "_CLEANUP_IN_PROGRESS")
}
func updateable(stack StackRecord) error {
	if active(stack) {
		return invalid("Stack " + stack.ID + " is in " + stack.Status + " state and can not be updated")
	}
	switch stack.Status {
	case "CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "CREATE_FAILED", "UPDATE_FAILED":
		return nil
	}
	return invalid("Stack " + stack.ID + " is in " + stack.Status + " state and can not be updated")
}
func (s *Service) changes(r Reader, stack StackRecord, t *Template, params, resolved, tags map[string]string) ([]ChangeRecord, error) {
	e, e1 := s.evaluation(r, stack, params, resolved)
	if e1 != nil {
		return nil, e1
	}
	order, e1 := t.Order(e)
	if e1 != nil {
		return nil, e1
	}
	policies, e1 := t.ResolvePolicies(e)
	if e1 != nil {
		return nil, e1
	}
	old, e1 := currentResources(r, stack.ID)
	if e1 != nil {
		return nil, e1
	}
	var prior *Template
	if stack.Template != "" {
		prior, e1 = ParseTemplate(stack.Template)
		if e1 != nil {
			return nil, e1
		}
	}
	out := []ChangeRecord{}
	enabled := map[string]bool{}
	affected := map[string]bool{}
	for _, id := range order {
		enabled[id] = true
		resource := t.Resources[id]
		before, exists := old[id]
		props, resolveErr := t.ResolveResource(id, e)
		if resolveErr != nil {
			props = resource.Properties
		}
		if !exists || before.PhysicalID == "" {
			affected[id] = true
			out = append(out, ChangeRecord{LogicalID: id, Type: resource.Type, Action: "Add", AfterContext: changeContext(props)})
			continue
		}
		dependencyChanged := referencesChanged(resource.Properties, affected)
		policyChanged := policies[id].DeletionPolicy != before.DeletionPolicy || policies[id].UpdateReplacePolicy != before.UpdateReplacePolicy
		policyExpressionChanged := prior == nil || !reflect.DeepEqual(prior.Resources[id].DeletionPolicy, resource.DeletionPolicy) || !reflect.DeepEqual(prior.Resources[id].UpdateReplacePolicy, resource.UpdateReplacePolicy)
		changed := dependencyChanged || policyChanged || before.Type != resource.Type || !maps.Equal(params, stack.Parameters) || !maps.Equal(resolved, stack.ResolvedParameters) || !maps.Equal(tags, stack.Tags) || prior == nil || !reflect.DeepEqual(prior.Resources[id], resource)
		if !changed {
			continue
		}
		replacement := "Conditional"
		if resolveErr == nil && !hasDynamicReferences(props) && !hasDynamicReferences(before.Properties) {
			if e1 = s.handlers[resource.Type].Validate(props); e1 != nil {
				return nil, e1
			}
			replacement = "True"
			if before.Type == resource.Type {
				replacement, e1 = resourceReplacementPlan(s.handlers[resource.Type], stack.Scope, before.Properties, props)
				if e1 != nil {
					return nil, e1
				}
			}
			if replacement == "False" && !dependencyChanged && !policyChanged && !policyExpressionChanged && reflect.DeepEqual(props, before.Properties) && maps.Equal(tags, stack.Tags) {
				continue
			}
		}
		affected[id] = true
		out = append(out, ChangeRecord{LogicalID: id, Type: resource.Type, Action: "Modify", Replacement: replacement, PhysicalID: before.PhysicalID, BeforeContext: changeContext(before.Properties), AfterContext: changeContext(props)})
	}
	for _, id := range slices.Sorted(maps.Keys(old)) {
		v := old[id]
		if !enabled[id] {
			out = append(out, ChangeRecord{LogicalID: id, Type: v.Type, Action: "Remove", PhysicalID: v.PhysicalID, BeforeContext: changeContext(v.Properties)})
		}
	}
	return out, nil
}
func (s *Service) begin(tx Transaction, stack StackRecord, kind, body string, params, resolved, tags map[string]string, caps []string, role, token, hash, changeSetID string, disableRollback bool) error {
	op := OperationRecord{ID: operationID(stack.ID, kind, token), StackID: stack.ID, Kind: kind, Phase: "APPLY", Token: token, RequestHash: hash, ChangeSetID: changeSetID, Template: body, Parameters: params, ResolvedParameters: resolved, Tags: tags, Capabilities: caps, RoleARN: role, Caller: awsctx.FromContext(tx.Context()), Revision: 1, Due: s.clock.Now(), Started: s.clock.Now(), DisableRollback: disableRollback}
	op.Caller.ParentEventID = apievents.EventID(tx.Context())
	current, e := currentResources(tx, stack.ID)
	if e != nil {
		return e
	}
	all, e := tx.Resources(stack.ID)
	if e != nil {
		return e
	}
	generations := map[string]uint64{}
	for _, v := range all {
		generations[v.LogicalID] = max(generations[v.LogicalID], v.Generation)
	}
	if kind != "DELETE" {
		t, e := ParseTemplate(body)
		if e != nil {
			return e
		}
		evaluation, e := s.evaluation(tx, stack, params, resolved)
		if e != nil {
			return e
		}
		policies, e := t.ResolvePolicies(evaluation)
		if e != nil {
			return e
		}
		order, e := t.Order(evaluation)
		if e != nil {
			return e
		}
		for _, id := range order {
			before := current[id]
			after := ResourceRecord{StackID: stack.ID, LogicalID: id, Type: t.Resources[id].Type, Generation: generations[id] + 1, Token: uuid.NewString(), Current: true, DeletionPolicy: policies[id].DeletionPolicy, UpdateReplacePolicy: policies[id].UpdateReplacePolicy}
			op.Steps = append(op.Steps, StepRecord{Position: len(op.Steps), LogicalID: id, Action: "UPSERT", State: "PENDING", Before: before, After: after})
			delete(current, id)
		}
	}
	// Removed resources and stack deletion run in reverse dependency order.
	ids := slices.Sorted(maps.Keys(current))
	if stack.Template != "" {
		oldTemplate, e := ParseTemplate(stack.Template)
		if e != nil {
			return e
		}
		evaluation, e := s.evaluation(tx, stack, stack.Parameters, stack.ResolvedParameters)
		if e != nil {
			return e
		}
		oldOrder, e := oldTemplate.Order(evaluation)
		if e != nil {
			return e
		}
		slices.Reverse(oldOrder)
		ids = oldOrder
	}
	for _, id := range ids {
		if before, ok := current[id]; ok {
			op.Steps = append(op.Steps, StepRecord{Position: len(op.Steps), LogicalID: id, Action: "DELETE", State: "PENDING", Before: before})
			delete(current, id)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(current)) {
		op.Steps = append(op.Steps, StepRecord{Position: len(op.Steps), LogicalID: id, Action: "DELETE", State: "PENDING", Before: current[id]})
	}
	stack.OperationID = op.ID
	stack.Status = kind + "_IN_PROGRESS"
	stack.StatusReason = "User Initiated"
	stack.RoleARN = role
	stack.DisableRollback = disableRollback
	if kind == "CREATE" {
		stack.Template, stack.Parameters, stack.Tags, stack.Capabilities = body, params, tags, caps
		stack.ResolvedParameters = resolved
	}
	if kind != "CREATE" {
		stack.Updated = s.clock.Now()
	}
	if e = s.stackEvent(tx, &stack, op.Token, stack.Status, stack.StatusReason); e != nil {
		return e
	}
	if e = tx.PutStack(stack); e != nil {
		return e
	}
	if kind != "DELETE" {
		sets, err := tx.ChangeSets(stack.ID)
		if err != nil {
			return err
		}
		for _, set := range sets {
			if set.ID != changeSetID && (set.ExecutionStatus == "AVAILABLE" || set.ExecutionStatus == "UNAVAILABLE") {
				if err := tx.DeleteChangeSet(set.ID); err != nil {
					return err
				}
			}
		}
	}
	return tx.PutOperation(op)
}
