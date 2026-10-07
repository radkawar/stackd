package organizations

import (
	"context"
	"net/http"
	"slices"
	"strings"

	iampolicy "stackd/iam/policy"
	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) registerPolicyOperations() {
	register(s, "ListEffectivePolicyValidationErrors", (*operationState).listEffectivePolicyValidationErrors)
	register(s, "DescribeEffectivePolicy", (*operationState).describeEffectivePolicy)
	register(s, "CreatePolicy", (*operationState).createPolicy)
	register(s, "UpdatePolicy", (*operationState).updatePolicy)
	register(s, "DescribePolicy", func(s *operationState, r *http.Request, in *api.DescribePolicyInput) (*api.DescribePolicyOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		p, ok := o.policies[inputString(in.PolicyId)]
		if !ok || !claimVisible(r, p.CloudFormationOwner) {
			return nil, failure("PolicyNotFoundException", "The policy does not exist.")
		}
		return &api.DescribePolicyOutput{Policy: new(p.api())}, nil
	})
	register(s, "DeletePolicy", func(s *operationState, r *http.Request, in *api.DeletePolicyInput) (*api.DeletePolicyOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		p, ok := o.policies[inputString(in.PolicyId)]
		if !ok {
			return nil, failure("PolicyNotFoundException", "The policy does not exist.")
		}
		if err := claimMutation(r, p.CloudFormationOwner); err != nil {
			return nil, err
		}
		if p.PolicySummary.AWSManaged {
			return nil, failure("InvalidInputException", "IMMUTABLE_POLICY: AWS managed policies cannot be deleted.")
		}
		for _, attached := range o.attachments {
			if slices.Contains(attached, inputString(in.PolicyId)) {
				return nil, failure("PolicyInUseException", "Detach the policy from all targets before deleting it.")
			}
		}
		delete(o.policies, inputString(in.PolicyId))
		delete(o.tags, inputString(in.PolicyId))
		return &api.DeletePolicyOutput{}, nil
	})
	register(s, "AttachPolicy", func(s *operationState, r *http.Request, in *api.AttachPolicyInput) (*api.AttachPolicyOutput, *awswire.Error) {
		return &api.AttachPolicyOutput{}, s.changeAttachment(r, inputString(in.PolicyId), inputString(in.TargetId), true)
	})
	register(s, "DetachPolicy", func(s *operationState, r *http.Request, in *api.DetachPolicyInput) (*api.DetachPolicyOutput, *awswire.Error) {
		return &api.DetachPolicyOutput{}, s.changeAttachment(r, inputString(in.PolicyId), inputString(in.TargetId), false)
	})
	register(s, "ListPolicies", func(s *operationState, r *http.Request, in *api.ListPoliciesInput) (*api.ListPoliciesOutput, *awswire.Error) {
		items, next, err := s.listPolicies(r, in, inputString(in.Filter), "")
		return &api.ListPoliciesOutput{Policies: items, NextToken: nextToken(next)}, err
	})
	register(s, "ListPoliciesForTarget", func(s *operationState, r *http.Request, in *api.ListPoliciesForTargetInput) (*api.ListPoliciesForTargetOutput, *awswire.Error) {
		items, next, err := s.listPolicies(r, in, inputString(in.Filter), inputString(in.TargetId))
		return &api.ListPoliciesForTargetOutput{Policies: items, NextToken: nextToken(next)}, err
	})
	register(s, "ListTargetsForPolicy", (*operationState).listTargets)
	register(s, "EnablePolicyType", func(s *operationState, r *http.Request, in *api.EnablePolicyTypeInput) (*api.EnablePolicyTypeOutput, *awswire.Error) {
		root, err := s.changePolicyType(r, inputString(in.RootId), inputString(in.PolicyType), true)
		return &api.EnablePolicyTypeOutput{Root: root}, err
	})
	register(s, "DisablePolicyType", func(s *operationState, r *http.Request, in *api.DisablePolicyTypeInput) (*api.DisablePolicyTypeOutput, *awswire.Error) {
		root, err := s.changePolicyType(r, inputString(in.RootId), inputString(in.PolicyType), false)
		return &api.DisablePolicyTypeOutput{Root: root}, err
	})
}

func (s *operationState) createPolicy(r *http.Request, in *api.CreatePolicyInput) (*api.CreatePolicyOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if o.organization.FeatureSet != "ALL" {
		return nil, failure("ConstraintViolationException", "ORGANIZATION_NOT_IN_ALL_FEATURES_MODE")
	}
	// A controller replay of the same incarnation observes its committed
	// policy, even after a native rename; it never adopts a same-name policy.
	owner := cloudFormationClaim(r)
	if owner != "" {
		for _, p := range o.policies {
			if p.CloudFormationOwner != owner {
				continue
			}
			if p.PolicySummary.Type != inputString(in.Type) {
				return nil, failure("DuplicatePolicyException", "This CloudFormation incarnation already owns another policy.")
			}
			return &api.CreatePolicyOutput{Policy: new(p.api())}, nil
		}
	}
	count := 0
	for _, p := range o.policies {
		if p.PolicySummary.Type == inputString(in.Type) && p.PolicySummary.Name == inputString(in.Name) {
			return nil, failure("DuplicatePolicyException", "A policy of this type already has this name.")
		}
		if p.PolicySummary.Type == inputString(in.Type) {
			count++
		}
	}
	if count >= policyCountLimit(inputString(in.Type)) {
		return nil, failure("ConstraintViolationException", "POLICY_NUMBER_LIMIT_EXCEEDED")
	}
	if err := s.validatePolicy(inputString(in.Content), inputString(in.Type)); err != nil {
		return nil, err
	}
	tags, err := mergeTags(nil, in.Tags)
	if err != nil {
		return nil, err
	}
	id := s.createdResourceID
	p := policy{Content: inputString(in.Content), PolicySummary: policySummary{ID: id, ARN: o.arn(awsctx.FromContext(r.Context()).Partition, "policy", strings.ToLower(inputString(in.Type))+"/"+id), Name: inputString(in.Name), Description: inputString(in.Description), Type: inputString(in.Type)}, CloudFormationOwner: owner}
	o.policies[id] = p
	o.tags[id] = tags
	return &api.CreatePolicyOutput{Policy: new(p.api())}, nil
}

func (s *operationState) updatePolicy(r *http.Request, in *api.UpdatePolicyInput) (*api.UpdatePolicyOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	p, ok := o.policies[inputString(in.PolicyId)]
	if !ok {
		return nil, failure("PolicyNotFoundException", "The policy does not exist.")
	}
	if err := claimMutation(r, p.CloudFormationOwner); err != nil {
		return nil, err
	}
	if p.PolicySummary.AWSManaged {
		return nil, failure("InvalidInputException", "IMMUTABLE_POLICY: AWS managed policies cannot be modified.")
	}
	if in.Name != nil {
		for id, other := range o.policies {
			if id != inputString(in.PolicyId) && other.PolicySummary.Type == p.PolicySummary.Type && other.PolicySummary.Name == string(*in.Name) {
				return nil, failure("DuplicatePolicyException", "A policy of this type already has this name.")
			}
		}
		p.PolicySummary.Name = string(*in.Name)
	}
	if in.Description != nil && *in.Description != "" {
		p.PolicySummary.Description = string(*in.Description)
	}
	if in.Content != nil {
		if err := s.validatePolicy(string(*in.Content), p.PolicySummary.Type); err != nil {
			return nil, err
		}
		p.Content = string(*in.Content)
	}
	o.policies[inputString(in.PolicyId)] = p
	var targets []string
	for target, attached := range o.attachments {
		if slices.Contains(attached, inputString(in.PolicyId)) {
			targets = append(targets, target)
		}
	}
	s.scheduleEffectivePolicies(o, targets, p.PolicySummary.Type, awsctx.FromContext(r.Context()))
	// AWS returns the requested name/description fields, including an empty
	// description that does not replace the stored value.
	out := p.api()
	out.PolicySummary.Name, out.PolicySummary.Description = in.Name, in.Description
	return &api.UpdatePolicyOutput{Policy: &out}, nil
}

func (s *operationState) changeAttachment(r *http.Request, policyID, targetID string, attach bool) *awswire.Error {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return err
	}
	p, ok := o.policies[policyID]
	if !ok {
		return failure("PolicyNotFoundException", "The policy does not exist.")
	}
	if err := claimMutation(r, p.CloudFormationOwner); err != nil {
		return err
	}
	if !o.targetExists(targetID) {
		return failure("TargetNotFoundException", "The target does not exist.")
	}
	if !o.policyEnabled(p.PolicySummary.Type) {
		return failure("PolicyTypeNotEnabledException", "The policy type is disabled.")
	}
	attached := o.attachments[targetID]
	count := 0
	for _, id := range attached {
		if o.policies[id].PolicySummary.Type == p.PolicySummary.Type {
			count++
		}
	}
	if attach {
		if slices.Contains(attached, policyID) {
			return failure("DuplicatePolicyAttachmentException", "The policy is already attached to this target.")
		}
		if count >= policyAttachmentLimit(p.PolicySummary.Type) {
			return failure("ConstraintViolationException", "MAX_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED")
		}
		o.attachments[targetID] = append(attached, policyID)
	} else {
		if !slices.Contains(attached, policyID) {
			return failure("PolicyNotAttachedException", "The policy is not attached to this target.")
		}
		if p.PolicySummary.Type == "RESOURCE_CONTROL_POLICY" && p.PolicySummary.AWSManaged {
			return failure("InvalidInputException", "NON_DETACHABLE_POLICY: RCPFullAWSAccess cannot be detached.")
		}
		if count == 1 && p.PolicySummary.Type == "SERVICE_CONTROL_POLICY" {
			return failure("ConstraintViolationException", "MIN_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED: Each target must retain at least one SCP.")
		}
		o.attachments[targetID] = slices.DeleteFunc(attached, func(id string) bool { return id == policyID })
	}
	s.scheduleEffectivePolicies(o, []string{targetID}, p.PolicySummary.Type, awsctx.FromContext(r.Context()))
	return nil
}

func (s *operationState) listPolicies(r *http.Request, in paginationInput, filter, target string) (api.Policies, string, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, "", err
	}
	if target != "" && !o.targetExists(target) {
		return nil, "", failure("TargetNotFoundException", "The target does not exist.")
	}
	items := make(api.Policies, 0)
	for id, p := range o.policies {
		if p.PolicySummary.Type == filter && (target == "" || slices.Contains(o.attachments[target], id)) && claimVisible(r, p.CloudFormationOwner) {
			items = append(items, p.PolicySummary.api())
		}
	}
	return paginate(s, items, in, o.organization.ID+"/policies/"+filter+"/"+target, func(v api.PolicySummary) string { return inputString(v.Id) })
}

func (s *operationState) listTargets(r *http.Request, in *api.ListTargetsForPolicyInput) (*api.ListTargetsForPolicyOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if p, ok := o.policies[inputString(in.PolicyId)]; !ok || !claimVisible(r, p.CloudFormationOwner) {
		return nil, failure("PolicyNotFoundException", "The policy does not exist.")
	}
	items := make(api.PolicyTargets, 0)
	for id, attached := range o.attachments {
		if !slices.Contains(attached, inputString(in.PolicyId)) {
			continue
		}
		target := api.PolicyTargetSummary{TargetId: new(api.PolicyTargetId(id))}
		if a, ok := o.accounts[id]; ok {
			target.Arn, target.Name, target.Type = new(api.GenericArn(a.ARN)), new(api.TargetName(a.Name)), new(api.TargetType("ACCOUNT"))
		} else if u, ok := o.units[id]; ok {
			target.Arn, target.Name, target.Type = new(api.GenericArn(u.ARN)), new(api.TargetName(u.Name)), new(api.TargetType("ORGANIZATIONAL_UNIT"))
		} else {
			target.Arn, target.Name, target.Type = new(api.GenericArn(o.root.ARN)), new(api.TargetName(o.root.Name)), new(api.TargetType("ROOT"))
		}
		items = append(items, target)
	}
	items, next, err := paginate(s, items, in, o.organization.ID+"/targets/"+inputString(in.PolicyId), func(v api.PolicyTargetSummary) string { return inputString(v.TargetId) })
	return &api.ListTargetsForPolicyOutput{Targets: items, NextToken: nextToken(next)}, err
}

func (s *operationState) changePolicyType(r *http.Request, rootID, kind string, enable bool) (*api.Root, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if rootID != o.root.ID {
		return nil, failure("RootNotFoundException", "The root does not exist.")
	}
	if o.organization.FeatureSet != "ALL" {
		return nil, failure("PolicyTypeNotAvailableForOrganizationException", "Policy types require all features.")
	}
	if o.policyEnabled(kind) == enable {
		if enable {
			return nil, failure("PolicyTypeAlreadyEnabledException", "The policy type is already enabled.")
		}
		return nil, failure("PolicyTypeNotEnabledException", "The policy type is not enabled.")
	}
	if enable {
		o.root.PolicyTypes = append(o.root.PolicyTypes, policyType{Type: kind, Status: "ENABLED"})
		slices.SortFunc(o.root.PolicyTypes, func(a, b policyType) int { return strings.Compare(a.Type, b.Type) })
		o.installFullAccessPolicy(kind)
		o.attachDefaultType(o.root.ID, kind)
		for id := range o.parents {
			o.attachDefaultType(id, kind)
		}
	} else {
		o.root.PolicyTypes = slices.DeleteFunc(o.root.PolicyTypes, func(p policyType) bool { return p.Type == kind })
		for target, attached := range o.attachments {
			o.attachments[target] = slices.DeleteFunc(attached, func(id string) bool { return o.policies[id].PolicySummary.Type == kind })
		}
	}
	s.scheduleEffectivePolicies(o, []string{o.root.ID}, kind, awsctx.FromContext(r.Context()))
	return new(o.root.api()), nil
}

func (o *orgState) installFullAccessPolicy(kind string) {
	if kind != "SERVICE_CONTROL_POLICY" && kind != "RESOURCE_CONTROL_POLICY" {
		return
	}
	id, name := "p-FullAWSAccess", "FullAWSAccess"
	content := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	if kind == "RESOURCE_CONTROL_POLICY" {
		id, name = "p-RCPFullAWSAccess", "RCPFullAWSAccess"
		content = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`
	}
	partition := strings.Split(o.organization.ARN, ":")[1]
	o.policies[id] = policy{Content: content, PolicySummary: policySummary{ID: id, ARN: "arn:" + partition + ":organizations::aws:policy/" + strings.ToLower(kind) + "/" + id, Name: name, Description: "Allows access to every operation", Type: kind, AWSManaged: true}}
}

func (o *orgState) attachDefaults(target string) {
	for _, kind := range []string{"SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"} {
		if o.policyEnabled(kind) {
			o.attachDefaultType(target, kind)
		}
	}
}

func (o *orgState) attachDefaultType(target, kind string) {
	if kind != "SERVICE_CONTROL_POLICY" && kind != "RESOURCE_CONTROL_POLICY" {
		return
	}
	id := "p-FullAWSAccess"
	if kind == "RESOURCE_CONTROL_POLICY" {
		id = "p-RCPFullAWSAccess"
	}
	if !slices.Contains(o.attachments[target], id) {
		o.attachments[target] = append(o.attachments[target], id)
	}
}

// ServiceControlPolicies returns a snapshot of the SCP hierarchy for an account.
// The management account is exempt from SCPs, as it is in AWS Organizations.
func (s *Service) ServiceControlPolicies(ctx context.Context, accountID string) ([]iampolicy.PolicyLevel, error) {
	m := awsctx.FromContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if snapshot, ok := ctx.Value(policySnapshotKey{}).(policySnapshot); ok && snapshot.source == s && snapshot.partition == m.Partition && snapshot.account == accountID {
		return clonePolicyLevels(snapshot.levels), nil
	}
	record, _, err := s.storage.Load(ctx, m.Partition)
	if err != nil {
		return nil, err
	}
	worker := &operationState{serviceState: decodeState(record, m.Partition, accountID)}
	return worker.policyLevels(accountID), nil
}

func clonePolicyLevels(levels []iampolicy.PolicyLevel) []iampolicy.PolicyLevel {
	out := slices.Clone(levels)
	for i := range out {
		out[i].Documents = slices.Clone(out[i].Documents)
	}
	return out
}

func (s *operationState) policyLevels(accountID string) []iampolicy.PolicyLevel {
	o := s.orgs[s.memberships[accountID]]
	if o == nil || o.organization.MasterAccountID == accountID || !o.policyEnabled("SERVICE_CONTROL_POLICY") {
		return nil
	}
	return o.controlPolicyLevels(accountID, "SERVICE_CONTROL_POLICY")
}

func (o *orgState) controlPolicyLevels(targetID, kind string) []iampolicy.PolicyLevel {
	var levels []iampolicy.PolicyLevel
	for target := targetID; target != ""; target = o.parents[target] {
		level := iampolicy.PolicyLevel{TargetID: target, Documents: []iampolicy.Policy{}}
		for _, id := range o.attachments[target] {
			if p := o.policies[id]; p.PolicySummary.Type == kind {
				level.Documents = append(level.Documents, iampolicy.Policy{Source: p.PolicySummary.ARN, Document: p.Content})
			}
		}
		slices.SortFunc(level.Documents, func(a, b iampolicy.Policy) int { return strings.Compare(a.Source, b.Source) })
		levels = append(levels, level)
	}
	slices.Reverse(levels)
	return levels
}
