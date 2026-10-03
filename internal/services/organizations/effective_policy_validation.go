package organizations

import (
	"net/http"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awswire"
)

// EffectivePolicyError records a diagnostic produced by an inherited policy,
// with the actual contributing policy IDs rather than a copy of their documents.
type EffectivePolicyError struct {
	Code, Message, Path  string
	ContributingPolicies []string
}

func (e EffectivePolicyError) api() api.EffectivePolicyValidationError {
	ids := make(api.PolicyIds, 0, len(e.ContributingPolicies))
	for _, id := range e.ContributingPolicies {
		ids = append(ids, api.PolicyId(id))
	}
	return api.EffectivePolicyValidationError{ContributingPolicies: ids, ErrorCode: new(api.ErrorCode(e.Code)), ErrorMessage: new(api.ErrorMessage(e.Message)), PathToError: new(api.PathToError(e.Path))}
}

func (s *operationState) listEffectivePolicyValidationErrors(r *http.Request, in *api.ListEffectivePolicyValidationErrorsInput) (*api.ListEffectivePolicyValidationErrorsOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	account, kind := inputString(in.AccountId), inputString(in.PolicyType)
	if _, ok := o.accounts[account]; !ok {
		return nil, failure("AccountNotFoundException", "The account does not exist in this organization.")
	}
	if !o.policyEnabled(kind) {
		return nil, failure("EffectivePolicyNotFoundException", "The policy type is not enabled.")
	}
	if kind != "BACKUP_POLICY" && kind != "TAG_POLICY" && kind != "CHATBOT_POLICY" {
		// TODO: Comeback implement effective-policy diagnostics for the remaining management-policy service schemas and their downstream enforcement failures; do not return an empty report for an unvalidated policy type.
		return nil, &awswire.Error{Code: "NotImplementedException", Message: "Effective policy validation is not implemented for this policy type.", StatusCode: http.StatusNotImplemented}
	}
	policy := o.effectivePolicies[effectivePolicyKey{account, kind}]
	items, next, err := paginate(s, policy.ValidationErrors, in, o.organization.ID+"/effective-validation/"+account+"/"+kind, func(e EffectivePolicyError) string { return e.Path + "\x00" + e.Code + "\x00" + e.Message })
	if err != nil {
		return nil, err
	}
	out := &api.ListEffectivePolicyValidationErrorsOutput{AccountId: in.AccountId, PolicyType: in.PolicyType, EffectivePolicyValidationErrors: make(api.EffectivePolicyValidationErrors, 0, len(items)), NextToken: nextToken(next)}
	for _, e := range items {
		out.EffectivePolicyValidationErrors = append(out.EffectivePolicyValidationErrors, e.api())
	}
	if policy.ValidationPath != "" {
		out.Path = new(api.Path(policy.ValidationPath))
		out.EvaluationTimestamp = new(policy.UpdatedAt)
	}
	return out, nil
}
