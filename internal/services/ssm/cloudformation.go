package ssm

import "context"

type cloudFormationPolicyOwnerKey struct{}

// WithCloudFormationResourcePolicyOwner binds an AWS::SSM::ResourcePolicy
// incarnation claim to ordinary, still-authorized resource-policy commands.
// It is internal command context, never wire input. Under a claim,
// PutResourcePolicy without an identifier returns the policy this incarnation
// already created, mutations require the stored claim, and
// GetResourcePolicies lists only the claimed policy.
func WithCloudFormationResourcePolicyOwner(ctx context.Context, claim string) context.Context {
	return context.WithValue(ctx, cloudFormationPolicyOwnerKey{}, claim)
}

func cloudFormationPolicyOwner(ctx context.Context) (string, bool) {
	claim, ok := ctx.Value(cloudFormationPolicyOwnerKey{}).(string)
	return claim, ok && claim != ""
}

func cloudFormationPolicyConflict() error {
	return failure("ResourcePolicyConflictException", "The resource policy belongs to another CloudFormation resource incarnation.")
}

type cloudFormationParameterOwnerKey struct{}

// WithCloudFormationParameterOwner binds an AWS::SSM::Parameter incarnation
// claim to ordinary, still-authorized parameter commands. It is internal
// command context, never wire input or a tag. Under a claim, PutParameter
// records the claim on a new parameter or returns the parameter this claim
// already created, and every other parameter command requires the stored
// claim in the same transaction as its effect.
func WithCloudFormationParameterOwner(ctx context.Context, claim string) context.Context {
	return context.WithValue(ctx, cloudFormationParameterOwnerKey{}, claim)
}

func cloudFormationParameterOwner(ctx context.Context) (string, bool) {
	claim, ok := ctx.Value(cloudFormationParameterOwnerKey{}).(string)
	return claim, ok && claim != ""
}

// cloudFormationParameterConflict rejects a claimed command on a parameter the
// claim did not create, including a same-name recreation with copied tags.
func cloudFormationParameterConflict(ctx context.Context, p ParameterRecord) error {
	if claim, claimed := cloudFormationParameterOwner(ctx); claimed && p.CloudFormationOwner != claim {
		return failure("AccessDeniedException", "The parameter belongs to a different CloudFormation resource incarnation.")
	}
	return nil
}
