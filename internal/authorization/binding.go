package authorization

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"stackd/iam/policy"
)

// ErrInvalidPrincipal identifies a resource policy that refers to an unknown,
// deleted or unsupported IAM principal at policy configuration time.
var ErrInvalidPrincipal = errors.New("invalid resource policy principal")

// Principal binds a current IAM ARN to its immutable unique identity.
type Principal struct {
	ARN string
	ID  string
}

// PrincipalResolver resolves either an IAM user/role ARN or an immutable ID in
// the request partition. Resource policies may reference another account.
type PrincipalResolver interface {
	ResolvePrincipal(context.Context, string) (Principal, error)
}

// GrantPrincipalResolver resolves KMS grant identities, including assumed-role
// and federated-user sessions that have not yet been issued. Policy admission
// also validates these identities, but retains session ARNs rather than IDs.
type GrantPrincipalResolver interface {
	ResolveGrantPrincipal(context.Context, string) (Principal, error)
}

// ResolveGrantPrincipal delegates identity ownership to IAM.
func (e *Evaluator) ResolveGrantPrincipal(ctx context.Context, reference string) (Principal, error) {
	resolver, ok := e.identity.(GrantPrincipalResolver)
	if !ok {
		return Principal{}, fmt.Errorf("%w: no IAM grant principal resolver is configured", ErrInvalidPrincipal)
	}
	return resolver.ResolveGrantPrincipal(ctx, reference)
}

// FederatedPrincipalValidator checks that a trust-policy provider exists in the
// role's account and partition. Provider references remain ARN-based; issuance
// independently fences the exact provider incarnation and configuration.
type FederatedPrincipalValidator interface {
	ValidateFederatedPrincipal(context.Context, string) error
}

// BoundPolicy retains the original policy and its immutable IAM principals.
// Providers save the document and principal bindings atomically and pass the
// bound policy through Request.ResourcePolicies. Conditions, including
// aws:PrincipalArn, retain their string matching and are deliberately not bound.
type BoundPolicy struct {
	Document     string
	PrincipalIDs map[string]string
	TrustPolicy  bool
}

// ResourcePolicyOptions describes the principal kinds admitted by a service.
// Enabling a federated selector does not turn the document into a role trust
// policy or grant that selector the permissions of AWS-credential principals.
type ResourcePolicyOptions struct {
	AllowFederatedPrincipals bool
}

// PolicyBinder protects against granting a deleted user's permissions to a new
// user with the same name. Read APIs render current ARNs, or deleted IDs as AWS
// does, without changing the authorization binding.
type PolicyBinder interface {
	BindResourcePolicy(context.Context, string, ResourcePolicyOptions) (BoundPolicy, error)
	RenderResourcePolicy(context.Context, BoundPolicy) (string, error)
}

// BindResourcePolicy validates a policy and resolves its IAM principals before
// publication. Account-root delegation and service principals need no binding.
func (e *Evaluator) BindResourcePolicy(ctx context.Context, document string, options ResourcePolicyOptions) (BoundPolicy, error) {
	return e.bindPolicy(ctx, document, false, options)
}

// BindTrustPolicy binds role trust principals without adding Resource to the
// stored document. Role and user principals retain immutable IDs.
func (e *Evaluator) BindTrustPolicy(ctx context.Context, document string) (BoundPolicy, error) {
	return e.bindPolicy(ctx, document, true, ResourcePolicyOptions{})
}

// ValidateTrustPolicy validates the evaluable IAM role trust-policy language.
func ValidateTrustPolicy(data []byte) error {
	_, err := policy.TrustResourcePolicy(data)
	return err
}

func (e *Evaluator) bindPolicy(ctx context.Context, document string, trust bool, options ResourcePolicyOptions) (BoundPolicy, error) {
	resolver, _ := e.identity.(PrincipalResolver)
	return bindPolicy(ctx, document, trust, resolver, options)
}

// BindTrustPolicy permits IAM to bind a trust policy using its active resource
// transaction, avoiding a nested lock against the same identity repository.
func BindTrustPolicy(ctx context.Context, document string, resolver PrincipalResolver) (BoundPolicy, error) {
	return bindPolicy(ctx, document, true, resolver, ResourcePolicyOptions{})
}

func bindPolicy(ctx context.Context, document string, trust bool, resolver PrincipalResolver, options ResourcePolicyOptions) (BoundPolicy, error) {
	if err := ctx.Err(); err != nil {
		return BoundPolicy{}, err
	}
	data := []byte(document)
	if trust {
		var err error
		data, err = policy.TrustResourcePolicy(data)
		if err != nil {
			return BoundPolicy{}, err
		}
	}
	doc, err := policy.ParseResource(data)
	if err != nil {
		return BoundPolicy{}, err
	}
	for _, reference := range doc.FederatedPrincipals() {
		if !trust && options.AllowFederatedPrincipals {
			continue
		}
		validator, ok := resolver.(FederatedPrincipalValidator)
		if !trust || !ok {
			return BoundPolicy{}, fmt.Errorf("%w: federated principals require an IAM trust-policy provider validator", ErrInvalidPrincipal)
		}
		if err := validator.ValidateFederatedPrincipal(ctx, reference); err != nil {
			return BoundPolicy{}, fmt.Errorf("%w: %s", ErrInvalidPrincipal, reference)
		}
	}
	bound := BoundPolicy{Document: document, PrincipalIDs: make(map[string]string), TrustPolicy: trust}
	for _, reference := range doc.AWSPrincipals() {
		if !needsBinding(reference) {
			continue
		}
		if resolver == nil {
			return BoundPolicy{}, fmt.Errorf("%w: no IAM principal resolver is configured", ErrInvalidPrincipal)
		}
		resolve := resolver.ResolvePrincipal
		parts := strings.SplitN(reference, ":", 6)
		session := len(parts) == 6 && parts[2] == "sts"
		if session {
			sessions, ok := resolver.(GrantPrincipalResolver)
			if !ok {
				return BoundPolicy{}, fmt.Errorf("%w: no IAM session principal resolver is configured", ErrInvalidPrincipal)
			}
			resolve = sessions.ResolveGrantPrincipal
		}
		principal, err := resolve(ctx, reference)
		if err != nil || principal.ID == "" || principal.ARN == "" {
			return BoundPolicy{}, fmt.Errorf("%w: %s", ErrInvalidPrincipal, reference)
		}
		// Native named-session policies survive role recreation. IAM user/role
		// principals instead bind their immutable identity at publication.
		if !session {
			bound.PrincipalIDs[reference] = principal.ID
		}
	}
	return bound, nil
}

// RenderResourcePolicy presents current principal ARNs while retaining stale
// unique IDs after deletion. A recreated ARN has a different ID and cannot
// recover the old policy's grant.
func (e *Evaluator) RenderResourcePolicy(ctx context.Context, bound BoundPolicy) (string, error) {
	resolver, _ := e.identity.(PrincipalResolver)
	return RenderBoundPolicy(ctx, bound, resolver)
}

// RenderBoundPolicy renders a stored policy using the caller's active principal
// transaction. Providers normally use the PolicyBinder method instead.
func RenderBoundPolicy(ctx context.Context, bound BoundPolicy, resolver PrincipalResolver) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(bound.PrincipalIDs) == 0 {
		return bound.Document, nil
	}
	replacements := make(map[string]string, len(bound.PrincipalIDs))
	for original, id := range bound.PrincipalIDs {
		replacements[original] = id
		if resolver == nil {
			continue
		}
		principal, err := resolver.ResolvePrincipal(ctx, id)
		if err != nil {
			if errors.Is(err, ErrInvalidPrincipal) {
				continue
			}
			return "", err
		}
		if principal.ID != id || principal.ARN == "" {
			return "", fmt.Errorf("IAM principal resolver returned an inconsistent binding")
		}
		replacements[original] = principal.ARN
	}
	var data []byte
	var err error
	if bound.TrustPolicy {
		data, err = policy.RewriteTrustPrincipals([]byte(bound.Document), replacements)
	} else {
		data, err = policy.RewriteResourcePrincipals([]byte(bound.Document), replacements)
	}
	return string(data), err
}

func needsBinding(reference string) bool {
	return strings.HasPrefix(reference, "AIDA") || strings.HasPrefix(reference, "AROA") ||
		(strings.HasPrefix(reference, "arn:") && !strings.HasSuffix(reference, ":root"))
}
