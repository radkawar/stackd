package policy

import (
	"fmt"
	"strings"
)

// Policy is an immutable document snapshot with its diagnostic source. Source is
// a managed policy ARN, an owning ARN followed by #inline-name, or an application
// supplied identifier. Version is the selected managed policy version, when one
// exists. Neither field influences permissions.
type Policy struct {
	Source   string
	Version  string
	Document string
}

// PolicyLevel contains the policies attached directly to an Organizations root,
// OU or account. Documents are unioned within a level and levels are intersected.
type PolicyLevel struct {
	TargetID  string
	Documents []Policy
}

// Authorization is a snapshot for one authenticated permission check. Callers
// own authentication, current identity and immutable principal bindings, trusted
// context, and selection of applicable policies. The evaluator performs no I/O,
// reads no clock and does not modify this snapshot. Keep it stable during a call.
//
// Principal.HasBoundary and HasSessionPolicy distinguish absent restrictions
// from present restrictions with no grants. RootSession identifies an AWS
// AssumeRoot task policy, whose explicit denials narrow root's inherent access.
// ServiceLinkedRole and ResourceControlExempt must come from trusted service
// state. Supply only RCP levels applicable to the action and resource owner.
type Authorization struct {
	Principal         Principal
	Identity          []Policy
	Boundary          []Policy
	Session           []Policy
	HasSessionPolicy  bool
	RootSession       bool
	ServiceLinkedRole bool
	ServiceControls   []PolicyLevel
	ResourceControls  []PolicyLevel
	Resource          []Policy
	// ResourceAccountID supplies the owner for an ARN with an omitted account or
	// the AWS-owned alias, or an operation selects *. Otherwise the ARN's account
	// is authoritative. Without an explicit owner, * uses the principal's account.
	ResourceAccountID string
	// ResourceAccountGrant is a service-owned grant to the caller's account,
	// such as Organizations membership or trusted-service administrator access.
	// Identity permissions and all restrictions, including resource-policy
	// explicit denials, still apply.
	ResourceAccountGrant bool
	// ResourcePublicGrant is an effective public ACL permission to the caller's
	// session. It cannot bypass explicit denials, Organizations controls or the
	// identity permission required for signed cross-account access.
	ResourcePublicGrant bool
	// ResourcePolicyDenyOnly ignores resource-policy Allows while preserving
	// explicit Deny and independent service-owned account/public grants.
	ResourcePolicyDenyOnly bool
	RequireResourcePolicy  bool
	ResourceControlExempt  bool
	Grants                 GrantPermissions
}

// GrantPermissions are KMS-validated principal, operation and constraint
// matches. Direct grants name an identity; Delegated grants name its account.
// SessionDirect grants name the caller's exact STS session and are not limited
// by implicit boundary/session denials. TrustedDirect and TrustedSessionDirect
// record the respective matches in grants issued by the caller's account;
// cross-account authorization cannot combine unrelated trust and bindings.
// Explicit denials and Organizations controls always apply.
type GrantPermissions struct {
	Direct, Delegated, SessionDirect    bool
	TrustedDirect, TrustedSessionDirect bool
}

// Layer identifies the authority responsible for a policy decision.
type Layer string

const (
	IdentityLayer        Layer = "identity"
	BoundaryLayer        Layer = "boundary"
	SessionLayer         Layer = "session"
	ServiceControlLayer  Layer = "serviceControl"
	ResourceControlLayer Layer = "resourceControl"
	ResourceLayer        Layer = "resource"
)

// AuthorizationResult is the decision and the evaluated policy prefix leading
// to it. Evaluation stops at a denying layer or error; absent layers were not
// evaluated. An error always denies access, regardless of any partial trace.
// Reason explains composition, including implicit restrictions bypassed by a
// direct resource grant. Traces contain key names, never request context values,
// credentials or policy document bodies. Returned slices belong to the caller.
type AuthorizationResult struct {
	Decision Decision
	Reason   string
	Layers   []LayerEvaluation
	// ServiceGrantRequired is true only when Allow depends on
	// ResourceAccountGrant or ResourcePublicGrant. Independent identity,
	// resource-policy and KMS grants remain in the counterfactual decision.
	ServiceGrantRequired bool
}

// LayerEvaluation retains each policy's source and the containing hierarchy
// target. Decision can differ from the policy union for root's inherent access
// and the deny-only AssumeRoot task ceiling; Reason identifies those cases.
type LayerEvaluation struct {
	Layer    Layer
	TargetID string
	Decision Decision
	Reason   string
	Policies []PolicyEvaluation
}

// PolicyEvaluation describes a single policy, in input order. Statements retain
// their original order and locations, including why a statement did not match.
// Failed records a parse failure or a reached malformed ARN operand. Other
// statements can still grant access; Decision is the policy result.
type PolicyEvaluation struct {
	Source     string
	Version    string
	Decision   Decision
	Failed     bool
	Statements []StatementEvaluation
}

// Authorize composes identity, boundary, session, resource and Organizations
// policies for a single request. It shares matchers with Evaluate and resource
// evaluation, while deliberately retaining enforcement's distinct contract from
// the AWS simulation API. A nil error alone does not grant access: Decision must
// also be Allow. The caller must authenticate Principal and supply trusted
// Context and current applicable policies before invoking this function.
func Authorize(request Request, snapshot Authorization) (AuthorizationResult, error) {
	result := AuthorizationResult{Decision: ImplicitDeny}
	context, err := requestContext(request)
	if err != nil {
		return result, err
	}
	if strings.EqualFold(request.Action, "sts:GetCallerIdentity") {
		if snapshot.Principal.AccountID == AnonymousAccountID {
			return result.finish(ImplicitDeny, "GetCallerIdentity requires authentication."), nil
		}
		return result.finish(Allow, "GetCallerIdentity requires authentication but no permission."), nil
	}
	p := snapshot.Principal
	root := p.ARN == "arn:"+p.Partition+":iam::"+p.AccountID+":root"
	identity, err := result.identityLayer(IdentityLayer, snapshot.Identity, request, context)
	if err != nil {
		return result, err
	}
	if root {
		identity = Allow
		result.Layers[len(result.Layers)-1].Decision = Allow
		result.Layers[len(result.Layers)-1].Reason = "Account root has inherent identity permissions."
	}
	if identity == ExplicitDeny {
		return result.finish(ExplicitDeny, "An identity policy explicitly denies this operation."), nil
	}
	boundary := Allow
	if p.HasBoundary {
		boundary, err = result.identityLayer(BoundaryLayer, snapshot.Boundary, request, context)
		if err != nil {
			return result, err
		}
		if boundary == ExplicitDeny {
			return result.finish(ExplicitDeny, "A permissions boundary explicitly denies this operation."), nil
		}
	}
	session := Allow
	if snapshot.HasSessionPolicy {
		session, err = result.identityLayer(SessionLayer, snapshot.Session, request, context)
		if err != nil {
			return result, err
		}
		if session == ExplicitDeny {
			return result.finish(ExplicitDeny, "A session policy explicitly denies this operation."), nil
		}
		if root && snapshot.RootSession {
			session = Allow
			result.Layers[len(result.Layers)-1].Decision = Allow
			result.Layers[len(result.Layers)-1].Reason = "An AssumeRoot task policy restricts root through explicit denials."
		}
	}
	if !snapshot.ServiceLinkedRole {
		controlRequest := request
		controlRequest.ActionAliases = nil
		if allowed, err := result.controls(ServiceControlLayer, snapshot.ServiceControls, controlRequest, context); err != nil || !allowed {
			return result, err
		}
		if !snapshot.ResourceControlExempt {
			if allowed, err := result.controls(ResourceControlLayer, snapshot.ResourceControls, controlRequest, context); err != nil || !allowed {
				return result, err
			}
		}
	}
	resource := ResourceDecision{Decision: ImplicitDeny}
	withoutServiceGrants := resource
	if len(snapshot.Resource) != 0 || snapshot.ResourceAccountGrant || snapshot.ResourcePublicGrant {
		layer := LayerEvaluation{Layer: ResourceLayer}
		for _, document := range snapshot.Resource {
			decision, policyErr := layer.resourcePolicy(document, request, context, p)
			if policyErr != nil || decision.Decision == ExplicitDeny {
				resource, err = decision, policyErr
				break
			}
			if snapshot.ResourcePolicyDenyOnly {
				continue
			}
			if decision.Decision == Allow {
				resource.Decision = Allow
			}
			resource.Direct = resource.Direct || decision.Direct
			resource.Delegated = resource.Delegated || decision.Delegated
			resource.SessionDirect = resource.SessionDirect || decision.SessionDirect
		}
		withoutServiceGrants = resource
		if err == nil && resource.Decision != ExplicitDeny && snapshot.ResourceAccountGrant {
			resource.Decision, resource.Delegated = Allow, true
			layer.Reason = "The service grants resource access to the caller's account."
		}
		if err == nil && resource.Decision != ExplicitDeny && snapshot.ResourcePublicGrant {
			resource.Decision, resource.Direct, resource.SessionDirect = Allow, true, true
			layer.Reason = "The service grants public resource access."
		}
		layer.Decision = resource.Decision
		result.Layers = append(result.Layers, layer)
		if err != nil {
			return result, err
		}
		if resource.Decision == ExplicitDeny {
			return result.finish(ExplicitDeny, "A resource policy explicitly denies this operation."), nil
		}
	}
	if snapshot.Grants != (GrantPermissions{}) {
		if !strings.HasPrefix(strings.ToLower(request.Action), "kms:") {
			return result, fmt.Errorf("%w: grant authorization is only supported for KMS actions", ErrInvalidRequest)
		}
	}
	identityAllows := identity == Allow && boundary == Allow && session == Allow
	crossAccount, assumeRootAllows := false, false
	grantIdentityAllows := boundary == Allow && session == Allow
	if p.Service == "" && p.AccountID != AnonymousAccountID {
		owner := p.AccountID
		if request.Resource != "*" {
			// requestContext has already validated the ARN shape. Numeric ownership
			// comes from that ARN, never a caller's optional override.
			owner = strings.SplitN(request.Resource, ":", 6)[4]
			if (owner == "" || owner == "aws") && snapshot.ResourceAccountID != "" {
				owner = snapshot.ResourceAccountID
			}
		} else if snapshot.ResourceAccountID != "" {
			owner = snapshot.ResourceAccountID
		}
		crossAccount = owner != "" && owner != p.AccountID && !awsManagedIAMResource(request, p.Partition)
		assumeRootAllows = crossAccount && identityAllows && strings.EqualFold(request.Action, "sts:AssumeRoot") && request.Resource == "arn:"+p.Partition+":iam::"+owner+":root"
		user := strings.HasPrefix(p.ARN, "arn:"+p.Partition+":iam::"+p.AccountID+":user/")
		grantIdentityAllows = user || root || grantIdentityAllows
	}
	trustedGrantAllows := snapshot.Grants.TrustedSessionDirect || (snapshot.Grants.TrustedDirect && grantIdentityAllows)
	// Compose already-evaluated permissions for both the actual decision and
	// the counterfactual without service grants. Policies, ownership and
	// identity restrictions are evaluated only once.
	compose := func(resource ResourceDecision) (Decision, string) {
		if snapshot.Grants != (GrantPermissions{}) {
			resource.Direct = resource.Direct || snapshot.Grants.Direct || snapshot.Grants.SessionDirect
			resource.Delegated = resource.Delegated || snapshot.Grants.Delegated
			resource.SessionDirect = resource.SessionDirect || snapshot.Grants.SessionDirect
			if resource.Direct || resource.Delegated {
				resource.Decision = Allow
			}
		}
		if p.Service != "" {
			if resource.Direct {
				return Allow, "The resource policy permits the AWS service; explicit denials and resource controls were checked."
			}
			return ImplicitDeny, "An AWS service principal requires a direct resource permission."
		}
		if p.AccountID == AnonymousAccountID {
			if resource.Direct {
				return Allow, "The resource policy permits anonymous access; explicit denials and resource controls were checked."
			}
			return ImplicitDeny, "Anonymous access requires a direct resource permission."
		}
		if crossAccount {
			if assumeRootAllows {
				return Allow, "Caller policies permit AssumeRoot; Organizations validates target eligibility."
			}
			if (identityAllows || trustedGrantAllows) && resource.Decision == Allow {
				return Allow, "Caller and resource permissions permit cross-account access."
			}
			return ImplicitDeny, "Cross-account access requires both identity and resource permissions."
		}
		if resource.Direct && (resource.SessionDirect || grantIdentityAllows) {
			return Allow, "A direct resource or KMS grant permits this operation; applicable explicit denials and controls were checked."
		}
		if identityAllows && (!snapshot.RequireResourcePolicy || resource.Delegated) {
			return Allow, "Identity permissions and applicable restrictions permit this operation."
		}
		return ImplicitDeny, "No applicable policy grants this operation."
	}
	result.Decision, result.Reason = compose(resource)
	if result.Decision == Allow && (snapshot.ResourceAccountGrant || snapshot.ResourcePublicGrant) {
		independent, _ := compose(withoutServiceGrants)
		result.ServiceGrantRequired = independent != Allow
	}
	return result, nil
}

func (r AuthorizationResult) finish(decision Decision, reason string) AuthorizationResult {
	r.Decision, r.Reason = decision, reason
	return r
}

// AWS-owned IAM policies and role templates have no customer resource policy.
func awsManagedIAMResource(request Request, partition string) bool {
	prefix := "arn:" + partition + ":iam::aws:"
	return (strings.HasPrefix(strings.ToLower(request.Action), "iam:") && strings.HasPrefix(request.Resource, prefix+"policy/")) ||
		(strings.EqualFold(request.Action, "iam:GetRoleTemplateVersion") && strings.HasPrefix(request.Resource, prefix+"role-template/"))
}
