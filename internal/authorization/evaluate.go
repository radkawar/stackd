package authorization

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"stackd/iam/policy"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
	"stackd/internal/identity"
)

// ValidateResourcePolicy rejects malformed or unsupported policies under the
// default service principal admission. Services admitting federated selectors
// use BindResourcePolicy with explicit ResourcePolicyOptions instead. Validation
// is separate from authorization, service-specific limits and lockout checks.
func ValidateResourcePolicy(data []byte) error {
	doc, err := policy.ParseResource(data)
	if err == nil && len(doc.FederatedPrincipals()) != 0 {
		return fmt.Errorf("%w: federated principals require a role trust policy", policy.ErrInvalidPolicy)
	}
	return err
}

// Authorize returns nil only when every applicable policy layer permits the
// operation. Unsupported policy expressions fail closed with an explicit error.
func (e *Evaluator) Authorize(ctx context.Context, request Request) *awswire.Error {
	if err := ctx.Err(); err != nil {
		return denied("Authorization canceled: " + err.Error())
	}
	m := awsctx.FromContext(ctx)
	if m.SessionType == string(identity.SessionTypeEC2InstanceIdentity) {
		if strings.EqualFold(request.Action, "sts:GetCallerIdentity") {
			return authorizeNetworkEndpoint(ctx, request, policy.Principal{})
		}
		// Instance identity roles are not subject to identity/resource policy
		// grants. Never resolve them as attached-profile IAM role sessions.
		return denied("EC2 instance identity credentials cannot authorize this operation.")
	}
	kind, err := principalKind(m)
	if err != nil {
		return denied(err.Error())
	}
	if kind != "Anonymous" && strings.EqualFold(request.Action, "sts:GetCallerIdentity") {
		return authorizeNetworkEndpoint(ctx, request, policy.Principal{})
	}
	set := PolicySet{}
	if kind != "Account" && kind != "Service" && kind != "Anonymous" {
		if e.identity == nil {
			return denied("No IAM policy source is configured for this principal.")
		}
		set, err = e.identity.IdentityPolicies(ctx)
		if err != nil {
			return denied("Unable to resolve IAM principal policies: " + err.Error())
		}
	}
	var now time.Time
	if request.EvaluationTime != nil {
		now = *request.EvaluationTime
	} else {
		now = e.clock.Now()
	}
	context, owner, err := evaluationContext(m, kind, set.PrincipalTags, request, now)
	if err != nil {
		return denied("Invalid authorization request: " + err.Error())
	}
	organizationSubject := "principal"
	if kind == "Service" {
		organizationSubject = "source"
	}
	if err := e.organizationContext(ctx, context, organizationSubject); err != nil {
		return denied("Unable to resolve principal organization: " + err.Error())
	}
	resourceControls, err := e.resourceControlContext(ctx, owner, context)
	if err != nil {
		return denied("Unable to resolve resource controls: " + err.Error())
	}
	if guard := networkEndpointGuard(ctx); guard != nil {
		values, rejected := guard.Context(ctx, request)
		if rejected != nil {
			return rejected
		}
		// The tunnel's infrastructure peer is not the customer's public source
		// IP. Endpoint requests instead carry EC2's authoritative VpcSourceIp.
		delete(context, "aws:sourceip")
		for key, values := range values {
			context[strings.ToLower(key)] = values
		}
	}
	contextTypes := catalog.ContextTypes(context)
	for key, kind := range request.ContextTypes {
		contextTypes[strings.ToLower(key)] = kind
	}
	req := policy.Request{Action: request.Action, ActionAliases: request.PolicyActionAliases, AdditionalDenyActions: request.AdditionalDenyActions, Resource: request.ResourceARN, Context: context, ContextTypes: contextTypes}
	snapshot := policy.Authorization{
		Principal: policy.Principal{ARN: m.PrincipalARN, AccountID: m.AccountID, Partition: m.Partition, ID: m.PrincipalID, IssuerARN: m.IssuerARN, IssuerID: m.IssuerID, HasBoundary: set.HasBoundary},
		Identity:  set.Identity, Boundary: set.Boundary, HasSessionPolicy: m.HasSessionPolicy,
		RootSession: m.SessionType == "AssumeRoot", ServiceLinkedRole: set.ServiceLinkedRole,
		ResourceAccountID: owner, RequireResourcePolicy: request.RequireResourcePolicy,
		ResourceAccountGrant:   request.ResourceAccountGrant,
		ResourcePublicGrant:    request.ResourcePublicGrant,
		ResourcePolicyDenyOnly: request.ResourcePolicyDenyOnly,
		ResourceControlExempt:  request.ResourceControlExempt,
		Grants:                 request.Grants,
	}
	if kind == "Service" {
		snapshot.Principal = policy.Principal{Service: m.ServicePrincipal.Name, ServiceAliases: m.ServicePrincipal.Aliases, Partition: m.Partition}
	}
	for i, document := range m.SessionPolicies {
		source := fmt.Sprintf("%s#session-policy-%d", m.PrincipalARN, i+1)
		if m.SessionType == "AssumeRoot" && i < len(m.SessionPolicyARNs) {
			source = m.SessionPolicyARNs[i]
		}
		snapshot.Session = append(snapshot.Session, policy.Policy{Source: source, Document: document})
	}
	snapshot.Session = append(snapshot.Session, set.ManagedSession...)
	if kind != "Service" && kind != "Anonymous" && !set.ServiceLinkedRole && e.controls != nil {
		snapshot.ServiceControls, err = e.controls.ServiceControlPolicies(ctx)
		if err != nil {
			return denied("Unable to resolve service control policies: " + err.Error())
		}
	}
	if catalog.AppliesResourceControlPolicy(request.Action) {
		snapshot.ResourceControls = resourceControls.Levels
	}
	for i, bound := range request.ResourcePolicies {
		if bound.TrustPolicy {
			snapshot.RequireResourcePolicy = true
		}
		if bound.Document == "" {
			continue
		}
		data := []byte(bound.Document)
		if bound.TrustPolicy {
			data, err = policy.TrustResourcePolicy(data)
			if err != nil {
				return evaluationFailure(err)
			}
		}
		if len(bound.PrincipalIDs) != 0 {
			data, err = policy.RewriteResourcePrincipals(data, bound.PrincipalIDs)
			if err != nil {
				return evaluationFailure(err)
			}
		}
		snapshot.Resource = append(snapshot.Resource, policy.Policy{
			Source: fmt.Sprintf("%s#resource-policy-%d", request.ResourceARN, i+1), Document: string(data),
		})
	}
	decision, err := policy.Authorize(req, snapshot)
	if err != nil {
		return evaluationFailure(err)
	}
	if request.ObserveDecision != nil {
		request.ObserveDecision(decision)
	}
	if decision.Decision != policy.Allow {
		principal := m.PrincipalARN
		if kind == "Service" {
			principal = m.ServicePrincipal.Name
		}
		if principal != "" {
			return denied(fmt.Sprintf("User: %s is not authorized to perform: %s on resource: %s. %s", principal, request.Action, request.ResourceARN, decision.Reason))
		}
		return denied(decision.Reason)
	}
	request.Context, request.ContextTypes = context, contextTypes
	return authorizeNetworkEndpoint(ctx, request, snapshot.Principal)
}

func (e *Evaluator) organizationContext(ctx context.Context, values map[string][]string, subject string) error {
	var id, path string
	metadata := awsctx.FromContext(ctx)
	// A role-owning account is not an originating service resource. Native
	// source-less assumptions omit source organization keys even in an org.
	if source, ok := e.controls.(OrganizationSource); ok && metadata.AccountID != policy.AnonymousAccountID && (subject != "source" || metadata.ServicePrincipal.SourceARN != "") {
		var err error
		id, path, err = source.PrincipalOrganization(ctx)
		if err != nil {
			return err
		}
	}
	for key, value := range map[string]string{"aws:" + subject + "orgid": id, "aws:" + subject + "orgpaths": path} {
		if supplied, exists := values[key]; exists && (value == "" || !slices.Equal(supplied, []string{value})) {
			return fmt.Errorf("service context cannot override verified %s", key)
		}
		if value != "" {
			values[key] = []string{value}
		}
	}
	return nil
}

func evaluationFailure(err error) *awswire.Error {
	return denied("Policy evaluation failed: " + err.Error())
}

func principalKind(m awsctx.Metadata) (string, error) {
	if m.ServicePrincipal.Name != "" {
		if m.ServicePrincipal.Type == "" {
			return "", fmt.Errorf("a service principal requires its observed principal type")
		}
		// A service assumption need not carry source-resource condition keys.
		// When supplied, source ownership still follows the request scope.
		if m.ServicePrincipal.SourceARN != "" {
			source := strings.SplitN(m.ServicePrincipal.SourceARN, ":", 6)
			if len(source) != 6 || source[0] != "arn" || source[1] != m.Partition || (source[4] != "" && source[4] != m.AccountID) || source[2] == "" || source[5] == "" {
				return "", fmt.Errorf("a service source resource must belong to the request account and partition")
			}
		}
		return "Service", nil
	}
	if m.AccountID == policy.AnonymousAccountID {
		return "Anonymous", nil
	}
	parts := strings.SplitN(m.PrincipalARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != m.Partition || parts[4] != m.AccountID || parts[3] != "" || m.AccountID == "" || m.Partition == "" {
		return "", fmt.Errorf("a verified principal in the request account and partition is required")
	}
	if parts[2] == "sts" {
		issuer := strings.SplitN(m.IssuerARN, ":", 6)
		if len(issuer) != 6 || issuer[1] != m.Partition || issuer[2] != "iam" || issuer[3] != "" || issuer[4] != m.AccountID || m.IssuerID == "" {
			return "", fmt.Errorf("a verified session issuer in the request account is required")
		}
		if strings.HasPrefix(parts[5], "assumed-role/") && strings.HasPrefix(issuer[5], "role/") {
			return "AssumedRole", nil
		}
		if strings.HasPrefix(parts[5], "federated-user/") && (strings.HasPrefix(issuer[5], "user/") || issuer[5] == "root") {
			return "FederatedUser", nil
		}
		return "", fmt.Errorf("session principal and issuer types do not agree")
	}
	if parts[2] != "iam" {
		return "", fmt.Errorf("unsupported principal service")
	}
	switch {
	case parts[5] == "root":
		return "Account", nil
	case strings.HasPrefix(parts[5], "user/") && len(parts[5]) > len("user/"):
		return "User", nil
	case strings.HasPrefix(parts[5], "role/") && len(parts[5]) > len("role/"):
		return "Role", nil
	default:
		return "", fmt.Errorf("unsupported IAM principal kind")
	}
}
