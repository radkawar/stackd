package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)

type principalPattern struct {
	kind  string
	value string
}

// AnonymousAccountID is the AWS request-context account value for unsigned
// access to resources whose service supports anonymous callers.
const AnonymousAccountID = "anonymous"

// Principal identifies the caller established by the transport. AccountID may
// be AnonymousAccountID for anonymous access. Service identifies an AWS service
// principal for internal calls; public requests must not manufacture this value.
type Principal struct {
	ARN         string
	AccountID   string
	Partition   string
	ID          string
	IssuerARN   string
	IssuerID    string
	Federated   string
	Service     string
	HasBoundary bool
	// ServiceAliases are verified equivalent identities, matched together with
	// Service in one decision, including Principal and NotPrincipal denials.
	ServiceAliases []string
}

// ResourceDecision distinguishes direct resource grants from account-level
// delegation, which still requires permission from the caller's identity.
type ResourceDecision struct {
	Decision      Decision
	Direct        bool
	Delegated     bool
	SessionDirect bool
}

// ParseResource compiles resource and KMS key policies. Unlike Parse, each
// statement must select Principal or NotPrincipal. Identity-only evaluation
// rejects the resulting document to prevent bypassing its principal selection.
func ParseResource(data []byte) (*Document, error) { return parseDocument(data, resourceDocument) }

func parsePrincipals(obj map[string]json.RawMessage) ([]principalPattern, bool, error) {
	raw, positive := obj["Principal"]
	negativeRaw, negative := obj["NotPrincipal"]
	if positive == negative {
		return nil, false, fmt.Errorf("%w: exactly one of Principal and NotPrincipal is required", ErrInvalidPolicy)
	}
	if negative {
		raw = negativeRaw
		if effect, _ := stringValue(obj["Effect"]); effect != "Deny" {
			return nil, false, fmt.Errorf("%w: NotPrincipal is supported only with Deny", ErrInvalidPolicy)
		}
	}
	if text, err := stringValue(raw); err == nil {
		if text != "*" {
			return nil, false, fmt.Errorf("%w: a scalar Principal must be *", ErrInvalidPolicy)
		}
		return []principalPattern{{kind: "AWS", value: "*"}}, negative, nil
	}
	principals, err := object(raw)
	if err != nil || len(principals) == 0 {
		return nil, false, fmt.Errorf("%w: Principal must be * or a nonempty principal object", ErrInvalidPolicy)
	}
	var result []principalPattern
	for _, kind := range sortedKeys(principals) {
		if kind != "AWS" && kind != "Service" && kind != "Federated" {
			// TODO: Comeback support canonical-user resource principals when their service consumers are implemented.
			return nil, false, fmt.Errorf("%w: principal kind %s", ErrUnsupported, kind)
		}
		values, err := scalarOrArray(principals[kind])
		if err != nil || len(values) == 0 {
			return nil, false, fmt.Errorf("%w: Principal values must not be empty", ErrInvalidPolicy)
		}
		for _, raw := range values {
			text, err := stringValue(raw)
			if err != nil || (kind != "Federated" && !validPrincipalPattern(kind, text)) {
				return nil, false, fmt.Errorf("%w: invalid %s principal", ErrInvalidPolicy, kind)
			}
			result = append(result, principalPattern{kind: kind, value: text})
		}
	}
	return result, negative, nil
}

func validPrincipalPattern(kind, text string) bool {
	if text == "" || strings.ContainsAny(text, " \t\r\n${}") {
		return false
	}
	if kind == "Federated" {
		switch text {
		case "accounts.google.com", "cognito-identity.amazonaws.com", "www.amazon.com", "graph.facebook.com":
			return true
		}
		parts := strings.SplitN(text, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "iam" || parts[3] != "" || !accountPattern.MatchString(parts[4]) || strings.ContainsAny(text, "*?") {
			return false
		}
		for _, prefix := range []string{"oidc-provider/", "saml-provider/"} {
			if strings.HasPrefix(parts[5], prefix) && len(parts[5]) > len(prefix) {
				return true
			}
		}
		return false
	}
	if kind == "Service" {
		return !strings.ContainsAny(text, "*?:/") && strings.Contains(text, ".")
	}
	if text == "*" || accountPattern.MatchString(text) {
		return true
	}
	if strings.ContainsAny(text, "*?") {
		return false
	}
	// AWS preserves unique IDs when an ARN principal is deleted. Such stale
	// principals remain valid policy values, but do not match a recreated ARN.
	if (strings.HasPrefix(text, "AIDA") || strings.HasPrefix(text, "AROA")) && !strings.Contains(text, ":") {
		return true
	}
	parts := strings.SplitN(text, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[3] != "" || !accountPattern.MatchString(parts[4]) {
		return false
	}
	return (parts[2] == "iam" && (parts[5] == "root" || strings.HasPrefix(parts[5], "user/") || strings.HasPrefix(parts[5], "role/"))) ||
		(parts[2] == "sts" && (strings.HasPrefix(parts[5], "assumed-role/") || strings.HasPrefix(parts[5], "federated-user/")))
}

// EvaluateResource evaluates action, resource, principal and conditions. It
// includes the IAM NotPrincipal/Deny rule for principals with a boundary.
func EvaluateResource(doc *Document, request Request, principal Principal) (ResourceDecision, error) {
	if doc == nil || !doc.resourcePolicy {
		return ResourceDecision{Decision: ImplicitDeny}, fmt.Errorf("%w: resource evaluation requires a resource policy document", ErrInvalidPolicy)
	}
	context, err := requestContext(request)
	if err != nil {
		return ResourceDecision{Decision: ImplicitDeny}, err
	}
	return evaluateResource(doc, request, context, principal, nil, false)
}

func evaluateResource(doc *Document, request Request, context evaluationContext, principal Principal, trace *evaluationTrace, simulation bool) (ResourceDecision, error) {
	result := ResourceDecision{Decision: ImplicitDeny}
	if doc == nil || !doc.resourcePolicy {
		return result, fmt.Errorf("%w: resource evaluation requires a resource policy document", ErrInvalidPolicy)
	}
	for statementIndex, st := range doc.statements {
		entry := trace.begin(0, statementIndex, st)
		if !matchesActionResource(st, request, context, entry) {
			continue
		}
		direct, delegated, sessionDirect := matchPrincipals(st.principals, principal)
		principalMatches := direct || delegated
		if st.notPrincipal {
			principalMatches = !principalMatches || (st.effect == ExplicitDeny && principal.HasBoundary)
		}
		if entry != nil {
			entry.PrincipalBinding = PrincipalBinding{Direct: direct, Delegated: delegated, SessionDirect: sessionDirect}
			entry.NotPrincipal = st.notPrincipal
			entry.BoundaryDeny = st.notPrincipal && st.effect == ExplicitDeny && principal.HasBoundary
		}
		entry.outcome(PrincipalMismatch)
		if !principalMatches {
			continue
		}
		if !matchesRequestConditions(st, context, simulation, entry) {
			continue
		}
		entry.outcome(StatementMatched)
		trace.match(0, statementIndex, st)
		if st.effect == ExplicitDeny {
			if trace == nil {
				return ResourceDecision{Decision: ExplicitDeny}, nil
			}
			result = ResourceDecision{Decision: ExplicitDeny}
			continue
		}
		if result.Decision == ExplicitDeny {
			continue
		}
		result.Decision = Allow
		result.Direct = result.Direct || direct
		result.Delegated = result.Delegated || delegated
		result.SessionDirect = result.SessionDirect || sessionDirect
	}
	if result.Decision == ExplicitDeny {
		return result, nil
	}
	return result, nil
}

func matchPrincipals(patterns []principalPattern, principal Principal) (direct, delegated, sessionDirect bool) {
	for _, pattern := range patterns {
		if pattern.kind == "Service" {
			direct = direct || (principal.Service != "" && (pattern.value == principal.Service || slices.Contains(principal.ServiceAliases, pattern.value)))
			continue
		}
		if pattern.kind == "Federated" {
			direct = direct || (principal.Federated != "" && pattern.value == principal.Federated)
			continue
		}
		if principal.Federated != "" {
			continue
		}
		if pattern.value == "*" {
			direct = true
			sessionDirect = sessionDirect || principal.IssuerARN != ""
			continue
		}
		if pattern.value == principal.AccountID || pattern.value == "arn:"+principal.Partition+":iam::"+principal.AccountID+":root" {
			delegated = true
			continue
		}
		callerMatch := (principal.ARN != "" && pattern.value == principal.ARN) || (principal.ID != "" && pattern.value == principal.ID)
		issuerMatch := (principal.IssuerARN != "" && pattern.value == principal.IssuerARN) || (principal.IssuerID != "" && pattern.value == principal.IssuerID)
		direct = direct || callerMatch || issuerMatch
		sessionDirect = sessionDirect || (callerMatch && principal.IssuerARN != "")
	}
	return direct, delegated, sessionDirect
}
