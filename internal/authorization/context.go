package authorization

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awsctx"
)

func evaluationContext(m awsctx.Metadata, kind string, principalTags map[string]string, request Request, now time.Time) (map[string][]string, string, error) {
	now = now.UTC()
	context := make(map[string][]string, len(request.Context)+10)
	// IAM context names are case-insensitive, including service tag keys that
	// can coexist with distinct casing. Keep a single value, not a fabricated
	// multivalued tag. Sorted input gives replay a stable collision winner.
	// TODO: Comeback — native case-collision winners differ between Lambda's
	// resource and request tags; lexical-last is not an AWS precedence claim.
	for _, original := range slices.Sorted(maps.Keys(request.Context)) {
		key := strings.ToLower(original)
		if key == "" {
			return nil, "", fmt.Errorf("context key cannot be empty")
		}
		context[key] = slices.Clone(request.Context[original])
	}
	// Federation and service-issued claims come from retained session metadata.
	// A resource consumer may repeat a claim, but cannot invent or override one.
	sessionKeys := make(map[string]bool, len(m.SessionContext))
	for key, values := range m.SessionContext {
		canonical := strings.ToLower(key)
		if canonical == "" || (strings.HasPrefix(canonical, "aws:") && !ec2CredentialOriginKey(canonical)) || strings.HasPrefix(canonical, "sts:") || sessionKeys[canonical] {
			return nil, "", fmt.Errorf("invalid verified session context")
		}
		if supplied, exists := context[canonical]; exists && !slices.Equal(supplied, values) {
			return nil, "", fmt.Errorf("service context cannot override verified %s", canonical)
		}
		context[canonical] = slices.Clone(values)
		sessionKeys[canonical] = true
	}
	for key := range context {
		namespace, _, _ := strings.Cut(key, ":")
		if (namespace == "saml" || strings.ContainsAny(namespace, "./") || ec2CredentialOriginKey(key)) && !sessionKeys[key] {
			return nil, "", fmt.Errorf("unverified session context %s", key)
		}
	}
	owner := m.AccountID
	if request.ResourceARN != "*" {
		parts := strings.SplitN(request.ResourceARN, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] != m.Partition || parts[2] == "" || parts[5] == "" {
			return nil, "", fmt.Errorf("resource must be a complete ARN in the caller's partition or *")
		}
		owner = parts[4]
	}
	if resolved := request.ResourceAccountID; resolved != "" {
		if len(resolved) != 12 || strings.Trim(resolved, "0123456789") != "" {
			return nil, "", fmt.Errorf("resource owner must be a twelve-digit account ID")
		}
		if request.ResourceARN != "*" && owner != "" && owner != "aws" && owner != resolved {
			return nil, "", fmt.Errorf("resolved resource owner contradicts its ARN")
		}
		owner = resolved
	}
	trusted := map[string]string{
		"aws:principalisawsservice": "false",
		"aws:viaawsservice":         strconv.FormatBool(len(m.CalledVia) != 0),
		"aws:principalarn":          m.PrincipalARN,
		"aws:principalaccount":      m.AccountID,
		"aws:principaltype":         kind,
		"aws:userid":                m.PrincipalID,
		"aws:requestedregion":       m.Region,
	}
	if kind == "Service" {
		delete(trusted, "aws:principalarn")
		delete(trusted, "aws:principalaccount")
		delete(trusted, "aws:userid")
		trusted["aws:principalisawsservice"] = "true"
		trusted["aws:principaltype"] = m.ServicePrincipal.Type
		trusted["aws:principalservicename"] = m.ServicePrincipal.Name
		if m.ServicePrincipal.SourceARN != "" {
			trusted["aws:sourcearn"] = m.ServicePrincipal.SourceARN
			trusted["aws:sourceaccount"] = m.AccountID
		}
	}
	if kind == "Anonymous" {
		delete(trusted, "aws:principalarn")
		delete(trusted, "aws:principalisawsservice")
		trusted["aws:userid"] = m.AccountID
	}
	if len(m.CalledVia) != 0 {
		trusted["aws:calledviafirst"] = m.CalledVia[0]
		trusted["aws:calledvialast"] = m.CalledVia[len(m.CalledVia)-1]
	}
	if kind == "AssumedRole" {
		trusted["aws:principalarn"] = m.IssuerARN
	}
	if owner != "" && (request.ResourceARN != "*" || request.ResourceAccountID != "") {
		trusted["aws:resourceaccount"] = owner
	}
	if m.UserName != "" {
		if kind == "User" {
			trusted["aws:username"] = m.UserName
		}
	}
	// Session tags override role tags using case-insensitive IAM tag keys.
	mergedTags := MergePrincipalTags(principalTags, m.SessionTags)
	for key, value := range mergedTags {
		trusted["aws:principaltag/"+strings.ToLower(key)] = value
	}
	if m.SessionType != "" || m.MFAPresent {
		trusted["aws:multifactorauthpresent"] = strconv.FormatBool(m.MFAPresent)
	}
	if m.SessionType != "" || !m.TokenIssueTime.IsZero() {
		trusted["aws:tokenissuetime"] = m.TokenIssueTime.UTC().Format(time.RFC3339)
	}
	if m.SessionType == "AssumeRoot" {
		trusted["aws:assumedroot"] = "true"
	}
	if m.SourceIdentity != "" {
		trusted["aws:sourceidentity"] = m.SourceIdentity
	}
	if m.FederatedProvider != "" {
		trusted["aws:federatedprovider"] = m.FederatedProvider
	}
	if m.MFAPresent {
		trusted["aws:multifactorauthage"] = strconv.FormatInt(max(0, int64(now.Sub(m.MFAAuthenticatedAt)/time.Second)), 10)
	}
	if m.TransportKnown {
		if m.SourceIP != "" {
			trusted["aws:sourceip"] = m.SourceIP
		}
		trusted["aws:securetransport"] = strconv.FormatBool(m.SecureTransport)
		trusted["aws:useragent"] = m.UserAgent
	}
	for key, value := range trusted {
		if supplied, exists := context[key]; exists && !slices.Equal(supplied, []string{value}) {
			return nil, "", fmt.Errorf("service context cannot override verified %s", key)
		}
		context[key] = []string{value}
	}
	if supplied, exists := context["aws:calledvia"]; exists && (len(m.CalledVia) == 0 || !slices.Equal(supplied, m.CalledVia)) {
		return nil, "", fmt.Errorf("service context cannot override verified aws:calledvia")
	}
	if len(m.CalledVia) != 0 {
		context["aws:calledvia"] = slices.Clone(m.CalledVia)
	}
	var serviceNames []string
	if kind == "Service" {
		serviceNames = make([]string, 1, 1+len(m.ServicePrincipal.Aliases))
		serviceNames[0] = m.ServicePrincipal.Name
		serviceNames = append(serviceNames, m.ServicePrincipal.Aliases...)
	}
	if supplied, exists := context["aws:principalservicenameslist"]; exists && (len(serviceNames) == 0 || !slices.Equal(supplied, serviceNames)) {
		return nil, "", fmt.Errorf("service context cannot override verified aws:principalservicenameslist")
	}
	if len(serviceNames) != 0 {
		context["aws:principalservicenameslist"] = serviceNames
	}
	// Service consumers cannot create principal attributes that were absent
	// from the authenticated identity (for example arbitrary principal tags).
	for key := range context {
		switch key {
		case "aws:sourceip", "aws:securetransport", "aws:useragent", "aws:principalservicename", "aws:principalarn", "aws:principalaccount", "aws:principalisawsservice", "aws:userid":
			if _, exists := trusted[key]; !exists {
				return nil, "", fmt.Errorf("unverified transport context %s", key)
			}
		case "aws:calledviafirst", "aws:calledvialast", "aws:sourceidentity", "aws:tokenissuetime", "aws:multifactorauthpresent", "aws:multifactorauthage", "aws:assumedroot", "aws:federatedprovider":
			if _, exists := trusted[key]; !exists {
				return nil, "", fmt.Errorf("unverified session context %s", key)
			}
		}
		if key == "aws:username" || strings.HasPrefix(key, "aws:principaltag/") {
			if _, exists := trusted[key]; !exists {
				return nil, "", fmt.Errorf("unverified principal context %s", key)
			}
		}
	}
	context["aws:currenttime"] = []string{now.Format(time.RFC3339)}
	context["aws:epochtime"] = []string{strconv.FormatInt(now.Unix(), 10)}
	return context, owner, nil
}

func ec2CredentialOriginKey(key string) bool {
	switch key {
	case "ec2:sourceinstancearn", "aws:ec2instancesourcevpc", "aws:ec2instancesourceprivateipv4":
		return true
	default:
		return false
	}
}

// MergePrincipalTags applies authenticated session overrides using IAM's
// case-insensitive tag keys. The resulting key spelling comes from the winning
// tag, which matters when publishing these same attributes in outbound JWTs.
func MergePrincipalTags(principal, session map[string]string) map[string]string {
	names := make(map[string]string, len(principal)+len(session))
	result := make(map[string]string, len(principal)+len(session))
	for _, tags := range []map[string]string{principal, session} {
		for key, value := range tags {
			canonical := strings.ToLower(key)
			if previous, exists := names[canonical]; exists {
				delete(result, previous)
			}
			names[canonical] = key
			result[key] = value
		}
	}
	return result
}
