package eks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

var impersonationNamespace = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var impersonationServiceAccount = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// Impersonation mirrors the pinned Kubernetes 1.33 filter's resource attributes.
// The original caller's current EKS grants can authorize delegation, as captured
// in impersonation_native.json. Only the target loses EKS policy authority.
type impersonationAttribute struct {
	Namespace   string `json:"namespace,omitempty"`
	Verb        string `json:"verb"`
	Group       string `json:"group,omitempty"`
	Version     string `json:"version"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name"`
}

func (c *nativeCluster) impersonatedIdentity(ctx context.Context, headers http.Header, caller Identity) (Identity, bool, error) {
	target, attributes, err := requestedImpersonation(headers)
	if err != nil || len(attributes) == 0 {
		return target, false, err
	}
	groups, err := c.policyGroups(ctx, caller)
	if err != nil {
		return Identity{}, true, err
	}
	caller.Groups = append(caller.Groups, groups...)
	for _, attribute := range attributes {
		allowed, err := c.allowImpersonation(ctx, caller, attribute)
		if err != nil {
			return Identity{}, true, err
		}
		if !allowed {
			return Identity{}, true, fmt.Errorf("user %q cannot impersonate %s %q", caller.Username, attribute.Resource, attribute.Name)
		}
	}
	return target, true, nil
}

func requestedImpersonation(headers http.Header) (Identity, []impersonationAttribute, error) {
	var target Identity
	var attributes []impersonationAttribute
	for header, values := range headers {
		lower := strings.ToLower(header)
		switch {
		case lower == "impersonate-user":
			if len(values) != 1 || values[0] == "" {
				return target, nil, errors.New("invalid impersonated user")
			}
			target.Username = values[0]
		case lower == "impersonate-group":
			target.Groups = append(target.Groups, values...)
		case lower == "impersonate-uid":
			if len(values) != 1 {
				return target, nil, errors.New("invalid impersonated UID")
			}
			target.UID = values[0]
		case strings.HasPrefix(lower, "impersonate-extra-"):
			key := strings.TrimPrefix(lower, "impersonate-extra-")
			if decoded, err := url.PathUnescape(key); err == nil {
				key = decoded
			}
			if target.Extra == nil {
				target.Extra = make(map[string][]string)
			}
			target.Extra[key] = append(target.Extra[key], values...)
		}
	}
	if target.Username == "" {
		if len(target.Groups) != 0 || target.UID != "" || len(target.Extra) != 0 {
			return target, nil, errors.New("impersonation attributes require a user")
		}
		return target, nil, nil
	}
	if strings.HasPrefix(target.Username, "stackd:") {
		return target, nil, errors.New("reserved runtime identity")
	}
	user := impersonationAttribute{Verb: "impersonate", Version: "v1", Resource: "users", Name: target.Username}
	parts := strings.Split(target.Username, ":")
	serviceAccount := len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" && len(parts[2]) <= 63 && impersonationNamespace.MatchString(parts[2]) && len(parts[3]) <= 253 && impersonationServiceAccount.MatchString(parts[3])
	if serviceAccount {
		user.Resource, user.Namespace, user.Name = "serviceaccounts", parts[2], parts[3]
	}
	attributes = append(attributes, user)
	for _, group := range target.Groups {
		if strings.HasPrefix(group, "stackd:") {
			return target, nil, errors.New("reserved runtime group")
		}
		attributes = append(attributes, impersonationAttribute{Verb: "impersonate", Version: "v1", Resource: "groups", Name: group})
	}
	if target.UID != "" {
		attributes = append(attributes, impersonationAttribute{Verb: "impersonate", Group: "authentication.k8s.io", Version: "v1", Resource: "uids", Name: target.UID})
	}
	for key, values := range target.Extra {
		for _, value := range values {
			attributes = append(attributes, impersonationAttribute{Verb: "impersonate", Group: "authentication.k8s.io", Version: "v1", Resource: "userextras", Subresource: key, Name: value})
		}
	}
	if serviceAccount && len(target.Groups) == 0 {
		target.Groups = []string{"system:serviceaccounts", "system:serviceaccounts:" + parts[2]}
	}
	target.Groups = authenticationGroups(target.Username, target.Groups)
	return target, attributes, nil
}

func authenticationGroups(username string, groups []string) []string {
	if username == "system:anonymous" {
		if !slices.Contains(groups, "system:unauthenticated") {
			groups = append(groups, "system:unauthenticated")
		}
	} else if !slices.Contains(groups, "system:authenticated") && !slices.Contains(groups, "system:unauthenticated") {
		groups = append(groups, "system:authenticated")
	}
	return groups
}

func (c *nativeCluster) allowImpersonation(ctx context.Context, caller Identity, attribute impersonationAttribute) (bool, error) {
	review := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			User               string                 `json:"user"`
			UID                string                 `json:"uid,omitempty"`
			Groups             []string               `json:"groups"`
			Extra              map[string][]string    `json:"extra,omitempty"`
			ResourceAttributes impersonationAttribute `json:"resourceAttributes"`
		} `json:"spec"`
	}{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"}
	review.Spec.User, review.Spec.UID, review.Spec.Extra = caller.Username, caller.UID, caller.Extra
	review.Spec.Groups = authenticationGroups(caller.Username, slices.Clone(caller.Groups))
	review.Spec.ResourceAttributes = attribute
	data, err := json.Marshal(review)
	if err != nil {
		return false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.nativeURL()+"/apis/authorization.k8s.io/v1/subjectaccessreviews", bytes.NewReader(data))
	if err != nil {
		return false, err
	}
	request.Header.Set("Content-Type", "application/json")
	// The private client submits the review, but spec identifies only the
	// authenticated caller. It is never itself the subject of this decision.
	response, err := c.client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return false, fmt.Errorf("native impersonation review returned %d", response.StatusCode)
	}
	var result struct {
		Status struct {
			Allowed         bool   `json:"allowed"`
			Denied          bool   `json:"denied"`
			EvaluationError string `json:"evaluationError"`
		} `json:"status"`
	}
	if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Status.Allowed && !result.Status.Denied && result.Status.EvaluationError == "", nil
}

func sanitizeIdentityHeaders(headers http.Header) {
	for header := range headers {
		lower := strings.ToLower(header)
		if lower == "authorization" || lower == "proxy-authorization" || lower == "cookie" || lower == "x-amz-security-token" || lower == "x-client-cert" || lower == "forwarded" || strings.HasPrefix(lower, "impersonate-") || strings.HasPrefix(lower, "x-remote-") || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-auth-") || strings.HasPrefix(lower, "x-authenticated-") {
			delete(headers, header)
		}
	}
}

func setIdentityHeaders(headers http.Header, identity Identity) {
	headers.Set("Impersonate-User", identity.Username)
	for _, group := range authenticationGroups(identity.Username, identity.Groups) {
		headers.Add("Impersonate-Group", group)
	}
	if identity.UID != "" {
		headers.Set("Impersonate-Uid", identity.UID)
	}
	for key, values := range identity.Extra {
		// Extra keys use percent encoding, not query-specific plus encoding.
		encoded := strings.ReplaceAll(url.QueryEscape(key), "+", "%20")
		for _, value := range values {
			headers.Add("Impersonate-Extra-"+encoded, value)
		}
	}
}
