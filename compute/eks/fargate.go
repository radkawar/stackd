package eks

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

type FargateSelector struct {
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
}
type FargateSpecification struct {
	ClusterID, ID, Name, RoleARN, RoleID string
	Selectors                            []FargateSelector
	Delete, AdmissionDenied              bool
	RegistryAuthorization                func(context.Context, []string) ([]RegistryAuthorization, error)
}
type FargateRuntime interface {
	ReconcileFargate(context.Context, FargateSpecification) error
}

var fargateNamespacePattern = regexp.MustCompile(`^[a-z0-9*?]([a-z0-9*?-]*[a-z0-9*?])?$`)
var fargateLabelPattern = regexp.MustCompile(`^[A-Za-z0-9*?]([A-Za-z0-9*?_.-]*[A-Za-z0-9*?])?$`)
var fargateLabelPrefixPattern = regexp.MustCompile(`^[a-z0-9*?]([a-z0-9*?.-]*[a-z0-9*?])?$`)

func ValidateFargateSelector(s FargateSelector) error {
	if len(s.Namespace) > 63 || !fargateNamespacePattern.MatchString(s.Namespace) {
		return errors.New("invalid Fargate namespace selector")
	}
	for k, v := range s.Labels {
		prefix, name, hasPrefix := strings.Cut(k, "/")
		if !hasPrefix {
			name = prefix
		}
		if len(name) > 63 || !fargateLabelPattern.MatchString(name) || hasPrefix && (len(prefix) > 253 || !fargateLabelPrefixPattern.MatchString(prefix)) || len(v) > 63 || v != "" && !fargateLabelPattern.MatchString(v) {
			return errors.New("invalid Fargate label selector")
		}
	}
	return nil
}

// wildcardMatch implements only the documented '*' and '?' syntax. In particular,
// brackets and slashes have no path/glob semantics for Kubernetes label keys.
func wildcardMatch(pattern, value string) bool {
	p, v := 0, 0
	star, mark := -1, 0
	for v < len(value) {
		if p < len(pattern) && pattern[p] == '*' {
			star = p
			p++
			mark = v
			continue
		}
		if p < len(pattern) {
			pr, ps := utf8.DecodeRuneInString(pattern[p:])
			vr, vs := utf8.DecodeRuneInString(value[v:])
			if pr == '?' || pr == vr {
				p += ps
				v += vs
				continue
			}
		}
		if star < 0 {
			return false
		}
		_, size := utf8.DecodeRuneInString(value[mark:])
		mark += size
		v = mark
		p = star + 1
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
func MatchFargateSelector(s FargateSelector, namespace string, labels map[string]string) bool {
	if !wildcardMatch(s.Namespace, namespace) {
		return false
	}
	for key, value := range s.Labels {
		found := false
		for actualKey, actualValue := range labels {
			if wildcardMatch(key, actualKey) && wildcardMatch(value, actualValue) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
