package s3

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
)

func publicPolicyTrustedCondition(conditions map[string]map[string]json.RawMessage, accessPoint bool) bool {
	for operator, keys := range conditions {
		base := strings.TrimPrefix(strings.TrimPrefix(operator, "ForAllValues:"), "ForAnyValue:")
		base = strings.TrimSuffix(base, "IfExists")
		for key, raw := range keys {
			// Universal quantification and IfExists admit a missing key. They
			// become trust restrictions only when Null:false requires presence.
			if (strings.HasPrefix(operator, "ForAllValues:") || strings.HasSuffix(operator, "IfExists")) && !publicPolicyRequiresPresence(conditions, key) {
				continue
			}
			if publicPolicyTrustValues(base, key, policyStrings(raw), accessPoint) {
				return true
			}
		}
	}
	return false
}

func publicPolicyRequiresPresence(conditions map[string]map[string]json.RawMessage, key string) bool {
	for candidate, raw := range conditions["Null"] {
		if !strings.EqualFold(candidate, key) {
			continue
		}
		var boolean bool
		if json.Unmarshal(raw, &boolean) == nil {
			return !boolean
		}
		values := policyStrings(raw)
		if len(values) == 0 {
			return false
		}
		for _, value := range values {
			if !strings.EqualFold(value, "false") {
				return false
			}
		}
		return true
	}
	return false
}

func publicPolicyTrustValues(operator, key string, values []string, accessPoint bool) bool {
	key = strings.ToLower(key)
	if accessPoint && key == "s3:dataaccesspointarn" {
		return false
	}
	if operator == "IpAddress" && key == "aws:sourceip" {
		for _, value := range values {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, addressErr := netip.ParseAddr(value)
				if addressErr != nil {
					return false
				}
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			// Prefix width is the restriction, not the address's private or
			// public designation. In particular fc00::/7 remains public.
			minimum := 32
			if prefix.Addr().Is4() {
				minimum = 8
			}
			if prefix.Bits() < minimum {
				return false
			}
		}
		return true
	}
	if operator != "StringEquals" && operator != "StringLike" && operator != "ArnEquals" && operator != "ArnLike" {
		return false
	}
	switch key {
	case "aws:sourceaccount", "aws:principalaccount", "aws:sourceorgid", "aws:principalorgid", "aws:sourcevpc", "aws:sourcevpce", "aws:userid", "aws:sourcearn", "aws:principalarn", "s3:dataaccesspointarn", "s3:dataaccesspointaccount":
	default:
		// SourceOwner is deliberately absent: unlike SourceAccount, native
		// classification does not recognize it as a public trust anchor.
		return false
	}
	for _, value := range values {
		if strings.Contains(value, "${") {
			return false
		}
		// StringEquals treats * and ? literally; ARN equality, like ARN
		// matching, interprets wildcards. Empty value sets grant nobody.
		if operator == "StringEquals" || !strings.ContainsAny(value, "*?") {
			continue
		}
		switch key {
		case "aws:sourcearn", "aws:principalarn", "s3:dataaccesspointarn":
			parts := strings.SplitN(value, ":", 6)
			if len(parts) != 6 || parts[0] != "arn" || !publicPolicyFixedAccount(parts[4]) {
				return false
			}
		case "aws:userid":
			id, _, found := strings.Cut(value, ":")
			if !found || id == "" || strings.ContainsAny(id, "*?") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func publicPolicyFixedAccount(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func publicPolicyDenyRestricts(deny, allow map[string]map[string]json.RawMessage, accessPoint bool) bool {
	if len(deny) == 0 {
		return true
	}
	// A denial whose predicates are already required by this Allow cancels
	// that Allow's selected resources. Compare parsed values, not JSON layout.
	implied := true
	for operator, keys := range deny {
		for key, raw := range keys {
			matched := false
			for candidate, allowed := range allow[operator] {
				if strings.EqualFold(candidate, key) {
					var left, right any
					if json.Unmarshal(raw, &left) == nil && json.Unmarshal(allowed, &right) == nil && reflect.DeepEqual(left, right) {
						matched = true
					}
				}
			}
			implied = implied && matched
		}
	}
	if implied {
		return true
	}
	// Denying everything outside one trusted set leaves no public grant in
	// that action/resource scope. Multiple predicates are a conjunction, so
	// their complement cannot be inferred from a single trusted predicate.
	// TODO: Comeback complete compound conditional-denial trust inference beyond the measured native public-policy matrix.
	if len(deny) != 1 {
		return false
	}
	for operator, keys := range deny {
		if len(keys) != 1 {
			return false
		}
		var positive string
		switch operator {
		case "StringNotEquals", "StringNotEqualsIfExists":
			positive = "StringEquals"
		case "StringNotLike", "StringNotLikeIfExists":
			positive = "StringLike"
		case "ArnNotEquals", "ArnNotEqualsIfExists":
			positive = "ArnEquals"
		case "ArnNotLike", "ArnNotLikeIfExists":
			positive = "ArnLike"
		case "NotIpAddress", "NotIpAddressIfExists":
			positive = "IpAddress"
		default:
			return false
		}
		for key, raw := range keys {
			return publicPolicyTrustValues(positive, key, policyStrings(raw), accessPoint)
		}
	}
	return false
}
