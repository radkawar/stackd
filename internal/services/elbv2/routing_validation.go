package elbv2

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/elbv2"
)

// Semantics follow the AWS ALB condition/action references:
// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/rule-condition-types.html
// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/rule-action-types.html
func validateConditions(conditions api.RuleConditionList) error {
	if len(conditions) == 0 {
		return invalid("a non-default rule requires a condition")
	}
	seen := make(map[string]bool)
	evaluations, wildcards := 0, 0
	for _, c := range conditions {
		if c.Field == nil {
			return invalid("condition field is required")
		}
		field := string(*c.Field)
		if field != "http-header" && field != "query-string" && seen[field] {
			return invalid("duplicate condition field " + field)
		}
		seen[field] = true
		configs := 0
		for _, present := range []bool{c.HostHeaderConfig != nil, c.PathPatternConfig != nil, c.HttpHeaderConfig != nil, c.HttpRequestMethodConfig != nil, c.QueryStringConfig != nil, c.SourceIpConfig != nil} {
			if present {
				configs++
			}
		}
		if configs > 1 || configs > 0 && (len(c.Values) > 0 || len(c.RegexValues) > 0) {
			return invalid("condition must use only its matching configuration or top-level values")
		}
		values, regexes := conditionPatterns(c)
		switch field {
		case "host-header":
			if configs > 0 && c.HostHeaderConfig == nil {
				return invalid("host-header requires HostHeaderConfig")
			}
		case "path-pattern":
			if configs > 0 && c.PathPatternConfig == nil {
				return invalid("path-pattern requires PathPatternConfig")
			}
		case "http-header":
			if c.HttpHeaderConfig == nil || c.HttpHeaderConfig.HttpHeaderName == nil {
				return invalid("http-header requires HttpHeaderName")
			}
			name := string(*c.HttpHeaderConfig.HttpHeaderName)
			if len(name) == 0 || len(name) > 40 {
				return invalid("HTTP header name must contain 1..40 characters")
			}
			if strings.EqualFold(name, "Host") {
				return invalid("Host requires a host-header condition, not an http-header condition")
			}
			for i := range name {
				if !isUnreserved(name[i]) && !strings.ContainsRune("!#$%&'+^`|", rune(name[i])) {
					return invalid("invalid HTTP header name")
				}
			}
		case "http-request-method":
			if c.HttpRequestMethodConfig == nil {
				return invalid("http-request-method requires HttpRequestMethodConfig")
			}
		case "source-ip":
			if c.SourceIpConfig == nil {
				return invalid("source-ip requires SourceIpConfig")
			}
			if c.SourceIpConfig.IpAddressType != nil {
				return unsupported("source-ip IpAddressType is an NLB-only condition")
			}
		case "query-string":
			if c.QueryStringConfig == nil {
				return invalid("query-string requires QueryStringConfig")
			}
			count := len(c.QueryStringConfig.Values)
			if count < 1 || count > 3 {
				return invalid("a condition requires 1..3 match evaluations")
			}
			evaluations += count
			for _, pair := range c.QueryStringConfig.Values {
				if pair.Value == nil {
					return invalid("query-string value is required")
				}
				for _, item := range []*api.StringValue{pair.Key, pair.Value} {
					if item == nil {
						continue
					}
					v := string(*item)
					if len(v) > 128 || !visibleASCII(v) {
						return invalid("query-string patterns must be visible ASCII of at most 128 characters")
					}
					wildcards += queryWildcardCount(v)
				}
			}
			continue
		default:
			return unsupported("condition field " + field)
		}
		if len(values) > 0 && len(regexes) > 0 {
			return invalid("value matching and regex matching cannot be combined in one condition")
		}
		count := len(values) + len(regexes)
		if count < 1 || count > 3 {
			return invalid("a condition requires 1..3 match evaluations")
		}
		evaluations += count
		for _, pattern := range regexes {
			if field != "host-header" && field != "path-pattern" && field != "http-header" {
				return invalid("regex is supported only for host, path and HTTP headers")
			}
			v := string(pattern)
			if len(v) == 0 || len(v) > 128 || !visibleASCII(v) {
				return invalid("regex must contain 1..128 visible ASCII characters")
			}
			for i := 0; i < len(v); i++ {
				if v[i] == '\\' && i+1 < len(v) {
					i++
					if v[i] == 'p' || v[i] == 'P' {
						return unsupported("Unicode regex character classes")
					}
				}
			}
			if _, err := regexp.Compile(v); err != nil {
				return invalid("unsupported or invalid condition regex: " + err.Error())
			}
		}
		for _, pattern := range values {
			v := string(pattern)
			if len(v) == 0 || len(v) > 128 || !visibleASCII(v) {
				return invalid("condition patterns must contain 1..128 visible ASCII characters")
			}
			switch field {
			case "host-header":
				dot := strings.LastIndexByte(v, '.')
				if dot < 0 || dot == len(v)-1 {
					return invalid("host pattern requires a dotted hostname")
				}
				for i := range v {
					ch := v[i]
					alpha := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
					if !alpha && (i > dot || !(ch >= '0' && ch <= '9' || ch == '-' || ch == '.' || ch == '*' || ch == '?')) {
						return invalid("invalid host pattern")
					}
				}
			case "path-pattern":
				for i := range v {
					if !isUnreserved(v[i]) && !strings.ContainsRune("/$\"'@:+&*?", rune(v[i])) {
						return invalid("invalid path pattern")
					}
				}
			case "http-request-method":
				if len(v) > 40 {
					return invalid("HTTP method exceeds 40 characters")
				}
				for i := range v {
					if !(v[i] >= 'A' && v[i] <= 'Z' || v[i] == '-' || v[i] == '_') {
						return invalid("HTTP method allows only uppercase letters, hyphen and underscore")
					}
				}
			case "source-ip":
				_, err := netip.ParsePrefix(v)
				if err != nil || v == "255.255.255.255/32" {
					return invalid("invalid source-ip CIDR")
				}
			}
			wildcards += strings.Count(v, "*") + strings.Count(v, "?")
		}
	}
	if evaluations > 5 {
		return invalid("a rule supports at most five match evaluations")
	}
	if wildcards > 5 {
		return invalid("a rule supports at most five wildcards")
	}
	return nil
}

func queryWildcardCount(v string) int {
	count, escaped := 0, false
	for i := range v {
		if escaped {
			escaped = false
			continue
		}
		if v[i] == '\\' {
			escaped = true
			continue
		}
		if v[i] == '*' || v[i] == '?' {
			count++
		}
	}
	return count
}

func (s *Service) validateActions(tx Reader, actions api.Actions, defaultRule bool) error {
	// Default and non-default rules share routing action constraints. Authentication
	// and JWT actions are rejected rather than accepted without enforcement.
	if err := validateActionShapes(actions); err != nil {
		return err
	}
	for _, group := range ForwardGroups(actions[0]) {
		if _, err := tx.TargetGroup(scopeFor(tx.Context()), group.ARN); err != nil {
			if errors.Is(err, ErrNotFound) {
				return failure("TargetGroupNotFound", "target group not found: "+group.ARN)
			}
			return err
		}
	}
	return nil
}

func validateActionShapes(actions api.Actions) error {
	if len(actions) == 0 {
		return invalid("exactly one terminal routing action is required")
	}
	for _, action := range actions {
		if action.Type == nil {
			return invalid("action type is required")
		}
		if action.AuthenticateCognitoConfig != nil || action.AuthenticateOidcConfig != nil || action.JwtValidationConfig != nil || *action.Type == api.ActionTypeEnumAUTHENTICATE_COGNITO || *action.Type == api.ActionTypeEnumAUTHENTICATE_OIDC || *action.Type == api.ActionTypeEnumJWT_VALIDATION {
			return unsupported("authentication and JWT validation actions")
		}
		if action.Order != nil && (*action.Order < 1 || *action.Order > 50000) {
			return invalid("action order must be in 1..50000")
		}
		switch *action.Type {
		case api.ActionTypeEnumFORWARD:
			if action.FixedResponseConfig != nil || action.RedirectConfig != nil {
				return invalid("forward action contains an unrelated configuration")
			}
			if action.ForwardConfig != nil {
				if sticky := action.ForwardConfig.TargetGroupStickinessConfig; sticky != nil {
					if sticky.Enabled != nil && bool(*sticky.Enabled) {
						return unsupported("target group stickiness")
					}
					if sticky.DurationSeconds != nil && (*sticky.DurationSeconds < 1 || *sticky.DurationSeconds > 604800) {
						return invalid("stickiness duration must be in 1..604800")
					}
				}
				if len(action.ForwardConfig.TargetGroups) == 0 || len(action.ForwardConfig.TargetGroups) > 5 {
					return invalid("forward configuration requires 1..5 target groups")
				}
				if action.TargetGroupArn != nil && (len(action.ForwardConfig.TargetGroups) != 1 || action.ForwardConfig.TargetGroups[0].TargetGroupArn == nil || *action.TargetGroupArn != *action.ForwardConfig.TargetGroups[0].TargetGroupArn) {
					return invalid("TargetGroupArn must match the single ForwardConfig target group")
				}
				for i, group := range action.ForwardConfig.TargetGroups {
					if group.TargetGroupArn == nil || *group.TargetGroupArn == "" {
						return invalid("target group ARN is required")
					}
					if len(action.ForwardConfig.TargetGroups) > 1 && group.Weight == nil {
						return invalid("each weighted target group requires a weight")
					}
					if group.Weight != nil && (*group.Weight < 0 || *group.Weight > 999) {
						return invalid("target group weight must be in 0..999")
					}
					for _, previous := range action.ForwardConfig.TargetGroups[:i] {
						if *previous.TargetGroupArn == *group.TargetGroupArn {
							return invalid("target group ARNs must be distinct")
						}
					}
				}
			} else if action.TargetGroupArn == nil || *action.TargetGroupArn == "" {
				return invalid("forward action requires a target group")
			}
		case api.ActionTypeEnumREDIRECT:
			if action.ForwardConfig != nil || action.TargetGroupArn != nil || action.FixedResponseConfig != nil {
				return invalid("redirect action contains an unrelated configuration")
			}
			if err := validateRedirect(action.RedirectConfig); err != nil {
				return err
			}
		case api.ActionTypeEnumFIXED_RESPONSE:
			if action.ForwardConfig != nil || action.TargetGroupArn != nil || action.RedirectConfig != nil {
				return invalid("fixed-response action contains an unrelated configuration")
			}
			if _, _, _, err := FixedResponse(action); err != nil {
				return invalid(err.Error())
			}
		default:
			return unsupported("action type " + string(*action.Type))
		}
	}
	if len(actions) != 1 {
		return invalid("exactly one terminal routing action is required, and it must be last")
	}
	return nil
}

func validateRedirect(c *api.RedirectActionConfig) error {
	if c == nil || c.StatusCode == nil {
		return invalid("redirect configuration and status code are required")
	}
	if *c.StatusCode != api.RedirectActionStatusCodeEnumHTTP_301 && *c.StatusCode != api.RedirectActionStatusCodeEnumHTTP_302 {
		return invalid("redirect status must be HTTP_301 or HTTP_302")
	}
	changed := false
	if c.Protocol != nil {
		v := string(*c.Protocol)
		if v != "HTTP" && v != "HTTPS" && v != "#{protocol}" {
			return invalid("redirect protocol must be HTTP, HTTPS or #{protocol}")
		}
		changed = v != "#{protocol}"
	}
	if c.Port != nil {
		v := string(*c.Port)
		if v != "#{port}" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != v {
				return invalid("redirect port must be in 1..65535 or #{port}")
			}
			changed = true
		}
	}
	if c.Host != nil {
		v := string(*c.Host)
		if len(v) == 0 || len(v) > 128 || !visibleASCII(v) {
			return invalid("invalid redirect hostname")
		}
		remaining := strings.ReplaceAll(v, "#{host}", "example.com")
		if strings.ContainsAny(remaining, " /\\@:?#\r\n") {
			return invalid("invalid redirect hostname")
		}
		changed = changed || v != "#{host}"
	}
	if c.Path != nil {
		v := string(*c.Path)
		if len(v) == 0 || len(v) > 128 || v[0] != '/' || !visibleASCII(v) {
			return invalid("redirect path must start with / and contain at most 128 visible ASCII characters")
		}
		if err := redirectKeywords(v, "host", "path", "port"); err != nil {
			return err
		}
		withoutKeywords := strings.NewReplacer("#{host}", "", "#{path}", "", "#{port}", "").Replace(v)
		if strings.ContainsAny(withoutKeywords, "?#") {
			return invalid("redirect path cannot contain query or fragment delimiters")
		}
		changed = changed || v != "/#{path}"
	}
	if c.Query != nil {
		v := string(*c.Query)
		if len(v) > 128 || !visibleASCII(v) || strings.HasPrefix(v, "?") {
			return invalid("invalid redirect query")
		}
		if err := redirectKeywords(v, "protocol", "host", "port", "path", "query"); err != nil {
			return err
		}
	}
	if !changed {
		return invalid("redirect must modify protocol, host, port or path")
	}
	return nil
}

func redirectKeywords(v string, allowed ...string) error {
	for _, keyword := range allowed {
		v = strings.ReplaceAll(v, "#{"+keyword+"}", "")
	}
	if strings.Contains(v, "#{") {
		return invalid(fmt.Sprintf("unsupported redirect interpolation in %q", v))
	}
	return nil
}
