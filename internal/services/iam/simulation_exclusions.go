package iam

import (
	"regexp"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awswire"
)

type simulationExclusion struct {
	kind       iamapi.PolicyIdentifierPolicyType
	arn        *regexp.Regexp
	ownerKind  string
	ownerName  *regexp.Regexp
	policyName string
}

func simulationExclusions(inputs iamapi.PolicyExclusionsListType) ([]simulationExclusion, *awswire.Error) {
	if len(inputs) > 256 {
		return nil, invalidInput("PolicyExclusionList cannot contain more than 256 identifiers.")
	}
	result := make([]simulationExclusion, 0, len(inputs))
	for _, input := range inputs {
		count := 0
		for _, present := range []bool{input.PolicyArn != nil, input.PolicyType != nil, input.InlinePolicyIdentifier != nil} {
			if present {
				count++
			}
		}
		if count != 1 {
			return nil, invalidInput("A policy identifier must specify exactly one of PolicyType, PolicyArn, or InlinePolicyIdentifier.")
		}
		exclusion := simulationExclusion{}
		switch {
		case input.PolicyType != nil:
			exclusion.kind = *input.PolicyType
			switch exclusion.kind {
			case iamapi.PolicyIdentifierPolicyTypeINLINE, iamapi.PolicyIdentifierPolicyTypeAWS_MANAGED,
				iamapi.PolicyIdentifierPolicyTypeUSER_MANAGED, iamapi.PolicyIdentifierPolicyTypePERMISSION_BOUNDARY,
				iamapi.PolicyIdentifierPolicyTypeSCP, iamapi.PolicyIdentifierPolicyTypeRCP:
			default:
				return nil, invalidInput("Invalid policy exclusion type.")
			}
		case input.PolicyArn != nil:
			arn := string(*input.PolicyArn)
			parts := strings.SplitN(arn, ":", 6)
			if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "iam" || parts[3] != "" ||
				(parts[4] != "aws" && (len(parts[4]) != 12 || strings.Trim(parts[4], "0123456789") != "")) ||
				!strings.HasPrefix(parts[5], "policy/") || len(parts[5]) == len("policy/") ||
				strings.ContainsAny(strings.Join(parts[:5], ":"), "*? \t\r\n") || strings.ContainsAny(parts[5], " \t\r\n:") {
				return nil, invalidInput("Policy exclusion ARN must identify a managed IAM policy.")
			}
			pattern, err := simulationSelectorPattern(arn)
			if err != nil {
				return nil, err
			}
			exclusion.arn = pattern
		case input.InlinePolicyIdentifier != nil:
			inline := input.InlinePolicyIdentifier
			exclusion.ownerKind, exclusion.policyName = inputString(inline.AttachmentType), inputString(inline.PolicyName)
			if exclusion.ownerKind != "user" && exclusion.ownerKind != "group" && exclusion.ownerKind != "role" {
				return nil, invalidInput("Inline policy exclusion requires an IAM user, group, or role attachment.")
			}
			if !namePattern.MatchString(exclusion.policyName) {
				return nil, invalidInput("Inline policy exclusions require an exact policy name.")
			}
			pattern, err := simulationSelectorPattern(inputString(inline.AttachmentName))
			if err != nil {
				return nil, err
			}
			exclusion.ownerName = pattern
		}
		result = append(result, exclusion)
	}
	return result, nil
}

func simulationSelectorPattern(pattern string) (*regexp.Regexp, *awswire.Error) {
	if pattern == "" || strings.Count(pattern, "*") > 1 {
		return nil, invalidInput("A policy exclusion selector permits at most one '*' wildcard.")
	}
	expression := regexp.QuoteMeta(pattern)
	expression = strings.ReplaceAll(expression, `\*`, ".*")
	expression = strings.ReplaceAll(expression, `\?`, ".")
	compiled, err := regexp.Compile("^" + expression + "$")
	if err != nil {
		return nil, invalidInput("Invalid policy exclusion selector.")
	}
	return compiled, nil
}

func simulationPolicyExcluded(policy simulationPolicy, exclusions []simulationExclusion) bool {
	for _, exclusion := range exclusions {
		switch {
		case exclusion.arn != nil:
			if policy.boundary {
				continue
			}
			// AWS simulation matches managed-policy selectors against the ARN
			// formed from its friendly name, even when the stored ARN has a path.
			arn := policy.arn
			if parts := strings.SplitN(arn, ":", 6); len(parts) == 6 {
				parts[5] = "policy/" + policy.name
				arn = strings.Join(parts, ":")
			}
			if arn != "" && exclusion.arn.MatchString(arn) {
				return true
			}
		case exclusion.ownerName != nil:
			if policy.ownerKind == exclusion.ownerKind && policy.name == exclusion.policyName && exclusion.ownerName.MatchString(policy.ownerName) {
				return true
			}
		case exclusion.kind == iamapi.PolicyIdentifierPolicyTypePERMISSION_BOUNDARY:
			if policy.boundary {
				return true
			}
		case exclusion.kind == iamapi.PolicyIdentifierPolicyTypeINLINE:
			if !policy.boundary && policy.ownerKind != "" {
				return true
			}
		case exclusion.kind == iamapi.PolicyIdentifierPolicyTypeAWS_MANAGED || exclusion.kind == iamapi.PolicyIdentifierPolicyTypeUSER_MANAGED:
			if !policy.boundary && string(policy.sourceType) == string(exclusion.kind) {
				return true
			}
		}
	}
	return false
}

func simulationExcludesControls(exclusions []simulationExclusion) bool {
	for _, exclusion := range exclusions {
		if exclusion.kind == iamapi.PolicyIdentifierPolicyTypeSCP {
			return true
		}
	}
	return false
}
