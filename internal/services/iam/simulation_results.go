package iam

import (
	"cmp"
	"slices"

	policyeval "stackd/iam/policy"
	iamapi "stackd/internal/awsapi/iam"
)

func simulationAll(previous, next *bool) *bool {
	if next == nil {
		return previous
	}
	if previous == nil {
		return wirePointer(*next)
	}
	return wirePointer(*previous && *next)
}

func simulationStatements(matches []simulationMatch, decision policyeval.Decision) iamapi.StatementListType {
	result := iamapi.StatementListType{}
	// AWS does not specify match ordering. Stable attribution and positions give
	// repeatable local results, including unions across repeated resources.
	slices.SortFunc(matches, func(a, b simulationMatch) int {
		if order := cmp.Compare(a.sourceID, b.sourceID); order != 0 {
			return order
		}
		if order := cmp.Compare(a.sourceType, b.sourceType); order != 0 {
			return order
		}
		if order := cmp.Compare(a.match.Start.Line, b.match.Start.Line); order != 0 {
			return order
		}
		if order := cmp.Compare(a.match.Start.Column, b.match.Start.Column); order != 0 {
			return order
		}
		if order := cmp.Compare(a.match.End.Line, b.match.End.Line); order != 0 {
			return order
		}
		return cmp.Compare(a.match.End.Column, b.match.End.Column)
	})
	type key struct {
		id, kind   string
		start, end policyeval.Position
	}
	seen := make(map[key]bool)
	for _, value := range matches {
		if decision == policyeval.ExplicitDeny && value.match.Effect != policyeval.ExplicitDeny {
			continue
		}
		k := key{value.sourceID, value.sourceType, value.match.Start, value.match.End}
		if seen[k] {
			continue
		}
		seen[k] = true
		result = append(result, iamapi.Statement{
			SourcePolicyId: wirePointer(iamapi.PolicyIdentifierType(value.sourceID)), SourcePolicyType: wirePointer(iamapi.PolicySourceType(value.sourceType)),
			StartPosition: &iamapi.Position{Line: wirePointer(iamapi.LineNumber(value.match.Start.Line)), Column: wirePointer(iamapi.ColumnNumber(value.match.Start.Column))},
			EndPosition:   &iamapi.Position{Line: wirePointer(iamapi.LineNumber(value.match.End.Line)), Column: wirePointer(iamapi.ColumnNumber(value.match.End.Column))},
		})
	}
	return result
}

func simulationMissing(keys []string) iamapi.ContextKeyNamesResultListType {
	slices.Sort(keys)
	return iamapi.ContextKeyNamesResultListType(simulationNames(slices.Compact(keys)))
}

func simulationNames(keys []string) []iamapi.ContextKeyNameType {
	result := make([]iamapi.ContextKeyNameType, len(keys))
	for i, key := range keys {
		result[i] = iamapi.ContextKeyNameType(key)
	}
	return result
}

func simulationBoundaryDetail(allowed *bool) *iamapi.PermissionsBoundaryDecisionDetail {
	if allowed == nil {
		return nil
	}
	return &iamapi.PermissionsBoundaryDecisionDetail{AllowedByPermissionsBoundary: wirePointer(iamapi.BooleanType(*allowed))}
}

func simulationDetails(values map[string]policyeval.Decision) iamapi.EvalDecisionDetailsType {
	if values == nil {
		return nil
	}
	result := make(iamapi.EvalDecisionDetailsType, len(values))
	for key, value := range values {
		result[iamapi.EvalDecisionSourceType(key)] = iamapi.PolicyEvaluationDecisionType(value)
	}
	return result
}
