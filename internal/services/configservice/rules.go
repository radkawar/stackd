package configservice

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/configservice"
)

func registerRules(s *Service) {
	register(s, "PutConfigRule", s.putConfigRule)
	register(s, "DeleteConfigRule", s.deleteConfigRule)
	registerConfigRuleAPI(s, "DescribeConfigRules", s.describeConfigRules)
	register(s, "StartConfigRulesEvaluation", s.startConfigRulesEvaluation)
	registerConfigRuleAPI(s, "PutEvaluations", s.putEvaluations)
	register(s, "DeleteEvaluationResults", s.deleteEvaluationResults)
	registerConfigRuleAPI(s, "DescribeConfigRuleEvaluationStatus", s.describeConfigRuleEvaluationStatus)
	registerConfigRuleAPI(s, "DescribeComplianceByConfigRule", s.describeComplianceByConfigRule)
	registerConfigRuleAPI(s, "DescribeComplianceByResource", s.describeComplianceByResource)
	register(s, "GetComplianceDetailsByConfigRule", s.getComplianceDetailsByConfigRule)
	registerConfigRuleAPI(s, "GetComplianceDetailsByResource", s.getComplianceDetailsByResource)
	registerConfigRuleAPI(s, "GetComplianceSummaryByConfigRule", s.getComplianceSummaryByConfigRule)
	registerConfigRuleAPI(s, "GetComplianceSummaryByResourceType", s.getComplianceSummaryByResourceType)
}

func registerConfigRuleAPI[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	register(s, action, func(tx Transaction, in *I) (*O, error) {
		if err := s.authorize(tx.Context(), action); err != nil {
			return nil, err
		}
		return fn(tx, in)
	})
}

func ruleByName(r Reader, scope Scope, name string) (Rule, error) {
	rules, err := r.Rules(scope)
	if err != nil {
		return Rule{}, err
	}
	for _, rule := range rules {
		if rule.Name == name {
			return rule, nil
		}
	}
	return Rule{}, failure("NoSuchConfigRuleException", "The Config rule does not exist: "+name)
}

func opaqueRuleID() string {
	var id [24]byte
	_, _ = rand.Read(id[:])
	return base64.RawURLEncoding.EncodeToString(id[:])
}

func (s *Service) putConfigRule(tx Transaction, in *api.PutConfigRuleInput) (*api.PutConfigRuleOutput, error) {
	c := in.ConfigRule
	if c == nil || value(c.ConfigRuleName) == "" || c.Source == nil {
		return nil, failure("InvalidParameterValueException", "ConfigRuleName and Source are required")
	}
	// TODO: Comeback: proactive evaluation, service scopes and custom policies need their own retained execution semantics.
	if c.MaximumExecutionFrequency != nil || c.CreatedBy != nil || c.RuleEvaluationVisibility != nil {
		return nil, failure("InvalidParameterValueException", "Frequency, CreatedBy and visibility are not supported")
	}
	if c.ConfigRuleState != nil && value(c.ConfigRuleState) != "ACTIVE" {
		return nil, failure("InvalidParameterValueException", "Only ACTIVE Config rules are supported")
	}
	if len(c.EvaluationModes) > 1 || (len(c.EvaluationModes) == 1 && value(c.EvaluationModes[0].Mode) != "DETECTIVE") {
		return nil, failure("InvalidParameterValueException", "Only DETECTIVE evaluation is supported")
	}
	scope := scopeFor(tx.Context())
	if _, ok, err := tx.Recorder(scope); err != nil {
		return nil, err
	} else if !ok {
		return nil, failure("NoAvailableConfigurationRecorderException", "A configuration recorder is required")
	}
	rule := Rule{Scope: scope, Name: value(c.ConfigRuleName), Description: value(c.Description), Owner: value(c.Source.Owner), SourceIdentifier: value(c.Source.SourceIdentifier), CreatedAt: s.clock.Now()}
	params := map[string]string{}
	if p := value(c.InputParameters); p != "" {
		if err := json.Unmarshal([]byte(p), &params); err != nil || params == nil {
			return nil, failure("InvalidParameterValueException", "InputParameters must be an object of string values")
		}
		data, _ := json.Marshal(params)
		rule.InputParameters = string(data)
	}
	if c.Source.CustomPolicyDetails != nil {
		return nil, failure("InvalidParameterValueException", "Custom policy rules are not supported")
	}
	switch rule.Owner {
	case "AWS":
		// TODO: Comeback: implement further managed rules from their documented evaluation contracts.
		if rule.SourceIdentifier != "REQUIRED_TAGS" || len(c.Source.SourceDetails) > 0 {
			return nil, failure("InvalidParameterValueException", "Only the REQUIRED_TAGS managed rule is supported")
		}
		if err := validateRequiredTags(params); err != nil {
			return nil, err
		}
	case "CUSTOM_LAMBDA":
		parts := strings.Split(rule.SourceIdentifier, ":")
		if len(parts) < 7 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "lambda" || parts[3] != scope.Region || parts[4] != scope.AccountID || parts[5] != "function" || parts[6] == "" {
			return nil, failure("InvalidParameterValueException", "SourceIdentifier must be a Lambda function ARN in this account and Region")
		}
		// TODO: Comeback: periodic custom Lambda rules require retained frequency deadlines, not inert SourceDetails.
		for _, d := range c.Source.SourceDetails {
			m := value(d.MessageType)
			if value(d.EventSource) != "aws.config" || d.MaximumExecutionFrequency != nil || (m != "ConfigurationItemChangeNotification" && m != "OversizedConfigurationItemChangeNotification") {
				return nil, failure("InvalidParameterValueException", "Only configuration-change Lambda rule sources are supported")
			}
			if slices.Contains(rule.SourceMessages, m) {
				return nil, failure("InvalidParameterValueException", "Duplicate source message type")
			}
			rule.SourceMessages = append(rule.SourceMessages, m)
		}
		if !slices.Contains(rule.SourceMessages, "ConfigurationItemChangeNotification") {
			return nil, failure("InvalidParameterValueException", "ConfigurationItemChangeNotification is required")
		}
	default:
		return nil, failure("InvalidParameterValueException", "Unsupported rule owner")
	}
	if c.Scope != nil {
		if len(c.Scope.ServicePrincipals) > 0 {
			return nil, failure("InvalidParameterValueException", "Service principal rule scopes are not supported")
		}
		for _, t := range c.Scope.ComplianceResourceTypes {
			rule.ResourceTypes = append(rule.ResourceTypes, string(t))
		}
		sort.Strings(rule.ResourceTypes)
		rule.ResourceTypes = slices.Compact(rule.ResourceTypes)
		rule.ResourceID = value(c.Scope.ComplianceResourceId)
		rule.TagKey = value(c.Scope.TagKey)
		rule.TagValue = value(c.Scope.TagValue)
		if rule.ResourceID != "" && len(rule.ResourceTypes) != 1 {
			return nil, failure("InvalidParameterValueException", "A resource ID scope requires exactly one resource type")
		}
		if rule.TagValue != "" && rule.TagKey == "" {
			return nil, failure("InvalidParameterValueException", "TagValue requires TagKey")
		}
	}
	rules, err := tx.Rules(scope)
	if err != nil {
		return nil, err
	}
	for _, old := range rules {
		if old.Name == rule.Name {
			rule.ID = old.ID
			rule.ARN = old.ARN
			rule.CreatedAt = old.CreatedAt
			rule.LastEvaluation = old.LastEvaluation
			rule.LastReevaluation = old.LastReevaluation
			break
		}
	}
	creating := rule.ID == ""
	if creating {
		rule.ID = "config-rule-" + opaqueRuleID()[:7]
		rule.ARN = fmt.Sprintf("arn:%s:config:%s:%s:config-rule/%s", scope.Partition, scope.Region, scope.AccountID, rule.ID)
	}
	if c.ConfigRuleArn != nil && value(c.ConfigRuleArn) != rule.ARN || c.ConfigRuleId != nil && value(c.ConfigRuleId) != rule.ID {
		return nil, failure("InvalidParameterValueException", "The supplied rule identifier does not match the rule")
	}
	if err := s.authorizeResource(tx.Context(), "PutConfigRule", rule.ARN); err != nil {
		return nil, err
	}
	if creating {
		if err := s.putCreationTags(tx, rule.ARN, in.Tags); err != nil {
			return nil, err
		}
	}
	if err := s.cancelRuleRuns(tx, scope, rule.Name); err != nil {
		return nil, err
	}
	if err := tx.PutRule(rule); err != nil {
		return nil, err
	}
	items, err := tx.Items(scope)
	if err != nil {
		return nil, err
	}
	for _, item := range latestRuleItems(items) {
		if err := s.evaluateRuleItem(tx, rule, item); err != nil {
			return nil, err
		}
	}
	s.wake(tx.Context())
	return &api.PutConfigRuleOutput{}, nil
}

func validateRequiredTags(p map[string]string) error {
	if p["tag1Key"] == "" {
		return failure("InvalidParameterValueException", "REQUIRED_TAGS requires tag1Key")
	}
	for k := range p {
		valid := false
		for n := 1; n <= 6; n++ {
			prefix := "tag" + strconv.Itoa(n)
			if k == prefix+"Key" || k == prefix+"Value" {
				valid = true
				if p[prefix+"Key"] == "" {
					return failure("InvalidParameterValueException", prefix+"Key is required when specifying a tag value")
				}
			}
		}
		if !valid {
			return failure("InvalidParameterValueException", "Unsupported REQUIRED_TAGS parameter: "+k)
		}
	}
	return nil
}

func (s *Service) cancelRuleRuns(tx Transaction, scope Scope, name string) error {
	runs, err := tx.EvaluationRuns()
	if err != nil {
		return err
	}
	for _, run := range runs {
		if run.Scope == scope && run.RuleName == name && (run.Status == "PENDING" || run.Status == "RUNNING") {
			run.Status = "CANCELLED"
			run.CompletedAt = s.clock.Now()
			if err := tx.PutEvaluationRun(run); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) deleteConfigRule(tx Transaction, in *api.DeleteConfigRuleInput) (*api.DeleteConfigRuleOutput, error) {
	scope := scopeFor(tx.Context())
	name := value(in.ConfigRuleName)
	rule, err := ruleByName(tx, scope, name)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "DeleteConfigRule", rule.ARN); err != nil {
		return nil, err
	}
	if err := s.cancelRuleRuns(tx, scope, name); err != nil {
		return nil, err
	}
	if err := tx.DeleteEvaluations(scope, name); err != nil {
		return nil, err
	}
	if err := tx.DeleteRule(scope, name); err != nil {
		return nil, err
	}
	if err := tx.PutTags(scope, rule.ARN, nil); err != nil {
		return nil, err
	}
	return &api.DeleteConfigRuleOutput{}, nil
}
func configRuleShape(r Rule) api.ConfigRule {
	c := api.ConfigRule{ConfigRuleName: new(api.ConfigRuleName(r.Name)), ConfigRuleId: new(api.StringWithCharLimit64(r.ID)), ConfigRuleArn: new(api.StringWithCharLimit256(r.ARN)), ConfigRuleState: new(api.ConfigRuleState("ACTIVE")), Source: &api.Source{Owner: new(api.Owner(r.Owner)), SourceIdentifier: new(api.StringWithCharLimit256(r.SourceIdentifier))}, EvaluationModes: api.EvaluationModes{{Mode: new(api.EvaluationMode("DETECTIVE"))}}}
	if r.Description != "" {
		c.Description = new(api.EmptiableStringWithCharLimit256(r.Description))
	}
	if r.InputParameters != "" {
		c.InputParameters = new(api.StringWithCharLimit1024(r.InputParameters))
	}
	for _, m := range r.SourceMessages {
		c.Source.SourceDetails = append(c.Source.SourceDetails, api.SourceDetail{EventSource: new(api.EventSource("aws.config")), MessageType: new(api.MessageType(m))})
	}
	if len(r.ResourceTypes) > 0 || r.ResourceID != "" || r.TagKey != "" {
		c.Scope = &api.Scope{}
		for _, t := range r.ResourceTypes {
			c.Scope.ComplianceResourceTypes = append(c.Scope.ComplianceResourceTypes, api.StringWithCharLimit256(t))
		}
		if r.ResourceID != "" {
			c.Scope.ComplianceResourceId = new(api.BaseResourceId(r.ResourceID))
		}
		if r.TagKey != "" {
			c.Scope.TagKey = new(api.StringWithCharLimit128(r.TagKey))
		}
		if r.TagValue != "" {
			c.Scope.TagValue = new(api.StringWithCharLimit256(r.TagValue))
		}
	}
	return c
}
func selectRules[T ~string](tx Reader, scope Scope, names []T) ([]Rule, error) {
	all, err := tx.Rules(scope)
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	if len(names) == 0 {
		return all, nil
	}
	selected := make([]Rule, 0, len(names))
	for _, r := range all {
		for _, name := range names {
			if r.Name == string(name) {
				selected = append(selected, r)
				break
			}
		}
	}
	for _, name := range names {
		if !slices.ContainsFunc(selected, func(r Rule) bool { return r.Name == string(name) }) {
			return nil, failure("NoSuchConfigRuleException", "The Config rule does not exist: "+string(name))
		}
	}
	return selected, nil
}
func (s *Service) describeConfigRules(tx Transaction, in *api.DescribeConfigRulesInput) (*api.DescribeConfigRulesOutput, error) {
	rules, err := selectRules(tx, scopeFor(tx.Context()), in.ConfigRuleNames)
	if err != nil {
		return nil, err
	}
	if in.Filters != nil {
		if in.Filters.RuleEvaluationVisibility != nil {
			return nil, failure("InvalidParameterValueException", "Rule visibility filters are not supported")
		}
		if value(in.Filters.EvaluationMode) != "" && value(in.Filters.EvaluationMode) != "DETECTIVE" {
			rules = nil
		}
	}
	page, next, err := rulePage(rules, 25, 25, value(in.NextToken), ruleQuery(tx, "DescribeConfigRules", in.ConfigRuleNames, in.Filters))
	if err != nil {
		return nil, err
	}
	out := &api.DescribeConfigRulesOutput{ConfigRules: api.ConfigRules{}, NextToken: ruleString[api.String](next)}
	for _, r := range page {
		out.ConfigRules = append(out.ConfigRules, configRuleShape(r))
	}
	return out, nil
}
func (s *Service) startConfigRulesEvaluation(tx Transaction, in *api.StartConfigRulesEvaluationInput) (*api.StartConfigRulesEvaluationOutput, error) {
	scope := scopeFor(tx.Context())
	rules, err := selectRules(tx, scope, in.ConfigRuleNames)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		if err := s.authorize(tx.Context(), "StartConfigRulesEvaluation"); err != nil {
			return nil, err
		}
	}
	for _, rule := range rules {
		if err := s.authorizeResource(tx.Context(), "StartConfigRulesEvaluation", rule.ARN); err != nil {
			return nil, err
		}
	}
	runs, err := tx.EvaluationRuns()
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	for _, r := range rules {
		for _, run := range runs {
			if run.Scope == scope && run.RuleName == r.Name && (run.Status == "PENDING" || run.Status == "RUNNING") {
				return nil, failure("LimitExceededException", "An evaluation is already in progress")
			}
		}
		if !r.LastReevaluation.IsZero() && now.Sub(r.LastReevaluation) < time.Minute {
			return nil, failure("LimitExceededException", "A rule can be reevaluated only once per minute")
		}
	}
	items, err := tx.Items(scope)
	if err != nil {
		return nil, err
	}
	latest := latestRuleItems(items)
	for _, r := range rules {
		r.LastReevaluation = now
		if err := tx.PutRule(r); err != nil {
			return nil, err
		}
		for _, item := range latest {
			if err := s.evaluateRuleItem(tx, r, item); err != nil {
				return nil, err
			}
		}
	}
	s.wake(tx.Context())
	return &api.StartConfigRulesEvaluationOutput{}, nil
}
func (s *Service) deleteEvaluationResults(tx Transaction, in *api.DeleteEvaluationResultsInput) (*api.DeleteEvaluationResultsOutput, error) {
	scope := scopeFor(tx.Context())
	name := value(in.ConfigRuleName)
	rule, err := ruleByName(tx, scope, name)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "DeleteEvaluationResults", rule.ARN); err != nil {
		return nil, err
	}
	if err := tx.DeleteEvaluations(scope, name); err != nil {
		return nil, err
	}
	return &api.DeleteEvaluationResultsOutput{}, nil
}

func (s *Service) putEvaluations(tx Transaction, in *api.PutEvaluationsInput) (*api.PutEvaluationsOutput, error) {
	if in.ResultToken == nil || len(in.Evaluations) > 100 {
		return nil, failure("InvalidParameterValueException", "ResultToken is required and at most 100 evaluations are allowed")
	}
	for _, e := range in.Evaluations {
		if value(e.ComplianceResourceId) == "" || value(e.ComplianceResourceType) == "" || e.OrderingTimestamp == nil || len(value(e.Annotation)) > 256 || !slices.Contains([]string{"COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE"}, value(e.ComplianceType)) {
			return nil, failure("InvalidParameterValueException", "Invalid evaluation: resource, timestamp and supported compliance type are required")
		}
	}
	out := &api.PutEvaluationsOutput{FailedEvaluations: api.Evaluations{}}
	if boolean(in.TestMode) {
		return out, nil
	}
	scope := scopeFor(tx.Context())
	runs, err := tx.EvaluationRuns()
	if err != nil {
		return nil, err
	}
	var run EvaluationRun
	found := false
	for _, r := range runs {
		if r.Scope == scope && r.Token == value(in.ResultToken) && r.Status == "RUNNING" && s.clock.Now().Before(r.Due) {
			run = r
			found = true
			break
		}
	}
	if !found {
		return nil, failure("InvalidResultTokenException", "The result token is invalid or expired")
	}
	rule, err := ruleByName(tx, scope, run.RuleName)
	if err != nil {
		return nil, err
	}
	existing, err := tx.Evaluations(scope)
	if err != nil {
		return nil, err
	}
	byKey := map[string]Evaluation{}
	for _, e := range existing {
		if e.RuleName == rule.Name {
			byKey[e.ResourceType+"\x00"+e.ResourceID] = e
		}
	}
	now := s.clock.Now()
	for _, e := range in.Evaluations {
		k := value(e.ComplianceResourceType) + "\x00" + value(e.ComplianceResourceId)
		old, ok := byKey[k]
		if ok && e.OrderingTimestamp.Before(old.OrderingTime) {
			continue
		}
		stored := Evaluation{Scope: scope, RuleName: rule.Name, ResourceType: value(e.ComplianceResourceType), ResourceID: value(e.ComplianceResourceId), ComplianceType: value(e.ComplianceType), Annotation: value(e.Annotation), OrderingTime: *e.OrderingTimestamp, RecordedAt: now, InvokedAt: run.CreatedAt}
		if err := tx.PutEvaluation(stored); err != nil {
			return nil, err
		}
		byKey[k] = stored
	}
	// A callback is evidence of evaluation; a successful Lambda Invoke alone is not.
	run.CompletedAt = now
	if err := tx.PutEvaluationRun(run); err != nil {
		return nil, err
	}
	rule.LastEvaluation = now
	rule.ErrorCode = ""
	rule.ErrorMessage = ""
	if err := tx.PutRule(rule); err != nil {
		return nil, err
	}
	return out, nil
}

func evaluationShape(e Evaluation) api.EvaluationResult {
	return api.EvaluationResult{Annotation: ruleString[api.StringWithCharLimit256](e.Annotation), ComplianceType: new(api.ComplianceType(e.ComplianceType)), ConfigRuleInvokedTime: &e.InvokedAt, ResultRecordedTime: &e.RecordedAt, EvaluationResultIdentifier: &api.EvaluationResultIdentifier{OrderingTimestamp: &e.OrderingTime, EvaluationResultQualifier: &api.EvaluationResultQualifier{ConfigRuleName: new(api.ConfigRuleName(e.RuleName)), ResourceType: new(api.StringWithCharLimit256(e.ResourceType)), ResourceId: new(api.BaseResourceId(e.ResourceID)), EvaluationMode: new(api.EvaluationMode("DETECTIVE"))}}}
}
func orderedEvaluations(r Reader, scope Scope) ([]Evaluation, error) {
	all, err := r.Evaluations(scope)
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.RuleName != b.RuleName {
			return a.RuleName < b.RuleName
		}
		if a.ResourceType != b.ResourceType {
			return a.ResourceType < b.ResourceType
		}
		return a.ResourceID < b.ResourceID
	})
	return all, nil
}
func complianceMatches(types api.ComplianceTypes, t string) bool {
	return len(types) == 0 || slices.Contains(types, api.ComplianceType(t))
}
func validateComplianceFilter(types api.ComplianceTypes) error {
	for _, t := range types {
		if t != "COMPLIANT" && t != "NON_COMPLIANT" {
			return failure("InvalidParameterValueException", "Only COMPLIANT and NON_COMPLIANT compliance filters are supported")
		}
	}
	return nil
}
func validateDetailComplianceFilter(types api.ComplianceTypes) error {
	for _, t := range types {
		if t != "COMPLIANT" && t != "NON_COMPLIANT" && t != "NOT_APPLICABLE" {
			return failure("InvalidParameterValueException", "INSUFFICIENT_DATA cannot filter evaluation details")
		}
	}
	return nil
}
func validateSummaryComplianceFilter(types api.ComplianceTypes) error {
	for _, t := range types {
		if t != "COMPLIANT" && t != "NON_COMPLIANT" && t != "NOT_APPLICABLE" && t != "INSUFFICIENT_DATA" {
			return failure("InvalidParameterValueException", "Invalid compliance type")
		}
	}
	return nil
}
func (s *Service) getComplianceDetailsByConfigRule(tx Transaction, in *api.GetComplianceDetailsByConfigRuleInput) (*api.GetComplianceDetailsByConfigRuleOutput, error) {
	if err := validateDetailComplianceFilter(in.ComplianceTypes); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	name := value(in.ConfigRuleName)
	rule, err := ruleByName(tx, scope, name)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "GetComplianceDetailsByConfigRule", rule.ARN); err != nil {
		return nil, err
	}
	all, err := orderedEvaluations(tx, scope)
	if err != nil {
		return nil, err
	}
	rows := api.EvaluationResults{}
	for _, e := range all {
		if e.RuleName == name && complianceMatches(in.ComplianceTypes, e.ComplianceType) {
			rows = append(rows, evaluationShape(e))
		}
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 10), 100, value(in.NextToken), ruleQuery(tx, "GetComplianceDetailsByConfigRule", name, in.ComplianceTypes))
	return &api.GetComplianceDetailsByConfigRuleOutput{EvaluationResults: rows, NextToken: ruleString[api.NextToken](next)}, err
}
func (s *Service) getComplianceDetailsByResource(tx Transaction, in *api.GetComplianceDetailsByResourceInput) (*api.GetComplianceDetailsByResourceOutput, error) {
	if err := validateDetailComplianceFilter(in.ComplianceTypes); err != nil {
		return nil, err
	}
	if in.ResourceEvaluationId != nil {
		return nil, failure("InvalidParameterValueException", "Proactive resource evaluations are not supported")
	}
	if value(in.ResourceId) == "" || value(in.ResourceType) == "" {
		return nil, failure("InvalidParameterValueException", "ResourceId and ResourceType are required")
	}
	all, err := orderedEvaluations(tx, scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	rows := api.EvaluationResults{}
	for _, e := range all {
		if e.ResourceType == value(in.ResourceType) && e.ResourceID == value(in.ResourceId) && complianceMatches(in.ComplianceTypes, e.ComplianceType) {
			rows = append(rows, evaluationShape(e))
		}
	}
	rows, next, err := rulePage(rows, 100, 100, value(in.NextToken), ruleQuery(tx, "GetComplianceDetailsByResource", in.ResourceId, in.ResourceType, in.ComplianceTypes))
	return &api.GetComplianceDetailsByResourceOutput{EvaluationResults: rows, NextToken: ruleString[api.String](next)}, err
}
func complianceShape(evaluations []Evaluation) api.Compliance {
	compliant, noncompliant := 0, 0
	for _, e := range evaluations {
		if e.ComplianceType == "NON_COMPLIANT" {
			noncompliant++
		} else if e.ComplianceType == "COMPLIANT" {
			compliant++
		}
	}
	kind := "INSUFFICIENT_DATA"
	if noncompliant > 0 {
		kind = "NON_COMPLIANT"
	} else if compliant > 0 {
		kind = "COMPLIANT"
	}
	out := api.Compliance{ComplianceType: new(api.ComplianceType(kind))}
	if noncompliant > 0 {
		out.ComplianceContributorCount = complianceCount(noncompliant)
	}
	return out
}
func complianceCount(n int) *api.ComplianceContributorCount {
	return &api.ComplianceContributorCount{CappedCount: new(api.Integer(min(n, 25))), CapExceeded: new(api.Boolean(n > 25))}
}
func (s *Service) describeComplianceByConfigRule(tx Transaction, in *api.DescribeComplianceByConfigRuleInput) (*api.DescribeComplianceByConfigRuleOutput, error) {
	if err := validateSummaryComplianceFilter(in.ComplianceTypes); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	rules, err := selectRules(tx, scope, in.ConfigRuleNames)
	if err != nil {
		return nil, err
	}
	evals, err := tx.Evaluations(scope)
	if err != nil {
		return nil, err
	}
	byRule := map[string][]Evaluation{}
	for _, e := range evals {
		byRule[e.RuleName] = append(byRule[e.RuleName], e)
	}
	rows := api.ComplianceByConfigRules{}
	for _, r := range rules {
		c := complianceShape(byRule[r.Name])
		if complianceMatches(in.ComplianceTypes, value(c.ComplianceType)) {
			rows = append(rows, api.ComplianceByConfigRule{ConfigRuleName: new(api.StringWithCharLimit64(r.Name)), Compliance: &c})
		}
	}
	rows, next, err := rulePage(rows, 25, 25, value(in.NextToken), ruleQuery(tx, "DescribeComplianceByConfigRule", in.ConfigRuleNames, in.ComplianceTypes))
	return &api.DescribeComplianceByConfigRuleOutput{ComplianceByConfigRules: rows, NextToken: ruleString[api.String](next)}, err
}
func (s *Service) describeComplianceByResource(tx Transaction, in *api.DescribeComplianceByResourceInput) (*api.DescribeComplianceByResourceOutput, error) {
	if err := validateSummaryComplianceFilter(in.ComplianceTypes); err != nil {
		return nil, err
	}
	if value(in.ResourceId) != "" && value(in.ResourceType) == "" {
		return nil, failure("InvalidParameterValueException", "ResourceId requires ResourceType")
	}
	all, err := tx.Evaluations(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	groups := map[string][]Evaluation{}
	for _, e := range all {
		if value(in.ResourceType) != "" && e.ResourceType != value(in.ResourceType) || value(in.ResourceId) != "" && e.ResourceID != value(in.ResourceId) {
			continue
		}
		k := e.ResourceType + "\x00" + e.ResourceID
		groups[k] = append(groups[k], e)
	}
	rows := api.ComplianceByResources{}
	for _, k := range sortedRuleKeys(groups) {
		es := groups[k]
		c := complianceShape(es)
		if complianceMatches(in.ComplianceTypes, value(c.ComplianceType)) {
			rows = append(rows, api.ComplianceByResource{ResourceType: new(api.StringWithCharLimit256(es[0].ResourceType)), ResourceId: new(api.BaseResourceId(es[0].ResourceID)), Compliance: &c})
		}
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 100), 100, value(in.NextToken), ruleQuery(tx, "DescribeComplianceByResource", in.ResourceType, in.ResourceId, in.ComplianceTypes))
	return &api.DescribeComplianceByResourceOutput{ComplianceByResources: rows, NextToken: ruleString[api.NextToken](next)}, err
}
func (s *Service) getComplianceSummaryByConfigRule(tx Transaction, _ *api.GetComplianceSummaryByConfigRuleInput) (*api.GetComplianceSummaryByConfigRuleOutput, error) {
	rules, err := tx.Rules(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	evals, err := tx.Evaluations(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	groups := map[string][]Evaluation{}
	for _, r := range rules {
		groups[r.Name] = nil
	}
	for _, e := range evals {
		groups[e.RuleName] = append(groups[e.RuleName], e)
	}
	return &api.GetComplianceSummaryByConfigRuleOutput{ComplianceSummary: s.ruleSummary(groups)}, nil
}
func (s *Service) ruleSummary(groups map[string][]Evaluation) *api.ComplianceSummary {
	a, b := 0, 0
	for _, es := range groups {
		switch value(complianceShape(es).ComplianceType) {
		case "COMPLIANT":
			a++
		case "NON_COMPLIANT":
			b++
		}
	}
	now := s.clock.Now()
	return &api.ComplianceSummary{ComplianceSummaryTimestamp: &now, CompliantResourceCount: complianceCount(a), NonCompliantResourceCount: complianceCount(b)}
}
func (s *Service) getComplianceSummaryByResourceType(tx Transaction, in *api.GetComplianceSummaryByResourceTypeInput) (*api.GetComplianceSummaryByResourceTypeOutput, error) {
	all, err := tx.Evaluations(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	types := map[string]map[string][]Evaluation{}
	for _, e := range all {
		if len(in.ResourceTypes) > 0 && !slices.Contains(in.ResourceTypes, api.StringWithCharLimit256(e.ResourceType)) {
			continue
		}
		if types[e.ResourceType] == nil {
			types[e.ResourceType] = map[string][]Evaluation{}
		}
		types[e.ResourceType][e.ResourceID] = append(types[e.ResourceType][e.ResourceID], e)
	}
	out := &api.GetComplianceSummaryByResourceTypeOutput{ComplianceSummariesByResourceType: api.ComplianceSummariesByResourceType{}}
	for _, t := range sortedRuleKeys(types) {
		out.ComplianceSummariesByResourceType = append(out.ComplianceSummariesByResourceType, api.ComplianceSummaryByResourceType{ResourceType: new(api.StringWithCharLimit256(t)), ComplianceSummary: s.ruleSummary(types[t])})
	}
	return out, nil
}
func (s *Service) describeConfigRuleEvaluationStatus(tx Transaction, in *api.DescribeConfigRuleEvaluationStatusInput) (*api.DescribeConfigRuleEvaluationStatusOutput, error) {
	scope := scopeFor(tx.Context())
	rules, err := selectRules(tx, scope, in.ConfigRuleNames)
	if err != nil {
		return nil, err
	}
	runs, err := tx.EvaluationRuns()
	if err != nil {
		return nil, err
	}
	rows := api.ConfigRuleEvaluationStatusList{}
	for _, r := range rules {
		st := api.ConfigRuleEvaluationStatus{ConfigRuleName: new(api.ConfigRuleName(r.Name)), ConfigRuleId: new(api.String(r.ID)), ConfigRuleArn: new(api.String(r.ARN)), FirstActivatedTime: &r.CreatedAt, FirstEvaluationStarted: new(api.Boolean(false)), LastErrorCode: ruleString[api.String](r.ErrorCode), LastErrorMessage: ruleString[api.String](r.ErrorMessage)}
		if !r.LastEvaluation.IsZero() {
			st.LastSuccessfulEvaluationTime = &r.LastEvaluation
			st.FirstEvaluationStarted = new(api.Boolean(true))
		}
		for _, run := range runs {
			if run.Scope != scope || run.RuleName != r.Name || run.Status == "PENDING" || run.Status == "CANCELLED" {
				continue
			}
			st.FirstEvaluationStarted = new(api.Boolean(true))
			switch run.Status {
			case "SUCCEEDED", "NO_RESULTS":
				if r.Owner == "CUSTOM_LAMBDA" {
					setLatestRuleTime(&st.LastSuccessfulInvocationTime, run.CompletedAt)
				}
			case "FAILED":
				setLatestRuleTime(&st.LastFailedInvocationTime, run.CompletedAt)
			case "EXPIRED":
				setLatestRuleTime(&st.LastFailedEvaluationTime, run.CompletedAt)
			}
		}
		rows = append(rows, st)
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 25), 25, value(in.NextToken), ruleQuery(tx, "DescribeConfigRuleEvaluationStatus", in.ConfigRuleNames))
	return &api.DescribeConfigRuleEvaluationStatusOutput{ConfigRulesEvaluationStatus: rows, NextToken: ruleString[api.String](next)}, err
}
func setLatestRuleTime(target **time.Time, t time.Time) {
	if *target == nil || t.After(**target) {
		*target = &t
	}
}
func sortedRuleKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func ruleString[T ~string](v string) *T {
	if v == "" {
		return nil
	}
	return new(T(v))
}
func ruleLimit[T ~int32 | ~int64 | ~int](v *T, def int) int {
	if v == nil || *v == 0 {
		return def
	}
	return int(*v)
}
func ruleQuery(tx Reader, action string, parts ...any) string {
	data, _ := json.Marshal(struct {
		Scope  Scope
		Action string
		Parts  []any
	}{scopeFor(tx.Context()), action, parts})
	return string(data)
}
func rulePage[T any](items []T, limit, maxLimit int, token, query string) ([]T, string, error) {
	if limit < 1 || limit > maxLimit {
		return nil, "", failure("InvalidLimitException", "Limit is outside the supported range")
	}
	start := 0
	if token != "" {
		data, err := base64.RawURLEncoding.DecodeString(token)
		var cursor struct {
			Query  string
			Offset int
		}
		if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Query != query || cursor.Offset < 0 || cursor.Offset > len(items) {
			return nil, "", failure("InvalidNextTokenException", "The pagination token is invalid")
		}
		start = cursor.Offset
	}
	end := min(start+limit, len(items))
	next := ""
	if end < len(items) {
		data, _ := json.Marshal(struct {
			Query  string
			Offset int
		}{query, end})
		next = base64.RawURLEncoding.EncodeToString(data)
	}
	return items[start:end], next, nil
}
