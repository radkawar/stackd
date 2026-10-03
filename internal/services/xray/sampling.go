package xray

import (
	"errors"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/xray"
)

const samplingRuleLimit = 25

// defaultSamplingRule is virtual until its mutable reservoir or rate is changed.
func defaultSamplingRule(scope Scope) SamplingRuleRecord {
	return SamplingRuleRecord{Key: SamplingRuleKey{Scope: scope, Name: "Default"}, Priority: 10000, FixedRate: .05, ReservoirSize: 1, Host: "*", HTTPMethod: "*", ResourceARN: "*", ServiceName: "*", ServiceType: "*", URLPath: "*", Attributes: map[string]string{}, Tags: map[string]string{}, Created: time.Unix(0, 0).UTC(), Modified: time.Unix(0, 0).UTC()}
}

func samplingRule(r Reader, key SamplingRuleKey) (SamplingRuleRecord, error) {
	row, err := r.SamplingRule(key)
	if errors.Is(err, ErrNotFound) && key.Name == "Default" {
		return defaultSamplingRule(key.Scope), nil
	}
	return row, err
}

func samplingRuleKey(scope Scope, name, arn string) (SamplingRuleKey, error) {
	key := SamplingRuleKey{Scope: scope, Name: name}
	if name != "" && arn != "" {
		return key, failure("InvalidRequestException", "Request cannot contain both sampling rule name and sampling rule ARN")
	}
	if name == "" && arn == "" {
		return key, failure("InvalidRequestException", "Request must contain either sampling rule name or sampling rule ARN")
	}
	if arn != "" {
		prefix := SamplingRuleKey{Scope: scope}.ARN()
		if !strings.HasPrefix(arn, prefix) {
			return key, failure("InvalidRequestException", "Invalid sampling rule ARN")
		}
		key.Name = strings.TrimPrefix(arn, prefix)
	}
	if length := utf8.RuneCountInString(key.Name); length < 1 || length > 32 {
		return key, failure("InvalidRequestException", "Invalid sampling rule name")
	}
	return key, nil
}

func samplingRuleOutput(row SamplingRuleRecord) api.SamplingRuleRecord {
	attributes := make(api.AttributeMap, len(row.Attributes))
	for k, v := range row.Attributes {
		attributes[api.AttributeKey(k)] = api.AttributeValue(v)
	}
	return api.SamplingRuleRecord{CreatedAt: new(row.Created), ModifiedAt: new(row.Modified), SamplingRule: &api.SamplingRule{
		RuleName: new(api.RuleName(row.Key.Name)), RuleARN: new(api.String(row.Key.ARN())), Version: new(api.Version(1)),
		Priority: new(api.Priority(row.Priority)), FixedRate: new(api.FixedRate(row.FixedRate)), ReservoirSize: new(api.ReservoirSize(row.ReservoirSize)),
		Host: new(api.Host(row.Host)), HTTPMethod: new(api.HTTPMethod(row.HTTPMethod)), ResourceARN: new(api.ResourceARN(row.ResourceARN)),
		ServiceName: new(api.ServiceName(row.ServiceName)), ServiceType: new(api.ServiceType(row.ServiceType)), URLPath: new(api.URLPath(row.URLPath)), Attributes: attributes, SamplingRateBoost: row.RateBoost,
	}}
}

func samplingAttributes(in api.AttributeMap) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[string(k)] = string(v)
	}
	return out
}

func (s *Service) createSamplingRule(tx Transaction, in *api.CreateSamplingRuleRequest) (*api.CreateSamplingRuleResult, error) {
	input := in.SamplingRule
	key, err := samplingRuleKey(scopeFor(tx.Context()), value(input.RuleName), value(input.RuleARN))
	if err != nil {
		return nil, err
	}
	tags, err := validateTags(in.Tags)
	if err != nil {
		return nil, err
	}
	context := tagContext(nil, tags, nil)
	request := authorization.Request{Action: "xray:CreateSamplingRule", ResourceARN: key.ARN(), Context: context, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}}
	if err := s.authorizeResource(tx, request); err != nil {
		return nil, err
	}
	if len(tags) != 0 {
		request.Action = "xray:TagResource"
		if err := s.authorizeResource(tx, request); err != nil {
			return nil, err
		}
	}
	if *input.Version != 1 {
		return nil, failure("InvalidRequestException", "Sampling rule version must be 1")
	}
	if _, err := samplingRule(tx, key); err == nil {
		return nil, failure("InvalidRequestException", "Sampling rule already exists")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	rows, err := tx.SamplingRules(key.Scope)
	if err != nil {
		return nil, err
	}
	count := 0
	for _, row := range rows {
		if row.Key.Name != "Default" {
			count++
		}
	}
	if count >= samplingRuleLimit {
		return nil, failure("RuleLimitExceededException", "The maximum number of custom sampling rules has been reached.")
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	row := SamplingRuleRecord{Key: key, Priority: int32(*input.Priority), FixedRate: float64(*input.FixedRate), ReservoirSize: int32(*input.ReservoirSize), Host: value(input.Host), HTTPMethod: value(input.HTTPMethod), ResourceARN: value(input.ResourceARN), ServiceName: value(input.ServiceName), ServiceType: value(input.ServiceType), URLPath: value(input.URLPath), Attributes: samplingAttributes(input.Attributes), RateBoost: input.SamplingRateBoost, Tags: tags, Created: now, Modified: now}
	if err := validateSamplingRule(row); err != nil {
		return nil, err
	}
	if err := tx.PutSamplingRule(row); err != nil {
		return nil, err
	}
	if err := tx.SetSamplingModified(key.Scope, now); err != nil {
		return nil, err
	}
	result := samplingRuleOutput(row)
	return &api.CreateSamplingRuleResult{SamplingRuleRecord: &result}, nil
}

func validateSamplingRule(row SamplingRuleRecord) error {
	// Updates use unconstrained NullableInteger/NullableDouble Smithy members.
	if row.ReservoirSize < 0 || row.FixedRate < 0 || row.FixedRate > 1 || math.IsNaN(row.FixedRate) || math.IsInf(row.FixedRate, 0) || len(row.Attributes) > 5 || row.Priority < 1 || row.Priority > 9999 && row.Key.Name != "Default" {
		return failure("InvalidRequestException", "Invalid update request for sampling rule")
	}
	return nil
}

func (s *Service) updateSamplingRule(tx Transaction, in *api.UpdateSamplingRuleRequest) (*api.UpdateSamplingRuleResult, error) {
	input := in.SamplingRuleUpdate
	key, err := samplingRuleKey(scopeFor(tx.Context()), value(input.RuleName), value(input.RuleARN))
	if err != nil {
		return nil, err
	}
	row, err := samplingRule(tx, key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if authErr := s.authorizeResource(tx, authorization.Request{Action: "xray:UpdateSamplingRule", ResourceARN: key.ARN(), Context: tagContext(row.Tags, nil, nil)}); authErr != nil {
		return nil, authErr
	}
	if err != nil {
		return nil, failure("InvalidRequestException", "Sampling rule does not exist")
	}
	if key.Name == "Default" && (input.Priority != nil || input.Host != nil || input.HTTPMethod != nil || input.ResourceARN != nil || input.ServiceName != nil || input.ServiceType != nil || input.URLPath != nil || input.Attributes != nil || input.SamplingRateBoost != nil) {
		return nil, failure("InvalidRequestException", "Only the reservoir size and fixed rate of the default sampling rule can be modified")
	}
	if input.FixedRate != nil {
		row.FixedRate = float64(*input.FixedRate)
	}
	if input.ReservoirSize != nil {
		row.ReservoirSize = int32(*input.ReservoirSize)
	}
	if input.Priority != nil {
		row.Priority = int32(*input.Priority)
	}
	if input.Host != nil {
		row.Host = value(input.Host)
	}
	if input.HTTPMethod != nil {
		row.HTTPMethod = value(input.HTTPMethod)
	}
	if input.ResourceARN != nil {
		row.ResourceARN = value(input.ResourceARN)
	}
	if input.ServiceName != nil {
		row.ServiceName = value(input.ServiceName)
	}
	if input.ServiceType != nil {
		row.ServiceType = value(input.ServiceType)
	}
	if input.URLPath != nil {
		row.URLPath = value(input.URLPath)
	}
	if input.Attributes != nil {
		row.Attributes = samplingAttributes(input.Attributes)
	}
	hadBoost := row.RateBoost != nil
	// Unlike omitted Attributes, native omitted/null boost configuration clears it.
	row.RateBoost = input.SamplingRateBoost
	if err := validateSamplingRule(row); err != nil {
		return nil, err
	}
	row.Modified = s.clock.Now().UTC().Truncate(time.Second)
	if err := tx.PutSamplingRule(row); err != nil {
		return nil, err
	}
	if hadBoost && row.RateBoost == nil {
		boost, err := tx.SamplingBoost(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err == nil {
			boost.Expires = row.Modified
			if err := tx.PutSamplingBoost(boost); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.SetSamplingModified(key.Scope, row.Modified); err != nil {
		return nil, err
	}
	result := samplingRuleOutput(row)
	return &api.UpdateSamplingRuleResult{SamplingRuleRecord: &result}, nil
}

func (s *Service) deleteSamplingRule(tx Transaction, in *api.DeleteSamplingRuleRequest) (*api.DeleteSamplingRuleResult, error) {
	key, err := samplingRuleKey(scopeFor(tx.Context()), value(in.RuleName), value(in.RuleARN))
	if err != nil {
		return nil, err
	}
	row, err := samplingRule(tx, key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if authErr := s.authorizeResource(tx, authorization.Request{Action: "xray:DeleteSamplingRule", ResourceARN: key.ARN(), Context: tagContext(row.Tags, nil, nil)}); authErr != nil {
		return nil, authErr
	}
	if key.Name == "Default" {
		return nil, failure("InvalidRequestException", "The default sampling rule cannot be deleted")
	}
	if err != nil {
		return nil, failure("InvalidRequestException", "Sampling rule does not exist")
	}
	if err := tx.DeleteSamplingRule(key); err != nil {
		return nil, err
	}
	if err := tx.SetSamplingModified(key.Scope, s.clock.Now().UTC().Truncate(time.Second)); err != nil {
		return nil, err
	}
	result := samplingRuleOutput(row)
	return &api.DeleteSamplingRuleResult{SamplingRuleRecord: &result}, nil
}

func (s *Service) getSamplingRules(tx Transaction, _ *api.GetSamplingRulesRequest) (*api.GetSamplingRulesResult, error) {
	if err := s.authorizeResource(tx, authorization.Request{Action: "xray:GetSamplingRules", ResourceARN: "*"}); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	rows, err := tx.SamplingRules(scope)
	if err != nil {
		return nil, err
	}
	foundDefault := false
	for _, row := range rows {
		foundDefault = foundDefault || row.Key.Name == "Default"
	}
	if !foundDefault {
		rows = append(rows, defaultSamplingRule(scope))
	}
	slices.SortFunc(rows, func(a, b SamplingRuleRecord) int {
		if a.Key.Name == b.Key.Name {
			return 0
		}
		if a.Key.Name == "Default" {
			return 1
		}
		if b.Key.Name == "Default" {
			return -1
		}
		return strings.Compare(a.Key.Name, b.Key.Name)
	})
	// The regional quota bounds this complete page to 26 records. Native ignores
	// arbitrary NextToken values; no synthetic continuation is needed at this limit.
	out := &api.GetSamplingRulesResult{SamplingRuleRecords: api.SamplingRuleRecordList{}}
	for _, row := range rows {
		out.SamplingRuleRecords = append(out.SamplingRuleRecords, samplingRuleOutput(row))
	}
	return out, nil
}
