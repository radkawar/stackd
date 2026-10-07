package wafv2

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/wafv2"
	"stackd/internal/awswire"
)

// AWS WAF API Reference constraints for entity names, metric names and labels.
var (
	entityName     = regexp.MustCompile(`^[\w\-]{1,128}$`)
	metricName     = regexp.MustCompile(`^[\w#:\.\-/]{1,255}$`)
	headerName     = regexp.MustCompile(`^[a-zA-Z0-9\-]{1,255}$`)
	customHeader   = regexp.MustCompile(`^[a-zA-Z0-9._$-]{1,64}$`)
	labelComponent = regexp.MustCompile(`^[0-9A-Za-z_\-]{1,128}$`)
)

// maxWebACLCapacity is the AWS WAF web ACL capacity unit (WCU) maximum.
const maxWebACLCapacity = 5000

var reservedLabelWords = []string{"awswaf", "aws", "waf", "rulegroup", "webacl", "regexpatternset", "ipset", "managed"}

// supportedTransformations implement the documented AWS WAF text
// transformations whose semantics are fully specified. CSS_DECODE, JS_DECODE,
// JS_DECODE_EXT and UTF8_TO_UNICODE are rejected rather than approximated.
var supportedTransformations = map[api.TextTransformationType]bool{
	"NONE": true, "LOWERCASE": true, "UPPERCASE": true, "URL_DECODE": true, "URL_DECODE_UNI": true,
	"BASE64_DECODE": true, "BASE64_DECODE_EXT": true, "HEX_DECODE": true, "MD5": true, "SHA256": true,
	"CMD_LINE": true, "CMD_LINE_UNIX": true, "CMD_LINE_WIN": true, "COMPRESS_WHITE_SPACE": true,
	"HTML_ENTITY_DECODE": true, "NORMALIZE_PATH": true, "NORMALIZE_PATH_WIN": true,
	"REMOVE_COMMENTS_CHAR": true, "REMOVE_NULLS": true, "REMOVE_WHITESPACE": true, "REPLACE_COMMENTS": true,
	"REPLACE_NULLS": true, "SQL_HEX_DECODE": true, "TRIM": true, "TRIM_LEFT": true, "TRIM_RIGHT": true,
	"ESCAPE_SEQ_DECODE": true,
}

// definitionInput carries every web ACL configuration member of Create and
// Update so unsupported members are rejected by name instead of stored inertly.
type definitionInput struct {
	DefaultAction                *api.DefaultAction
	Rules                        api.Rules
	VisibilityConfig             *api.VisibilityConfig
	CustomResponseBodies         api.CustomResponseBodies
	AssociationConfig            *api.AssociationConfig
	ApplicationConfig            *api.ApplicationConfig
	CaptchaConfig                *api.CaptchaConfig
	ChallengeConfig              *api.ChallengeConfig
	DataProtectionConfig         *api.DataProtectionConfig
	MonetizationConfig           *api.MonetizationConfig
	OnSourceDDoSProtectionConfig *api.OnSourceDDoSProtectionConfig
	TokenDomains                 api.TokenDomains
}

type admission struct {
	r      Reader
	scope  Scope
	ipSets map[string]bool
}

func unsupported(path, reason string) *awswire.Error {
	return invalidParameter("", path, path+" is not supported: "+reason)
}

// admitDefinition validates a web ACL definition, returning it with its
// capacity and the IP set ARNs it references.
func admitDefinition(r Reader, sc Scope, in definitionInput) (Definition, int64, []string, error) {
	for name, set := range map[string]bool{
		"ApplicationConfig":            in.ApplicationConfig != nil,
		"CaptchaConfig":                in.CaptchaConfig != nil,
		"ChallengeConfig":              in.ChallengeConfig != nil,
		"DataProtectionConfig":         in.DataProtectionConfig != nil,
		"MonetizationConfig":           in.MonetizationConfig != nil,
		"OnSourceDDoSProtectionConfig": in.OnSourceDDoSProtectionConfig != nil,
		"TokenDomains":                 len(in.TokenDomains) > 0,
	} {
		if set {
			return Definition{}, 0, nil, unsupported(name, "CAPTCHA/Challenge token handling, logging data protection, application integration, monetization and ALB DDoS protection have no implemented effect")
		}
	}
	if in.DefaultAction == nil {
		return Definition{}, 0, nil, invalidParameter("DEFAULT_ACTION", "DefaultAction", "DefaultAction is required")
	}
	if in.VisibilityConfig == nil {
		return Definition{}, 0, nil, invalidParameter("VISIBILITY_CONFIG", "VisibilityConfig", "VisibilityConfig is required")
	}
	if err := validateBodies(in.CustomResponseBodies); err != nil {
		return Definition{}, 0, nil, err
	}
	bodies := in.CustomResponseBodies
	if bodies == nil {
		bodies = api.CustomResponseBodies{}
	}
	if err := validateDefaultAction(*in.DefaultAction, bodies); err != nil {
		return Definition{}, 0, nil, err
	}
	if err := validateVisibility("VisibilityConfig", *in.VisibilityConfig); err != nil {
		return Definition{}, 0, nil, err
	}
	if err := validateAssociationConfig(in.AssociationConfig); err != nil {
		return Definition{}, 0, nil, err
	}
	a := &admission{r: r, scope: sc, ipSets: map[string]bool{}}
	capacity, err := a.rules(in.Rules, bodies)
	if err != nil {
		return Definition{}, 0, nil, err
	}
	if capacity > maxWebACLCapacity {
		return Definition{}, 0, nil, failure("WAFLimitsExceededException", fmt.Sprintf("The web ACL requires %d WCUs, above the %d WCU maximum", capacity, maxWebACLCapacity), 400)
	}
	refs := make([]string, 0, len(a.ipSets))
	for arn := range a.ipSets {
		refs = append(refs, arn)
	}
	slices.Sort(refs)
	d := Definition{DefaultAction: *in.DefaultAction, Rules: in.Rules, VisibilityConfig: *in.VisibilityConfig, CustomResponseBodies: in.CustomResponseBodies, AssociationConfig: in.AssociationConfig}
	return d, capacity, refs, nil
}

func validateBodies(bodies api.CustomResponseBodies) error {
	for key, body := range bodies {
		if !entityName.MatchString(string(key)) {
			return invalidParameter("CUSTOM_RESPONSE_BODY_KEY", string(key), "Custom response body keys must match ^[\\w\\-]+$")
		}
		content := value(body.Content)
		if len(content) == 0 || len(content) > 10240 {
			return invalidParameter("CUSTOM_RESPONSE_BODY", string(key), "Custom response body content must contain 1-10240 bytes")
		}
		switch value(body.ContentType) {
		case "TEXT_PLAIN", "TEXT_HTML":
		case "APPLICATION_JSON":
			if !json.Valid([]byte(content)) {
				return invalidParameter("CUSTOM_RESPONSE_BODY", string(key), "APPLICATION_JSON custom response body content must be valid JSON")
			}
		default:
			return invalidParameter("CUSTOM_RESPONSE_BODY", string(key), "ContentType must be TEXT_PLAIN, TEXT_HTML or APPLICATION_JSON")
		}
	}
	return nil
}

func validateDefaultAction(v api.DefaultAction, bodies api.CustomResponseBodies) error {
	switch {
	case v.Allow != nil && v.Block == nil:
		return validateRequestHandling("DefaultAction.Allow", v.Allow.CustomRequestHandling)
	case v.Block != nil && v.Allow == nil:
		return validateCustomResponse("DefaultAction.Block", v.Block.CustomResponse, bodies)
	default:
		return invalidParameter("DEFAULT_ACTION", "DefaultAction", "DefaultAction must specify exactly one of Allow or Block")
	}
}

func validateRequestHandling(path string, v *api.CustomRequestHandling) error {
	if v == nil {
		return nil
	}
	if len(v.InsertHeaders) == 0 {
		return invalidParameter("CUSTOM_REQUEST_HANDLING", path, path+".CustomRequestHandling requires InsertHeaders")
	}
	seen := map[string]bool{}
	for _, h := range v.InsertHeaders {
		name := strings.ToLower(value(h.Name))
		if !customHeader.MatchString(name) || len(value(h.Value)) > 255 {
			return invalidParameter("CUSTOM_REQUEST_HANDLING", path, "Inserted header names must match ^[a-zA-Z0-9._$-]+$ and values must not exceed 255 characters")
		}
		if seen[name] {
			return invalidParameter("CUSTOM_REQUEST_HANDLING", path, "Inserted header names must be unique")
		}
		seen[name] = true
	}
	return nil
}

func validateCustomResponse(path string, v *api.CustomResponse, bodies api.CustomResponseBodies) error {
	if v == nil {
		return nil
	}
	code := int32(0)
	if v.ResponseCode != nil {
		code = int32(*v.ResponseCode)
	}
	if code < 200 || code > 599 {
		return invalidParameter("CUSTOM_RESPONSE", path, path+".CustomResponse.ResponseCode must be between 200 and 599")
	}
	// CheckCapacity supplies nil bodies: it has no CustomResponseBodies input.
	if key := value(v.CustomResponseBodyKey); key != "" && bodies != nil {
		if _, ok := bodies[api.EntityName(key)]; !ok {
			return invalidParameter("CUSTOM_RESPONSE", key, "CustomResponseBodyKey "+key+" is not defined in CustomResponseBodies")
		}
	}
	for _, h := range v.ResponseHeaders {
		if !customHeader.MatchString(value(h.Name)) || len(value(h.Value)) > 255 {
			return invalidParameter("CUSTOM_RESPONSE", path, "Custom response header names must match ^[a-zA-Z0-9._$-]+$ and values must not exceed 255 characters")
		}
	}
	return nil
}

func validateVisibility(path string, v api.VisibilityConfig) error {
	if v.CloudWatchMetricsEnabled == nil || v.SampledRequestsEnabled == nil {
		return invalidParameter("VISIBILITY_CONFIG", path, path+" requires CloudWatchMetricsEnabled and SampledRequestsEnabled")
	}
	name := value(v.MetricName)
	if !metricName.MatchString(name) || name == "All" || name == "Default_Action" {
		return invalidParameter("METRIC_NAME", name, path+".MetricName must match ^[\\w#:\\.\\-/]+$, contain 1-255 characters and not be All or Default_Action")
	}
	return nil
}

func validateAssociationConfig(v *api.AssociationConfig) error {
	if v == nil {
		return nil
	}
	for kind, config := range v.RequestBody {
		if kind != "API_GATEWAY" {
			return unsupported("AssociationConfig.RequestBody."+string(kind), "only API Gateway REST stages can be associated")
		}
		switch value(config.DefaultSizeInspectionLimit) {
		case "KB_16", "KB_32", "KB_48", "KB_64":
		default:
			return invalidParameter("ASSOCIATION_CONFIG", "DefaultSizeInspectionLimit", "DefaultSizeInspectionLimit must be KB_16, KB_32, KB_48 or KB_64")
		}
	}
	return nil
}

func (a *admission) rules(rules api.Rules, bodies api.CustomResponseBodies) (int64, error) {
	names, priorities := map[string]bool{}, map[int32]bool{}
	var total int64
	for i, rule := range rules {
		path := "Rules[" + strconv.Itoa(i) + "]"
		name := value(rule.Name)
		if !entityName.MatchString(name) {
			return 0, invalidParameter("RULE", name, path+".Name must match ^[\\w\\-]+$ and contain 1-128 characters")
		}
		if names[name] {
			return 0, failure("WAFDuplicateItemException", "Rule names must be unique within a web ACL: "+name, 400)
		}
		names[name] = true
		if rule.Priority == nil || *rule.Priority < 0 {
			return 0, invalidParameter("RULE_PRIORITY", name, path+".Priority must be a non-negative integer")
		}
		if priorities[int32(*rule.Priority)] {
			return 0, invalidParameter("RULE_PRIORITY", name, "Rule priorities must be unique within a web ACL")
		}
		priorities[int32(*rule.Priority)] = true
		if rule.VisibilityConfig == nil {
			return 0, invalidParameter("VISIBILITY_CONFIG", name, path+".VisibilityConfig is required")
		}
		if err := validateVisibility(path+".VisibilityConfig", *rule.VisibilityConfig); err != nil {
			return 0, err
		}
		if rule.CaptchaConfig != nil || rule.ChallengeConfig != nil {
			return 0, unsupported(path+".CaptchaConfig/ChallengeConfig", "CAPTCHA and Challenge actions are not implemented")
		}
		if rule.OverrideAction != nil {
			return 0, invalidParameter("OVERRIDE_ACTION", name, path+".OverrideAction applies only to rule group statements; use Action")
		}
		if rule.Statement == nil {
			return 0, invalidParameter("STATEMENT", name, path+".Statement is required")
		}
		rate := rule.Statement.RateBasedStatement != nil
		if err := validateRuleAction(path, rule.Action, rate, bodies); err != nil {
			return 0, err
		}
		if err := validateLabels(path, rule.RuleLabels); err != nil {
			return 0, err
		}
		cost, err := a.statement(path+".Statement", rule.Statement, true)
		if err != nil {
			return 0, err
		}
		total += cost
	}
	return total, nil
}

func validateRuleAction(path string, v *api.RuleAction, rate bool, bodies api.CustomResponseBodies) error {
	if v == nil {
		return invalidParameter("RULE_ACTION", path, path+".Action is required")
	}
	if v.Captcha != nil || v.Challenge != nil || v.Monetize != nil {
		return unsupported(path+".Action", "CAPTCHA, Challenge and Monetize actions are not implemented")
	}
	set := 0
	for _, present := range []bool{v.Allow != nil, v.Block != nil, v.Count != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return invalidParameter("RULE_ACTION", path, path+".Action must specify exactly one of Allow, Block or Count")
	}
	switch {
	case v.Allow != nil:
		if rate {
			return invalidParameter("RULE_ACTION", path, "Rate-based rules can't use the Allow action")
		}
		return validateRequestHandling(path+".Action.Allow", v.Allow.CustomRequestHandling)
	case v.Count != nil:
		return validateRequestHandling(path+".Action.Count", v.Count.CustomRequestHandling)
	default:
		return validateCustomResponse(path+".Action.Block", v.Block.CustomResponse, bodies)
	}
}

func validateLabels(path string, labels api.Labels) error {
	for _, label := range labels {
		parts := strings.Split(value(label.Name), ":")
		if len(parts) > 6 {
			return invalidParameter("LABEL", value(label.Name), path+".RuleLabels may specify at most five namespaces")
		}
		for _, part := range parts {
			if !labelComponent.MatchString(part) || slices.Contains(reservedLabelWords, part) {
				return invalidParameter("LABEL", value(label.Name), "Label namespaces and names must contain 1-128 letters, digits, underscores or hyphens and not be reserved words")
			}
		}
	}
	return nil
}

// statement validates one statement and returns its WCU cost, per the
// AWS WAF Developer Guide rule statement pages.
func (a *admission) statement(path string, s *api.Statement, top bool) (int64, error) {
	if s == nil {
		return 0, invalidParameter("STATEMENT", path, path+" is required")
	}
	set := 0
	for _, present := range []bool{s.AndStatement != nil, s.AsnMatchStatement != nil, s.ByteMatchStatement != nil, s.GeoMatchStatement != nil, s.IPSetReferenceStatement != nil, s.LabelMatchStatement != nil, s.ManagedRuleGroupStatement != nil, s.NotStatement != nil, s.OrStatement != nil, s.RateBasedStatement != nil, s.RegexMatchStatement != nil, s.RegexPatternSetReferenceStatement != nil, s.RuleGroupReferenceStatement != nil, s.SizeConstraintStatement != nil, s.SqliMatchStatement != nil, s.XssMatchStatement != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return 0, invalidParameter("STATEMENT", path, path+" must specify exactly one statement type")
	}
	switch {
	case s.AndStatement != nil:
		return a.logical(path+".AndStatement", s.AndStatement.Statements)
	case s.OrStatement != nil:
		return a.logical(path+".OrStatement", s.OrStatement.Statements)
	case s.NotStatement != nil:
		return a.statement(path+".NotStatement.Statement", s.NotStatement.Statement, false)
	case s.ByteMatchStatement != nil:
		return a.byteMatch(path+".ByteMatchStatement", s.ByteMatchStatement)
	case s.RegexMatchStatement != nil:
		v := s.RegexMatchStatement
		pattern := value(v.RegexString)
		if len(pattern) == 0 || len(pattern) > 512 {
			return 0, invalidParameter("REGEX_STRING", path, path+".RegexString must contain 1-512 characters")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return 0, invalidParameter("REGEX_STRING", pattern, "Invalid regular expression (AWS WAF does not support backreferences or lookaround): "+err.Error())
		}
		return a.inspected(path+".RegexMatchStatement", 3, v.FieldToMatch, v.TextTransformations, v.PreParseTextTransformations, false)
	case s.SizeConstraintStatement != nil:
		v := s.SizeConstraintStatement
		switch value(v.ComparisonOperator) {
		case "EQ", "NE", "LE", "LT", "GE", "GT":
		default:
			return 0, invalidParameter("COMPARISON_OPERATOR", path, path+".ComparisonOperator must be EQ, NE, LE, LT, GE or GT")
		}
		if v.Size == nil || *v.Size < 0 || *v.Size > 21474836480 {
			return 0, invalidParameter("SIZE", path, path+".Size must be between 0 and 21474836480")
		}
		return a.inspected(path+".SizeConstraintStatement", 1, v.FieldToMatch, v.TextTransformations, v.PreParseTextTransformations, false)
	case s.IPSetReferenceStatement != nil:
		return a.ipSetReference(path+".IPSetReferenceStatement", s.IPSetReferenceStatement)
	case s.LabelMatchStatement != nil:
		v := s.LabelMatchStatement
		key := value(v.Key)
		if len(key) == 0 || len(key) > 1024 {
			return 0, invalidParameter("LABEL_MATCH_KEY", path, path+".Key must contain 1-1024 characters")
		}
		switch value(v.Scope) {
		case "LABEL":
			if strings.HasSuffix(key, ":") {
				return 0, invalidParameter("LABEL_MATCH_KEY", key, "A LABEL match key must end with the label name")
			}
		case "NAMESPACE":
			if !strings.HasSuffix(key, ":") {
				return 0, invalidParameter("LABEL_MATCH_KEY", key, "A NAMESPACE match key must end with a colon")
			}
		default:
			return 0, invalidParameter("LABEL_MATCH_SCOPE", path, path+".Scope must be LABEL or NAMESPACE")
		}
		return 1, nil
	case s.RateBasedStatement != nil:
		if !top {
			return 0, invalidParameter("STATEMENT", path, "A RateBasedStatement can't be nested inside another statement")
		}
		return a.rateBased(path+".RateBasedStatement", s.RateBasedStatement)
	case s.GeoMatchStatement != nil:
		return 0, unsupported(path+".GeoMatchStatement", "no geolocation database owner is available")
	case s.AsnMatchStatement != nil:
		return 0, unsupported(path+".AsnMatchStatement", "no autonomous system database owner is available")
	case s.ManagedRuleGroupStatement != nil:
		return 0, unsupported(path+".ManagedRuleGroupStatement", "vendor-managed rule group contents are not available")
	case s.RuleGroupReferenceStatement != nil:
		return 0, unsupported(path+".RuleGroupReferenceStatement", "rule groups are not implemented")
	case s.RegexPatternSetReferenceStatement != nil:
		return 0, unsupported(path+".RegexPatternSetReferenceStatement", "regex pattern sets are not implemented; use RegexMatchStatement")
	case s.SqliMatchStatement != nil:
		return 0, unsupported(path+".SqliMatchStatement", "the AWS SQL injection detection engine is not available")
	default:
		return 0, unsupported(path+".XssMatchStatement", "the AWS cross-site scripting detection engine is not available")
	}
}

func (a *admission) logical(path string, statements api.Statements) (int64, error) {
	if len(statements) < 2 {
		return 0, invalidParameter("STATEMENT", path, path+".Statements requires at least two statements")
	}
	var total int64
	for i := range statements {
		cost, err := a.statement(path+".Statements["+strconv.Itoa(i)+"]", &statements[i], false)
		if err != nil {
			return 0, err
		}
		total += cost
	}
	return total, nil
}

func (a *admission) byteMatch(path string, v *api.ByteMatchStatement) (int64, error) {
	if len(v.SearchString) == 0 || len(v.SearchString) > 200 {
		return 0, invalidParameter("BYTE_MATCH_STATEMENT", path, path+".SearchString must contain 1-200 bytes")
	}
	base := int64(2)
	switch value(v.PositionalConstraint) {
	case "EXACTLY", "STARTS_WITH", "ENDS_WITH":
	case "CONTAINS":
		base = 10
	case "CONTAINS_WORD":
		base = 10
		for _, c := range v.SearchString {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
				return 0, invalidParameter("POSITIONAL_CONSTRAINT", path, "CONTAINS_WORD search strings may contain only alphanumeric characters and underscores")
			}
		}
	default:
		return 0, invalidParameter("POSITIONAL_CONSTRAINT", path, path+".PositionalConstraint must be EXACTLY, STARTS_WITH, ENDS_WITH, CONTAINS or CONTAINS_WORD")
	}
	return a.inspected(path, base, v.FieldToMatch, v.TextTransformations, v.PreParseTextTransformations, value(v.PositionalConstraint) == "EXACTLY")
}

func (a *admission) inspected(path string, base int64, field *api.FieldToMatch, transformations api.TextTransformations, preparse api.PreParseTextTransformations, exact bool) (int64, error) {
	if len(preparse) > 0 {
		return 0, unsupported(path+".PreParseTextTransformations", "pre-parse transformations are not implemented")
	}
	cost, err := validateField(path+".FieldToMatch", field, base, exact)
	if err != nil {
		return 0, err
	}
	if len(transformations) == 0 || len(transformations) > 10 {
		return 0, invalidParameter("TEXT_TRANSFORMATION", path, path+".TextTransformations must contain 1-10 transformations")
	}
	priorities := map[int32]bool{}
	for _, t := range transformations {
		if t.Priority == nil || t.Type == nil {
			return 0, invalidParameter("TEXT_TRANSFORMATION", path, "Text transformations require Priority and Type")
		}
		if priorities[int32(*t.Priority)] {
			return 0, invalidParameter("TEXT_TRANSFORMATION", path, "Text transformation priorities must be unique")
		}
		priorities[int32(*t.Priority)] = true
		if !supportedTransformations[*t.Type] {
			return 0, unsupported(path+".TextTransformations."+string(*t.Type), "this transformation's decoding semantics are not implemented")
		}
		if *t.Type != "NONE" {
			cost += 10
		}
	}
	return cost, nil
}

func validOversize(v *api.OversizeHandling, required bool) bool {
	if v == nil {
		return !required
	}
	return *v == "CONTINUE" || *v == "MATCH" || *v == "NO_MATCH"
}
func validFallback(v *api.FallbackBehavior) bool {
	return v != nil && (*v == "MATCH" || *v == "NO_MATCH")
}

func validateField(path string, f *api.FieldToMatch, base int64, exact bool) (int64, error) {
	if f == nil {
		return 0, invalidParameter("FIELD_TO_MATCH", path, path+" is required")
	}
	set := 0
	for _, present := range []bool{f.AllQueryArguments != nil, f.Body != nil, f.Cookies != nil, f.HeaderOrder != nil, f.Headers != nil, f.JA3Fingerprint != nil, f.JA4Fingerprint != nil, f.JsonBody != nil, f.Method != nil, f.QueryString != nil, f.SingleHeader != nil, f.SingleQueryArgument != nil, f.UriFragment != nil, f.UriPath != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return 0, invalidParameter("FIELD_TO_MATCH", path, path+" must specify exactly one request component")
	}
	switch {
	case f.SingleHeader != nil:
		if name := strings.TrimSpace(value(f.SingleHeader.Name)); name == "" || len(name) > 64 {
			return 0, invalidParameter("SINGLE_HEADER", path, path+".SingleHeader.Name must contain 1-64 characters")
		}
	case f.SingleQueryArgument != nil:
		if name := value(f.SingleQueryArgument.Name); name == "" || len(name) > 30 {
			return 0, invalidParameter("SINGLE_QUERY_ARGUMENT", path, path+".SingleQueryArgument.Name must contain 1-30 characters")
		}
	case f.AllQueryArguments != nil:
		base += 10
	case f.Body != nil:
		if !validOversize(f.Body.OversizeHandling, false) {
			return 0, invalidParameter("OVERSIZE_HANDLING", path, "Body.OversizeHandling must be CONTINUE, MATCH or NO_MATCH")
		}
	case f.JsonBody != nil:
		v := f.JsonBody
		if v.MatchPattern == nil || (v.MatchPattern.All != nil) == (len(v.MatchPattern.IncludedPaths) > 0) {
			return 0, invalidParameter("JSON_MATCH_PATTERN", path, "JsonBody.MatchPattern must specify exactly one of All or IncludedPaths")
		}
		for _, p := range v.MatchPattern.IncludedPaths {
			if p != "" && !strings.HasPrefix(string(p), "/") {
				return 0, invalidParameter("JSON_POINTER", string(p), "JsonBody included paths must be JSON Pointers")
			}
		}
		switch value(v.MatchScope) {
		case "ALL", "KEY", "VALUE":
		default:
			return 0, invalidParameter("JSON_MATCH_SCOPE", path, "JsonBody.MatchScope must be ALL, KEY or VALUE")
		}
		if fb := v.InvalidFallbackBehavior; fb != nil && *fb != "MATCH" && *fb != "NO_MATCH" && *fb != "EVALUATE_AS_STRING" {
			return 0, invalidParameter("BODY_PARSING_FALLBACK_BEHAVIOR", path, "JsonBody.InvalidFallbackBehavior must be MATCH, NO_MATCH or EVALUATE_AS_STRING")
		}
		if !validOversize(v.OversizeHandling, false) {
			return 0, invalidParameter("OVERSIZE_HANDLING", path, "JsonBody.OversizeHandling must be CONTINUE, MATCH or NO_MATCH")
		}
		base *= 2
	case f.Headers != nil:
		v := f.Headers
		if v.MatchPattern == nil || countSet(v.MatchPattern.All != nil, len(v.MatchPattern.IncludedHeaders) > 0, len(v.MatchPattern.ExcludedHeaders) > 0) != 1 {
			return 0, invalidParameter("HEADER_MATCH_PATTERN", path, "Headers.MatchPattern must specify exactly one of All, IncludedHeaders or ExcludedHeaders")
		}
		if err := validateMapScope(path, "Headers", v.MatchScope, v.OversizeHandling); err != nil {
			return 0, err
		}
	case f.Cookies != nil:
		v := f.Cookies
		if v.MatchPattern == nil || countSet(v.MatchPattern.All != nil, len(v.MatchPattern.IncludedCookies) > 0, len(v.MatchPattern.ExcludedCookies) > 0) != 1 {
			return 0, invalidParameter("COOKIE_MATCH_PATTERN", path, "Cookies.MatchPattern must specify exactly one of All, IncludedCookies or ExcludedCookies")
		}
		if err := validateMapScope(path, "Cookies", v.MatchScope, v.OversizeHandling); err != nil {
			return 0, err
		}
	case f.UriFragment != nil:
		if v := f.UriFragment.FallbackBehavior; v != nil && !validFallback(v) {
			return 0, invalidParameter("FALLBACK_BEHAVIOR", path, "UriFragment.FallbackBehavior must be MATCH or NO_MATCH")
		}
	case f.JA3Fingerprint != nil || f.JA4Fingerprint != nil:
		fallback := f.JA3Fingerprint
		if fallback == nil {
			fallback = (*api.JA3Fingerprint)(f.JA4Fingerprint)
		}
		if !validFallback(fallback.FallbackBehavior) {
			return 0, invalidParameter("FALLBACK_BEHAVIOR", path, "Fingerprint inspection requires FallbackBehavior MATCH or NO_MATCH")
		}
		if !exact {
			return 0, invalidParameter("FIELD_TO_MATCH", path, "JA3 and JA4 fingerprints can be inspected only by an EXACTLY string match")
		}
	case f.HeaderOrder != nil:
		return 0, unsupported(path+".HeaderOrder", "the received header order is not retained by the API Gateway request path")
	}
	return base, nil
}

func countSet(values ...bool) int {
	n := 0
	for _, v := range values {
		if v {
			n++
		}
	}
	return n
}

func validateMapScope(path, component string, scope *api.MapMatchScope, oversize *api.OversizeHandling) error {
	switch value(scope) {
	case "ALL", "KEY", "VALUE":
	default:
		return invalidParameter("MAP_MATCH_SCOPE", path, component+".MatchScope must be ALL, KEY or VALUE")
	}
	if !validOversize(oversize, true) {
		return invalidParameter("OVERSIZE_HANDLING", path, component+".OversizeHandling must be CONTINUE, MATCH or NO_MATCH")
	}
	return nil
}

func validateForwarded(path string, header *api.ForwardedIPHeaderName, fallback *api.FallbackBehavior) error {
	if !headerName.MatchString(value(header)) {
		return invalidParameter("HEADER_NAME", path, path+".HeaderName must match ^[a-zA-Z0-9-]+$")
	}
	if !validFallback(fallback) {
		return invalidParameter("FALLBACK_BEHAVIOR", path, path+".FallbackBehavior must be MATCH or NO_MATCH")
	}
	return nil
}

func (a *admission) ipSetReference(path string, v *api.IPSetReferenceStatement) (int64, error) {
	arn := value(v.ARN)
	if _, err := a.r.IPSet(a.scope, arn); err != nil {
		if errors.Is(err, ErrNotFound) {
			return 0, nonexistent("The referenced IP set " + arn + " doesn't exist in this account, Region and scope")
		}
		return 0, err
	}
	a.ipSets[arn] = true
	cost := int64(1)
	if f := v.IPSetForwardedIPConfig; f != nil {
		if err := validateForwarded(path+".IPSetForwardedIPConfig", f.HeaderName, f.FallbackBehavior); err != nil {
			return 0, err
		}
		switch value(f.Position) {
		case "FIRST", "LAST":
		case "ANY":
			cost += 4
		default:
			return 0, invalidParameter("POSITION", path, "IPSetForwardedIPConfig.Position must be FIRST, LAST or ANY")
		}
	}
	return cost, nil
}

func (a *admission) rateBased(path string, v *api.RateBasedStatement) (int64, error) {
	if v.Limit == nil || *v.Limit < 10 || *v.Limit > 2000000000 {
		return 0, invalidParameter("RATE_BASED_STATEMENT", path, path+".Limit must be between 10 and 2000000000")
	}
	if w := v.EvaluationWindowSec; w != nil && *w != 60 && *w != 120 && *w != 300 && *w != 600 {
		return 0, invalidParameter("RATE_BASED_STATEMENT", path, path+".EvaluationWindowSec must be 60, 120, 300 or 600")
	}
	if len(v.CustomKeys) > 0 {
		return 0, unsupported(path+".CustomKeys", "custom aggregation keys are not implemented; use IP, FORWARDED_IP or CONSTANT")
	}
	switch value(v.AggregateKeyType) {
	case "IP":
		if v.ForwardedIPConfig != nil {
			return 0, invalidParameter("RATE_BASED_STATEMENT", path, "ForwardedIPConfig applies only to FORWARDED_IP aggregation")
		}
	case "FORWARDED_IP":
		if v.ForwardedIPConfig == nil {
			return 0, invalidParameter("RATE_BASED_STATEMENT", path, "FORWARDED_IP aggregation requires ForwardedIPConfig")
		}
		if err := validateForwarded(path+".ForwardedIPConfig", v.ForwardedIPConfig.HeaderName, v.ForwardedIPConfig.FallbackBehavior); err != nil {
			return 0, err
		}
	case "CONSTANT":
		if v.ScopeDownStatement == nil {
			return 0, invalidParameter("RATE_BASED_STATEMENT", path, "CONSTANT aggregation requires a ScopeDownStatement")
		}
	case "CUSTOM_KEYS":
		return 0, unsupported(path+".AggregateKeyType", "CUSTOM_KEYS aggregation is not implemented")
	default:
		return 0, invalidParameter("RATE_BASED_STATEMENT", path, path+".AggregateKeyType must be IP, FORWARDED_IP, CONSTANT or CUSTOM_KEYS")
	}
	cost := int64(2)
	if v.ScopeDownStatement != nil {
		nested, err := a.statement(path+".ScopeDownStatement", v.ScopeDownStatement, false)
		if err != nil {
			return 0, err
		}
		cost += nested
	}
	return cost, nil
}

// validateAddresses admits CIDR blocks of one IP version, as AWS WAF requires.
func validateAddresses(version string, addresses api.IPAddresses) ([]string, error) {
	if version != "IPV4" && version != "IPV6" {
		return nil, invalidParameter("IP_ADDRESS_VERSION", version, "IPAddressVersion must be IPV4 or IPV6")
	}
	if len(addresses) > 10000 {
		return nil, failure("WAFLimitsExceededException", "An IP set can contain at most 10,000 addresses", 400)
	}
	out := make([]string, 0, len(addresses))
	seen := map[string]bool{}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(string(address))
		if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4() != (version == "IPV4") || prefix.Addr().Is4In6() {
			return nil, invalidParameter("IP_ADDRESS", string(address), "Addresses must be "+version+" CIDR blocks with a prefix length from /1")
		}
		text := string(address)
		if !seen[text] {
			seen[text] = true
			out = append(out, text)
		}
	}
	return out, nil
}
