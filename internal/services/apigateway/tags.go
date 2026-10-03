package apigateway

import (
	"errors"
	"maps"
	"net/url"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/apigateway"
	"strings"
	"unicode"
	"unicode/utf8"
)

func validateTags(tags map[string]string) error {
	if len(tags) > 50 {
		return bad("Too many tags")
	}
	for k, v := range tags {
		if k == "" || utf8.RuneCountInString(k) > 128 || utf8.RuneCountInString(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") || !tagCharacters(k) || !tagCharacters(v) {
			return bad("Invalid tag")
		}
	}
	return nil
}
func tagCharacters(v string) bool {
	for _, c := range v {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) && !unicode.IsSpace(c) && !strings.ContainsRune(".:+=@_/-", c) {
			return false
		}
	}
	return utf8.ValidString(v)
}
func (s *Service) authorizeTags(r Reader, verb, path string, existing, requested map[string]string, keys []string) error {
	scope := scopeFor(r.Context())
	conditions := map[string][]string{}
	for k, v := range existing {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	for k, v := range requested {
		conditions["aws:RequestTag/"+k] = []string{v}
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		slices.Sort(keys)
		conditions["aws:TagKeys"] = keys
	}
	if e := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "apigateway:" + verb, ResourceARN: controlARN(scope, path), ResourceAccountID: scope.AccountID, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}}); e != nil {
		return e
	}
	return nil
}

type taggedResource struct {
	api       APIRecord
	stage     *StageRecord
	clientKey *ClientKeyRecord
	usagePlan *UsagePlanRecord
}

func tagged(r Reader, arn string) (taggedResource, error) {
	scope := scopeFor(r.Context())
	if id, ok := strings.CutPrefix(arn, controlARN(scope, "/apikeys/")); ok {
		row, err := r.ClientKey(ClientKey{Scope: scope, ID: id})
		return taggedResource{clientKey: &row}, err
	}
	if id, ok := strings.CutPrefix(arn, controlARN(scope, "/usageplans/")); ok {
		row, err := r.UsagePlan(PlanKey{Scope: scope, ID: id})
		return taggedResource{usagePlan: &row}, err
	}
	prefix := controlARN(scope, "/restapis/")
	if !strings.HasPrefix(arn, prefix) {
		return taggedResource{}, ErrNotFound
	}
	parts := strings.Split(strings.TrimPrefix(arn, prefix), "/")
	if len(parts) != 1 && (len(parts) != 3 || parts[1] != "stages") {
		return taggedResource{}, ErrNotFound
	}
	owner, err := r.API(APIKey{Scope: scope, ID: parts[0]})
	if err != nil {
		return taggedResource{}, err
	}
	out := taggedResource{api: owner}
	if len(parts) == 3 {
		stage, err := r.Stage(StageKey{APIKey: owner.Key, Name: parts[2]})
		if err != nil {
			return taggedResource{}, err
		}
		out.stage = &stage
	}
	return out, nil
}
func (v taggedResource) tags() map[string]string {
	if v.clientKey != nil {
		return v.clientKey.Tags
	}
	if v.usagePlan != nil {
		return v.usagePlan.Tags
	}
	if v.stage != nil {
		return v.stage.Tags
	}
	return v.api.Tags
}
func mergedTags(parent, child map[string]string) map[string]string {
	if len(child) == 0 {
		return parent
	}
	out := maps.Clone(parent)
	if out == nil {
		out = map[string]string{}
	}
	maps.Copy(out, child)
	return out
}
func (v taggedResource) effectiveTags() map[string]string {
	if v.stage != nil {
		return mergedTags(v.api.Tags, v.stage.Tags)
	}
	return v.tags()
}
func stageTags(r Reader, owner APIRecord, suffix string) (map[string]string, error) {
	if !strings.HasPrefix(suffix, "/stages/") {
		return owner.Tags, nil
	}
	name, _, _ := strings.Cut(strings.TrimPrefix(suffix, "/stages/"), "/")
	row, err := r.Stage(StageKey{APIKey: owner.Key, Name: name})
	if errors.Is(err, ErrNotFound) {
		return owner.Tags, nil
	}
	if err != nil {
		return nil, err
	}
	return mergedTags(owner.Tags, row.Tags), nil
}
func (v taggedResource) put(tx Transaction, tags map[string]string) error {
	if v.clientKey != nil {
		v.clientKey.Tags = tags
		return tx.PutClientKey(*v.clientKey)
	}
	if v.usagePlan != nil {
		v.usagePlan.Tags = tags
		return tx.PutUsagePlan(*v.usagePlan)
	}
	if v.stage != nil {
		v.stage.Tags = tags
		return tx.PutStage(*v.stage)
	}
	v.api.Tags = tags
	return tx.PutAPI(v.api)
}
func (s *Service) tagResource(tx Transaction, in *api.TagResourceRequest) (*api.Unit, error) {
	arn := value(in.ResourceArn)
	row, err := tagged(tx, arn)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	requested := mapIn(in.Tags)
	if e := s.authorizeTags(tx, "PUT", "/tags/"+url.QueryEscape(arn), row.effectiveTags(), requested, nil); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	tags := maps.Clone(row.tags())
	if tags == nil {
		tags = map[string]string{}
	}
	maps.Copy(tags, requested)
	if err := validateTags(tags); err != nil {
		return nil, err
	}
	return &api.Unit{}, row.put(tx, tags)
}
func (s *Service) untagResource(tx Transaction, in *api.UntagResourceRequest) (*api.Unit, error) {
	arn := value(in.ResourceArn)
	row, err := tagged(tx, arn)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	keys := stringsIn(in.TagKeys)
	if e := s.authorizeTags(tx, "DELETE", "/tags/"+url.QueryEscape(arn), row.effectiveTags(), nil, keys); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	tags := maps.Clone(row.tags())
	for _, k := range keys {
		if strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, bad("Reserved tag key")
		}
		delete(tags, k)
	}
	return &api.Unit{}, row.put(tx, tags)
}
func (s *Service) getTags(tx Transaction, in *api.GetTagsRequest) (*api.Tags, error) {
	arn := value(in.ResourceArn)
	row, err := tagged(tx, arn)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if e := s.authorizeTags(tx, "GET", "/tags/"+url.QueryEscape(arn), row.effectiveTags(), nil, nil); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	if value(in.Position) != "" {
		return nil, bad("Invalid position")
	}
	if in.Limit != nil && (*in.Limit < 1 || *in.Limit > 500) {
		return nil, bad("Invalid limit")
	}
	return &api.Tags{Tags: mapOut(row.tags())}, nil
}
