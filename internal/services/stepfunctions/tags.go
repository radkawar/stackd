package stepfunctions

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awswire"
)

func admitControlTags(input api.TagList) (map[string]string, error) {
	tags := make(map[string]string, len(input))
	for _, tag := range input {
		key, val := value(tag.Key), value(tag.Value)
		if err := admitTagKey(key); err != nil {
			return nil, err
		}
		if tag.Value == nil || !validTagText(val) || utf8.RuneCountInString(val) > 256 {
			return nil, invalid("Tag values must contain at most 256 permitted characters.")
		}
		if _, exists := tags[key]; exists {
			return nil, invalid("Duplicate tag keys are not allowed.")
		}
		tags[key] = val
	}
	if len(tags) > 50 {
		return nil, failure("TooManyTags", "A resource cannot have more than 50 tags.", 400)
	}
	return tags, nil
}

func admitTagKey(key string) error {
	if strings.HasPrefix(strings.ToLower(key), "aws:") {
		return failure("AccessDeniedException", "Caller is an end user and not allowed to mutate system tags", 400)
	}
	if key == "" || !validTagText(key) || utf8.RuneCountInString(key) > 128 {
		return invalid("Tag keys must contain between 1 and 128 permitted characters.")
	}
	return nil
}

func validTagText(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	for _, c := range text {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && !unicode.IsSpace(c) && !strings.ContainsRune("_.:/=+-@", c) {
			return false
		}
	}
	return true
}

func requestTagConditions(tags map[string]string, keys []string) map[string][]string {
	conditions := make(map[string][]string, len(tags)+1)
	if keys == nil {
		keys = make([]string, 0, len(tags))
		for key, val := range tags {
			conditions["aws:RequestTag/"+key] = []string{val}
			keys = append(keys, key)
		}
		slices.Sort(keys)
	}
	if len(keys) != 0 {
		conditions["aws:TagKeys"] = keys
	}
	return conditions
}

func (s *Service) createTagAuthority(r Reader, resource string, tags map[string]string) *awswire.Error {
	if len(tags) == 0 {
		return nil
	}
	return s.authorize(r, "TagResource", resource, nil, requestTagConditions(tags, nil))
}

type controlTagTarget struct {
	machine   *MachineRecord
	activity  *ActivityRecord
	qualified bool
}

func (target controlTagTarget) tags() map[string]string {
	if target.machine != nil {
		return target.machine.Tags
	}
	if target.activity != nil {
		return target.activity.Tags
	}
	return nil
}

func (target controlTagTarget) put(tx Transaction, tags map[string]string) error {
	if target.machine != nil {
		target.machine.Tags = tags
		target.machine.Version++
		return tx.PutMachine(*target.machine)
	}
	target.activity.Tags = tags
	return tx.PutActivity(*target.activity)
}

func (s *Service) tagTarget(r Reader, raw, action string, requested map[string]string, keys []string) (controlTagTarget, error) {
	scope, kind, name, qualifier, err := parseResourceARN(raw)
	if err != nil {
		return controlTagTarget{}, err
	}
	target := controlTagTarget{qualified: qualifier != ""}
	var missing bool
	if scope != scopeFor(r.Context()) {
		missing = true
	} else if kind == "stateMachine" {
		machine, readErr := r.Machine(MachineKey{Scope: scope, Name: name})
		if readErr != nil && !errors.Is(readErr, ErrNotFound) {
			return target, readErr
		}
		missing = errors.Is(readErr, ErrNotFound)
		if !missing {
			target.machine = &machine
		}
	} else {
		activity, readErr := r.Activity(ActivityKey{Scope: scope, Name: name})
		if readErr != nil && !errors.Is(readErr, ErrNotFound) {
			return target, readErr
		}
		missing = errors.Is(readErr, ErrNotFound)
		if !missing {
			target.activity = &activity
		}
	}
	if denied := s.authorize(r, action, raw, target.tags(), requestTagConditions(requested, keys)); denied != nil {
		return target, denied
	}
	if missing || target.qualified && action != "ListTagsForResource" {
		return target, resourceMissing(raw)
	}
	if target.machine != nil {
		if err := cloudFormationCheck(r.Context(), "StateMachine", target.machine.CFNOwner); err != nil {
			return target, err
		}
	} else if target.activity != nil {
		if err := cloudFormationCheck(r.Context(), "Activity", target.activity.CFNOwner); err != nil {
			return target, err
		}
	}
	if target.qualified {
		if number, ok := versionNumber(qualifier); ok {
			_, err = r.Version(VersionKey{Machine: target.machine.Key, MachineID: target.machine.ID, Number: number})
		} else {
			_, err = r.Alias(AliasKey{Machine: target.machine.Key, MachineID: target.machine.ID, Name: qualifier})
		}
		if errors.Is(err, ErrNotFound) {
			return target, resourceMissing(raw)
		}
		if err != nil {
			return target, err
		}
	}
	return target, nil
}

func (s *Service) listTagsForResource(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	target, err := s.tagTarget(tx, value(in.ResourceArn), "ListTagsForResource", nil, nil)
	if err != nil {
		return nil, err
	}
	out := &api.ListTagsForResourceOutput{Tags: api.TagList{}}
	if target.qualified {
		return out, nil
	}
	tags := target.tags()
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		out.Tags = append(out.Tags, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(tags[key]))})
	}
	return out, nil
}

func (s *Service) tagResource(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	if len(in.Tags) == 0 {
		return nil, invalid("tags must contain at least one tag.")
	}
	requested, err := admitControlTags(in.Tags)
	if err != nil {
		return nil, err
	}
	target, err := s.tagTarget(tx, value(in.ResourceArn), "TagResource", requested, nil)
	if err != nil {
		return nil, err
	}
	tags := maps.Clone(target.tags())
	if tags == nil {
		tags = make(map[string]string)
	}
	maps.Copy(tags, requested)
	if len(tags) > 50 {
		return nil, failure("TooManyTags", "A resource cannot have more than 50 tags.", 400)
	}
	if err := target.put(tx, tags); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}

func (s *Service) untagResource(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	if len(in.TagKeys) == 0 {
		return nil, invalid("tagKeys must contain at least one key.")
	}
	keys := make([]string, len(in.TagKeys))
	for i, key := range in.TagKeys {
		if err := admitTagKey(string(key)); err != nil {
			return nil, err
		}
		keys[i] = string(key)
	}
	target, err := s.tagTarget(tx, value(in.ResourceArn), "UntagResource", nil, keys)
	if err != nil {
		return nil, err
	}
	tags := maps.Clone(target.tags())
	for _, key := range keys {
		delete(tags, key)
	}
	if err := target.put(tx, tags); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}
