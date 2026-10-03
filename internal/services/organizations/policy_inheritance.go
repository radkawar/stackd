package organizations

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"
)

// Normalize an admitted source for inheritance without re-running admission.
// Calendar admission depends on request time; storing a policy does not make
// its later reads subject to a new CreatePolicy validation decision.
func normalizeManagementPolicy(n *managementNode, kind string) {
	if kind != "BACKUP_POLICY" && kind != "TAG_POLICY" && kind != "CHATBOT_POLICY" {
		return
	}
	var normalize func(*managementNode)
	normalize = func(n *managementNode) {
		if n.assigned {
			if values, ok := n.assign.([]any); ok {
				for i, value := range values {
					values[i], _ = managementScalar(value)
				}
			} else {
				n.assign, _ = managementScalar(n.assign)
			}
		}
		for _, values := range [][]any{n.append, n.remove} {
			for i, value := range values {
				values[i], _ = managementScalar(value)
			}
		}
		for _, child := range n.children {
			normalize(child)
		}
		if kind == "CHATBOT_POLICY" {
			// Native effective documents also lowercase identifier keys. Source
			// admission retains their case for Slack/Teams identifier validation.
			foldChatFields(n)
		}
	}
	normalize(n)
	if kind == "TAG_POLICY" {
		tags := n.children["tags"]
		if tags == nil {
			return
		}
		canonical := make(map[string]*managementNode, len(tags.children))
		for key, value := range tags.children {
			canonical[strings.ToLower(key)] = value
		}
		tags.children = canonical
	}
}

type policyContribution struct {
	policyID string
	node     *managementNode
}

type inheritedSetting struct {
	policies []string
	value    any
	children map[string]*inheritedSetting
	allowed  policyOperators
}

// mergeLevel resolves peers before inheriting the next level: first assignment,
// all appends, then all removals. Peer child controls intersect only after that
// level's own values are applied. Ancestor restrictions cannot be relaxed.
func (s *inheritedSetting) mergeLevel(nodes []policyContribution) {
	if s.allowed&policyAssign != 0 {
		for _, contribution := range nodes {
			n := contribution.node
			if n.assigned {
				s.value = n.assign
				s.policies = []string{contribution.policyID}
				break
			}
		}
	}
	if s.allowed&policyAppend != 0 {
		for _, contribution := range nodes {
			n := contribution.node
			if n.append == nil {
				continue
			}
			values, _ := s.value.([]any)
			if values == nil {
				values = []any{}
			}
			for _, value := range n.append {
				if !slices.ContainsFunc(values, func(v any) bool { return reflect.DeepEqual(v, value) }) {
					values = append(values, value)
					s.addPolicy(contribution.policyID)
				}
			}
			s.value = values
		}
	}
	if s.allowed&policyRemove != 0 {
		for _, contribution := range nodes {
			n := contribution.node
			if values, ok := s.value.([]any); ok {
				before := len(values)
				s.value = slices.DeleteFunc(values, func(v any) bool {
					return slices.ContainsFunc(n.remove, func(remove any) bool { return reflect.DeepEqual(v, remove) })
				})
				if len(s.value.([]any)) != before {
					s.addPolicy(contribution.policyID)
				}
			}
		}
	}
	children := make(map[string][]policyContribution)
	for _, contribution := range nodes {
		n := contribution.node
		if n.children != nil && s.children == nil {
			s.children = make(map[string]*inheritedSetting)
		}
		for key, child := range n.children {
			children[key] = append(children[key], policyContribution{policyID: contribution.policyID, node: child})
		}
	}
	for _, key := range slices.Sorted(maps.Keys(children)) {
		if s.children == nil {
			s.children = make(map[string]*inheritedSetting)
		}
		if s.children[key] == nil {
			s.children[key] = &inheritedSetting{allowed: policyAll}
		}
		s.children[key].mergeLevel(children[key])
	}
	for _, contribution := range nodes {
		n := contribution.node
		s.allowed &= n.allowed
	}
}

func (s *inheritedSetting) addPolicy(id string) {
	if !slices.Contains(s.policies, id) {
		s.policies = append(s.policies, id)
	}
}

func (s *inheritedSetting) contributingPolicies() []string {
	policies := make(map[string]bool)
	var collect func(*inheritedSetting)
	collect = func(n *inheritedSetting) {
		for _, id := range n.policies {
			policies[id] = true
		}
		for _, child := range n.children {
			collect(child)
		}
	}
	collect(s)
	return slices.Sorted(maps.Keys(policies))
}

func (s *inheritedSetting) document() any {
	if s.children == nil {
		return s.value
	}
	out := make(map[string]any)
	for key, child := range s.children {
		if value := child.document(); value != nil {
			out[key] = value
		}
	}
	return out
}

func (o *orgState) effectivePolicyContent(accountID, kind string, now time.Time) (string, []EffectivePolicyError, error) {
	var hierarchy []string
	for id := accountID; id != ""; id = o.parents[id] {
		hierarchy = append(hierarchy, id)
	}
	slices.Reverse(hierarchy)
	resolved := &inheritedSetting{allowed: policyAll}
	for _, target := range hierarchy {
		var nodes []policyContribution
		for _, id := range o.attachments[target] {
			p := o.policies[id]
			if p.PolicySummary.Type != kind {
				continue
			}
			n, err := parseManagementPolicy([]byte(p.Content), kind)
			if err != nil {
				return "", nil, err
			}
			normalizeManagementPolicy(n, kind)
			nodes = append(nodes, policyContribution{policyID: id, node: n})
		}
		resolved.mergeLevel(nodes)
	}
	if kind == "BACKUP_POLICY" || kind == "CHATBOT_POLICY" || kind == "S3_POLICY" {
		pruneEmptySettings(resolved)
	}
	var validationErrors []EffectivePolicyError
	if kind == "BACKUP_POLICY" {
		validationErrors = validateEffectiveBackup(resolved, now)
	}
	if len(validationErrors) > 0 {
		return "", validationErrors, nil
	}
	doc, _ := resolved.document().(map[string]any)
	if doc == nil {
		doc = make(map[string]any)
	}
	if kind == "TAG_POLICY" {
		completeEffectiveTags(doc)
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		return "", nil, err
	}
	data := encoded.Bytes()[:encoded.Len()-1] // Encode terminates its document with a newline.
	if kind == "TAG_POLICY" {
		validationErrors = validateEffectiveTags(resolved, len(data))
		if len(validationErrors) > 0 {
			return "", validationErrors, nil
		}
	}
	return string(data), validationErrors, nil
}

func pruneEmptySettings(n *inheritedSetting) bool {
	for key, child := range n.children {
		if pruneEmptySettings(child) {
			delete(n.children, key)
		}
	}
	return n.value == nil && len(n.children) == 0
}

type backupValidation struct{ errors []EffectivePolicyError }
