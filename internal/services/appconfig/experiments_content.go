package appconfig

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

func experimentFlagValue(t ExperimentTreatment, name, rule string) map[string]any {
	v := map[string]any{"name": name, "enabled": t.Enabled}
	if rule != "" {
		v["rule"] = rule
	}
	if len(t.Attributes) > 0 {
		attrs := map[string]any{}
		for k, a := range t.Attributes {
			switch a.Kind {
			case "boolean":
				attrs[k] = a.Boolean
			case "number":
				attrs[k] = a.Number
			case "string":
				attrs[k] = a.String
			case "numbers":
				attrs[k] = a.Numbers
			case "strings":
				attrs[k] = a.Strings
			}
		}
		v["attributeValues"] = attrs
	}
	return v
}

// applyExperimentRuns transforms an immutable deployed hosted document. The
// existing Agent owns hashing, entity context, treatment assignment and logs.
func applyExperimentRuns(content []byte, runs []ExperimentRun) ([]byte, string, error) {
	root, err := parseFeatureFlags(content)
	if err != nil {
		return nil, "", err
	}
	values := flagObject(root["values"])
	headers := []string{}
	slices.SortFunc(runs, func(a, b ExperimentRun) int { return strings.Compare(a.Snapshot.FlagKey, b.Snapshot.FlagKey) })
	for _, r := range runs {
		if r.Status != "RUNNING" {
			continue
		}
		d := r.Snapshot
		baseline := flagObject(values[d.FlagKey])
		if baseline == nil {
			return nil, "", failure("BadRequestException", "The experiment feature flag is not deployed in the target environment: "+d.FlagKey)
		}
		if _, err := parseVariantRule(d.AudienceRule); err != nil {
			return nil, "", failure("BadRequestException", "Experiment definition produces invalid flag content: invalid audience rule.")
		}
		treatments := append(slices.Clone(d.Treatments), d.Control)
		total := 0.0
		for _, t := range treatments {
			total += t.Weight
		}
		if total <= 0 {
			return nil, "", failure("BadRequestException", "Experiment treatment weights must have a positive total.")
		}
		variants := []any{}
		overrideKeys := []string{}
		for entity := range r.Overrides {
			overrideKeys = append(overrideKeys, entity)
		}
		slices.Sort(overrideKeys)
		for _, t := range append([]ExperimentTreatment{d.Control}, d.Treatments...) {
			entities := []string{}
			for _, entity := range overrideKeys {
				if r.Overrides[entity] == t.Key {
					entities = append(entities, entity)
				}
			}
			if len(entities) > 0 {
				encoded, _ := json.Marshal(entities)
				variants = append(variants, experimentFlagValue(t, "__"+t.Key+"_override__", "(in $entityId "+string(encoded)+")"))
			}
		}
		seed := strconv.Quote(d.AccountID + ":" + d.ApplicationID + ":" + d.ID + ":" + strconv.Itoa(int(r.Number)))
		lower := 0.0
		mapping := []string{}
		split := func(pct float64) string {
			return fmt.Sprintf("(split pct::%s by::$entityId seed::%s)", strconv.FormatFloat(pct, 'f', -1, 64), seed)
		}
		for _, t := range treatments {
			width := 100 * t.Weight / total
			upper := lower + width*r.Exposure/100
			bucket := split(upper)
			if lower > 0 {
				bucket = "(and " + bucket + " (not " + split(lower) + "))"
			}
			rule := "(and (exists key::\"entityId\") " + d.AudienceRule + " " + bucket + ")"
			name := "__" + t.Key + "__"
			variants = append(variants, experimentFlagValue(t, name, rule))
			mapping = append(mapping, t.Key+"="+name)
			lower += width
		}
		if existing, ok := baseline["_variants"].([]any); ok {
			variants = append(variants, existing...)
		} else {
			v := map[string]any{"name": "__default__", "enabled": baseline["enabled"]}
			attrs := map[string]any{}
			for k, a := range baseline {
				if k != "enabled" && !strings.HasPrefix(k, "_") {
					attrs[k] = a
				}
			}
			if len(attrs) > 0 {
				v["attributeValues"] = attrs
			}
			variants = append(variants, v)
		}
		values[d.FlagKey] = map[string]any{"_variants": variants}
		headers = append(headers, d.FlagKey+"="+experimentRunARN(d.Scope, d.ApplicationID, d.ID, r.Number)+"|"+strings.Join(mapping, ","))
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return nil, "", err
	}
	if err = validateFeatureFlags(encoded); err != nil {
		return nil, "", err
	}
	return encoded, strings.Join(headers, ";"), nil
}
