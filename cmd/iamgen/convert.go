package main

import (
	"fmt"
	"slices"
	"strings"

	"stackd/internal/iam/catalog/schema"
)

func convert(source sourceSnapshot) ([]schema.Service, error) {
	services := make([]schema.Service, 0, len(source.Services))
	prefixes := make(map[string]bool)
	for _, s := range source.Services {
		if s.Name == "" || !strings.HasPrefix(s.Version, "v1.") || prefixes[strings.ToLower(s.Name)] {
			return nil, fmt.Errorf("invalid or duplicate service %q at version %q", s.Name, s.Version)
		}
		prefixes[strings.ToLower(s.Name)] = true
		service := schema.Service{Prefix: s.Name}
		resources := make(map[string]sourceResource)
		for _, resource := range s.Resources {
			if resource.Name == "" || len(resource.ARNFormats) == 0 {
				return nil, fmt.Errorf("service %s has incomplete resource %q", s.Name, resource.Name)
			}
			if _, exists := resources[resource.Name]; exists {
				return nil, fmt.Errorf("service %s has duplicate resource %q", s.Name, resource.Name)
			}
			resources[resource.Name] = resource
			service.Resources = append(service.Resources, schema.Resource{Name: resource.Name, ARNTemplates: sortedUnique(resource.ARNFormats)})
		}
		names := make(map[string]bool)
		variants := make(map[string]int)
		for _, action := range s.Actions {
			if action.Name == "" || names[action.Name] {
				return nil, fmt.Errorf("service %s has invalid or duplicate action %q", s.Name, action.Name)
			}
			names[action.Name] = true
			variants[strings.ToLower(action.Name)]++
		}
		for _, action := range s.Actions {
			item := schema.Action{Name: s.Name + ":" + action.Name, ConditionKeys: slices.Clone(action.ActionConditionKeys), Ambiguous: variants[strings.ToLower(action.Name)] > 1}
			for _, reference := range action.Resources {
				resource, exists := resources[reference.Name]
				if !exists {
					return nil, fmt.Errorf("action %s has unknown resource %q", item.Name, reference.Name)
				}
				item.Resources = append(item.Resources, reference.Name)
				item.ConditionKeys = append(item.ConditionKeys, resource.ConditionKeys...)
			}
			item.Resources = sortedUnique(item.Resources)
			item.ConditionKeys = sortedUnique(item.ConditionKeys)
			service.Actions = append(service.Actions, item)
		}
		slices.SortFunc(service.Actions, func(a, b schema.Action) int { return strings.Compare(a.Name, b.Name) })
		slices.SortFunc(service.Resources, func(a, b schema.Resource) int { return strings.Compare(a.Name, b.Name) })
		services = append(services, service)
	}
	slices.SortFunc(services, func(a, b schema.Service) int { return strings.Compare(a.Prefix, b.Prefix) })
	return services, nil
}

func sortedUnique(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return slices.Compact(out)
}
