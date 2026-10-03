package iam

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
	"stackd/internal/iam/simcatalog"
)

func validateSimulationResources(resources []string, _ string) *awswire.Error {
	for _, resource := range resources {
		if resource == "*" {
			if len(resources) > 1 {
				return invalidInput("ResourceNames are not in a valid ARN format: *.")
			}
			continue
		}
		parts := strings.SplitN(resource, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] == "" || parts[5] == "" {
			return invalidInput("ResourceNames are not in a valid ARN format: " + resource + ".")
		}
	}
	return nil
}

func simulationExplicitResources(resources []string) bool {
	return len(resources) != 0 && (len(resources) != 1 || resources[0] != "*")
}

func simulationCatalog() (*catalog.Catalog, *awswire.Error) {
	metadata, err := catalog.Load()
	if err != nil {
		return nil, &awswire.Error{Code: "PolicyEvaluation", Message: "Unable to load IAM action metadata.", StatusCode: 500}
	}
	return metadata, nil
}

func validateSimulationActions(actions, resources []string) *awswire.Error {
	if len(actions) == 0 {
		return invalidInput("ActionNames is required.")
	}
	var known, unknown []string
	for _, action := range actions {
		if !strings.Contains(action, ":") {
			return invalidInput("The action is invalid since it is missing names")
		}
		if entry, exists := simcatalog.LookupAction(action); exists && entry.ResourceAware {
			known = append(known, action)
		} else {
			unknown = append(unknown, action)
		}
	}
	if simulationExplicitResources(resources) && len(known) != 0 && len(unknown) != 0 {
		return invalidInput(fmt.Sprintf("Invalid Input Actions: [%s] and [%s] require different authorization information.", strings.Join(known, ","), strings.Join(unknown, ",")))
	}
	return nil
}

func validateSimulationHandling(actions, resources []string, option string) *awswire.Error {
	if option == "" || !simulationExplicitResources(resources) {
		return nil
	}
	for _, name := range actions {
		if !simcatalog.SupportsResourceHandling(name, option) {
			return invalidInput("Invalid input resource handling options. Action does not support resource handling options: " + name + ".")
		}
	}
	// The captured EC2 scenarios accept incomplete resource sets. These labels
	// select the simulator's action scenario; they do not create dependencies.
	return nil
}

// The cache contains only templates from the immutable generated catalog, not
// request strings, so callers cannot make it retain arbitrary input patterns.
var simulationTemplatePatterns sync.Map

func simulationTemplateMatches(template, resource string) (bool, *awswire.Error) {
	if cached, exists := simulationTemplatePatterns.Load(template); exists {
		return cached.(*regexp.Regexp).MatchString(resource), nil
	}
	var pattern strings.Builder
	pattern.WriteByte('^')
	for remaining := template; remaining != ""; {
		start := strings.Index(remaining, "${")
		if start < 0 {
			pattern.WriteString(regexp.QuoteMeta(remaining))
			break
		}
		pattern.WriteString(regexp.QuoteMeta(remaining[:start]))
		end := strings.IndexByte(remaining[start:], '}')
		if end < 0 {
			return false, &awswire.Error{Code: "PolicyEvaluation", Message: "Invalid generated IAM resource template.", StatusCode: 500}
		}
		variable := remaining[start+2 : start+end]
		if variable == "Partition" || variable == "Region" || variable == "Account" {
			pattern.WriteString("[^:]*")
		} else {
			pattern.WriteString(".+")
		}
		remaining = remaining[start+end+1:]
	}
	pattern.WriteByte('$')
	compiled, err := regexp.Compile(pattern.String())
	if err != nil {
		return false, &awswire.Error{Code: "PolicyEvaluation", Message: "Invalid generated IAM resource template.", StatusCode: 500}
	}
	actual, _ := simulationTemplatePatterns.LoadOrStore(template, compiled)
	return actual.(*regexp.Regexp).MatchString(resource), nil
}

func simulationResourceCompatible(name, resource string) (bool, *awswire.Error) {
	if resource == "*" {
		return true, nil
	}
	entry, exists := simcatalog.LookupAction(name)
	if !exists || !entry.ResourceAware {
		// Simulator actions outside the resource-aware group participate in
		// literal policy matching, even when SAR lists the action.
		return true, nil
	}
	metadata, apiErr := simulationCatalog()
	if apiErr != nil {
		return false, apiErr
	}
	action, exists := metadata.LookupAction(name)
	if !exists {
		return false, nil
	}
	prefix, _, _ := strings.Cut(strings.ToLower(name), ":")
	for _, reference := range action.Resources {
		if reference == "" {
			continue
		}
		definition, exists := metadata.LookupResource(prefix, reference)
		if !exists {
			return false, &awswire.Error{Code: "PolicyEvaluation", Message: "Missing generated IAM resource definition.", StatusCode: 500}
		}
		templates := definition.ARNTemplates
		if prefix == "s3" && (reference == "bucket" || reference == "object") {
			// Native input_resources_known_s3_{buckets,objects} captures:
			// classic bucket and object actions share simulator eligibility.
			templates = []string{"arn:${Partition}:s3:::${BucketName}"}
		}
		for _, template := range templates {
			matches, apiErr := simulationTemplateMatches(template, resource)
			if apiErr != nil || matches {
				return matches, apiErr
			}
		}
	}
	return false, nil
}

// aggregateResource renders the simulator's captured display name. SAR resource
// templates remain eligibility metadata; they are never display-name fallbacks.
func (s *compiledSimulation) aggregateResource(name string) *string {
	if len(s.resources) == 1 && s.resources[0] != "*" {
		return wirePointer(s.resources[0])
	}
	action, exists := simcatalog.LookupAction(name)
	if !exists {
		return wirePointer("*")
	}
	if len(s.resources) == 0 || (len(s.resources) == 1 && s.resources[0] == "*") {
		template := strings.ReplaceAll(action.DefaultResourceTemplate, "${AuthenticatedAccount}", s.accountID)
		if strings.HasPrefix(template, "arn:aws:") {
			template = "arn:" + s.partition + ":" + strings.TrimPrefix(template, "arn:aws:")
		}
		return &template
	}
	if !action.ResourceAware {
		return wirePointer("*")
	}
	if !action.HasAggregateTemplate {
		return nil
	}
	template := action.AggregateTemplate
	// Captured literal ${Partition} templates retain that spelling. Concrete
	// commercial ARN templates use the first requested ARN's partition.
	if strings.HasPrefix(template, "arn:aws:") {
		for _, resource := range s.resources {
			if parts := strings.SplitN(resource, ":", 6); len(parts) == 6 {
				template = "arn:" + parts[1] + ":" + strings.TrimPrefix(template, "arn:aws:")
				break
			}
		}
	}
	return &template
}
