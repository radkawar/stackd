package codepipeline

import (
	"fmt"
	"regexp"
	api "stackd/internal/awsapi/codepipeline"
)

var variableReference = regexp.MustCompile(`#\{([^{}]+)\}`)

func pipelineVariableOverrides(overrides api.PipelineVariableList) (map[string]*api.PipelineVariableValue, error) {
	values := make(map[string]*api.PipelineVariableValue, len(overrides))
	for _, override := range overrides {
		name := text(override.Name)
		if _, exists := values[name]; exists {
			return nil, failure("ValidationException", "Variable names must be unique. The following variable name is already in use: "+name)
		}
		values[name] = override.Value
	}
	return values, nil
}

// Pipeline bindings are captured once at execution admission. Action resolution
// and retries consume only these values, never the current definition defaults.
func bindPipelineVariables(declarations api.PipelineVariableDeclarationList, values map[string]*api.PipelineVariableValue) (api.ResolvedPipelineVariableList, []string) {
	var missing []string
	for _, declaration := range declarations {
		name := text(declaration.Name)
		if _, overridden := values[name]; !overridden {
			values[name] = declaration.DefaultValue
		}
		if values[name] == nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 || len(declarations) == 0 {
		// Native execution history omits all bindings when a required value is missing.
		return nil, missing
	}
	resolved := make(api.ResolvedPipelineVariableList, len(declarations))
	for i, declaration := range declarations {
		name := text(declaration.Name)
		resolved[i] = api.ResolvedPipelineVariable{Name: new(api.String(name)), ResolvedValue: new(api.String(*values[name]))}
	}
	return resolved, nil
}

func resolveConfiguration(d Definition, e Execution, decl api.ActionDeclaration, target *Execution) (api.ActionConfigurationMap, error) {
	values := map[string]string{"codepipeline.PipelineExecutionId": e.ID}
	for _, variable := range e.Variables {
		values["variables."+text(variable.Name)] = text(variable.ResolvedValue)
	}
	for i, stage := range d.Declaration.Stages {
		for j, producer := range stage.Actions {
			namespace := text(producer.Namespace)
			if namespace == "" {
				continue
			}
			a := latestAction(e, int32(i), int32(j))
			if a == nil && target != nil && int32(i) < e.RollbackStageIndex {
				a = latestAction(*target, int32(i), int32(j))
			}
			if a == nil || a.Status != "Succeeded" {
				continue
			}
			for key, value := range a.OutputVariables {
				values[namespace+"."+string(key)] = string(value)
			}
		}
	}
	resolved := make(api.ActionConfigurationMap, len(decl.Configuration))
	for key, value := range decl.Configuration {
		var err error
		text := variableReference.ReplaceAllStringFunc(string(value), func(reference string) string {
			name := reference[2 : len(reference)-1]
			value, ok := values[name]
			if !ok {
				err = fmt.Errorf("unresolved action variable %s", name)
				return reference
			}
			return value
		})
		if err != nil {
			return nil, err
		}
		resolved[key] = api.ActionConfigurationValue(text)
	}
	return resolved, nil
}
