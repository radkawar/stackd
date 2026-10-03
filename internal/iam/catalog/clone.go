package catalog

import "slices"

func cloneService(service Service) Service {
	service.Actions = slices.Clone(service.Actions)
	for i, action := range service.Actions {
		service.Actions[i] = cloneAction(action)
	}
	service.Resources = slices.Clone(service.Resources)
	for i, resource := range service.Resources {
		service.Resources[i] = cloneResource(resource)
	}
	return service
}

func cloneAction(action Action) Action {
	action.Resources = slices.Clone(action.Resources)
	action.ConditionKeys = slices.Clone(action.ConditionKeys)
	return action
}

func cloneResource(resource Resource) Resource {
	resource.ARNTemplates = slices.Clone(resource.ARNTemplates)
	return resource
}
