package ecs

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Native controls retain write responses but redact each container environment
// as a scalar marker, even for empty response lists. audit_environment.json
// independently captures the same rule for an explicitly supplied request
// environment; neither rule redacts tags or unrelated container fields.
var auditResponse = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"taskDefinition.containerDefinitions.environment":  {Mode: awsapi.RedactValueField},
	"taskDefinitions.containerDefinitions.environment": {Mode: awsapi.RedactValueField},
	"taskDefinition.registeredAt":                      {TimeLayout: time.RFC3339},
	"taskDefinition.deregisteredAt":                    {TimeLayout: time.RFC3339},
	"taskDefinitions.registeredAt":                     {TimeLayout: time.RFC3339},
	"taskDefinitions.deregisteredAt":                   {TimeLayout: time.RFC3339},
	"task.overrides.containerOverrides.environment":    {Mode: awsapi.RedactValueField},
	"tasks.overrides.containerOverrides.environment":   {Mode: awsapi.RedactValueField},
	"task.connectivityAt":                              {TimeLayout: time.RFC3339},
	"task.createdAt":                                   {TimeLayout: time.RFC3339},
	"task.executionStoppedAt":                          {TimeLayout: time.RFC3339},
	"task.pullStartedAt":                               {TimeLayout: time.RFC3339},
	"task.pullStoppedAt":                               {TimeLayout: time.RFC3339},
	"task.startedAt":                                   {TimeLayout: time.RFC3339},
	"task.stoppedAt":                                   {TimeLayout: time.RFC3339},
	"task.stoppingAt":                                  {TimeLayout: time.RFC3339},
	"tasks.connectivityAt":                             {TimeLayout: time.RFC3339},
	"tasks.createdAt":                                  {TimeLayout: time.RFC3339},
	"tasks.executionStoppedAt":                         {TimeLayout: time.RFC3339},
	"tasks.pullStartedAt":                              {TimeLayout: time.RFC3339},
	"tasks.pullStoppedAt":                              {TimeLayout: time.RFC3339},
	"tasks.startedAt":                                  {TimeLayout: time.RFC3339},
	"tasks.stoppedAt":                                  {TimeLayout: time.RFC3339},
	"tasks.stoppingAt":                                 {TimeLayout: time.RFC3339},
	"service.createdAt":                                {TimeLayout: time.RFC3339},
	"service.deployments.createdAt":                    {TimeLayout: time.RFC3339},
	"service.deployments.updatedAt":                    {TimeLayout: time.RFC3339},
	"service.events.createdAt":                         {TimeLayout: time.RFC3339},
}}

var auditRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"containerDefinitions.environment":         {Mode: awsapi.RedactValueField},
	"overrides.containerOverrides.environment": {Mode: awsapi.RedactValueField},
}}

func auditProjection(action string) apievents.Projection {
	p := apievents.Projection{Category: journal.CategoryManagement}
	p.ReadOnly = strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "List")
	switch action {
	case "CreateCluster", "UpdateCluster", "UpdateClusterSettings", "DeleteCluster",
		"RegisterTaskDefinition", "DeregisterTaskDefinition", "DeleteTaskDefinitions", "RunTask", "StopTask",
		"CreateService", "UpdateService", "DeleteService":
		p.Response = &auditResponse
	}
	if action == "RegisterTaskDefinition" || action == "RunTask" || action == "StartTask" {
		p.Request = auditRequest
	}
	return p
}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ecs")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	// Native missing-resource and authorization failures omit execution inputs;
	// InvalidParameterException retains sanitized parameters (ecs_targets.json).
	if rejected != nil && (action == "RunTask" || action == "StartTask") && rejected.Code != "InvalidParameterException" {
		in = nil
	}
	// network_interfaces.json captures default booleans and dryrun even when
	// absent from the accepted RunTask request. Keep the API input unchanged.
	if input, ok := in.(*api.RunTaskInput); ok && input != nil {
		copy := *input
		if copy.Count == nil {
			copy.Count = new(api.BoxedInteger(1))
		}
		if copy.EnableECSManagedTags == nil {
			copy.EnableECSManagedTags = new(api.Boolean(false))
		}
		if copy.EnableExecuteCommand == nil {
			copy.EnableExecuteCommand = new(api.Boolean(false))
		}
		if copy.Overrides != nil {
			for i, container := range copy.Overrides.ContainerOverrides {
				if container.Command == nil {
					continue
				}
				overrides := *copy.Overrides
				overrides.ContainerOverrides = slices.Clone(overrides.ContainerOverrides)
				for j := i; j < len(overrides.ContainerOverrides); j++ {
					if overrides.ContainerOverrides[j].Command != nil {
						overrides.ContainerOverrides[j].Command = api.StringList{"***REDACTED***"}
					}
				}
				copy.Overrides = &overrides
				break
			}
		}
		in = &copy
	}
	// Native request parameters materialize the container CPU scalar default,
	// including on failures. Detach only the changed slice from the API input.
	if input, ok := in.(*api.RegisterTaskDefinitionInput); ok && input != nil {
		for i := range input.ContainerDefinitions {
			if input.ContainerDefinitions[i].Cpu != nil {
				continue
			}
			copy := *input
			copy.ContainerDefinitions = slices.Clone(input.ContainerDefinitions)
			zero := api.Integer(0)
			for j := i; j < len(copy.ContainerDefinitions); j++ {
				if copy.ContainerDefinitions[j].Cpu == nil {
					copy.ContainerDefinitions[j].Cpu = &zero
				}
			}
			in = &copy
			break
		}
	}
	call, err := auditProjection(action).Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	if call.ErrorCode == "AccessDeniedException" {
		call.ErrorCode = "AccessDenied"
	}
	// ECS logs this unmodeled member on task-definition writes and on RunTask
	// outcomes whose request parameters are retained.
	if action == "RegisterTaskDefinition" || action == "DeregisterTaskDefinition" || (action == "RunTask" && in != nil) {
		var request map[string]json.RawMessage
		if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
			return err
		}
		if request == nil {
			request = make(map[string]json.RawMessage, 1)
		}
		request["dryrun"] = json.RawMessage("false")
		call.RequestParameters, err = json.Marshal(request)
		if err != nil {
			return err
		}
	}
	// Lookup aliases are distinct from the native event's resources field,
	// which is absent in these captures. Preserve caller spelling on failures.
	switch input := in.(type) {
	case *api.CreateClusterInput:
		if input != nil && input.ClusterName != nil {
			call.Resources = []journal.APIResource{{Type: "AWS::ECS::Cluster", Name: value(input.ClusterName)}}
		}
	case *api.DeleteClusterInput:
		if input != nil && input.Cluster != nil {
			call.Resources = []journal.APIResource{{Type: "AWS::ECS::Cluster", Name: value(input.Cluster)}}
		}
	case *api.UpdateClusterSettingsInput:
		if input != nil && input.Cluster != nil {
			call.Resources = []journal.APIResource{{Type: "AWS::ECS::Cluster", Name: value(input.Cluster)}}
			if output, ok := out.(*api.UpdateClusterSettingsOutput); ok && rejected == nil && output != nil && output.Cluster != nil && value(output.Cluster.ClusterName) != value(input.Cluster) {
				call.Resources = append([]journal.APIResource{{Type: "AWS::ECS::Cluster", Name: value(output.Cluster.ClusterName)}}, call.Resources...)
			}
		}
	}
	if rejected == nil {
		switch output := out.(type) {
		case *api.CreateServiceOutput:
			if output != nil && output.Service != nil {
				call.Resources = []journal.APIResource{{Type: "AWS::ECS::Service", Name: value(output.Service.ServiceArn)}}
			}
		case *api.UpdateServiceOutput:
			if output != nil && output.Service != nil {
				call.Resources = []journal.APIResource{{Type: "AWS::ECS::Service", Name: value(output.Service.ServiceArn)}}
			}
		case *api.DeleteServiceOutput:
			if output != nil && output.Service != nil {
				call.Resources = []journal.APIResource{{Type: "AWS::ECS::Service", Name: value(output.Service.ServiceArn)}}
			}
		case *api.RegisterTaskDefinitionOutput:
			if output != nil && output.TaskDefinition != nil {
				call.Resources = []journal.APIResource{{Type: "AWS::ECS::TaskDefinition", Name: value(output.TaskDefinition.TaskDefinitionArn)}}
			}
		case *api.DeregisterTaskDefinitionOutput:
			if output != nil && output.TaskDefinition != nil {
				call.Resources = []journal.APIResource{{Type: "AWS::ECS::TaskDefinition", Name: value(output.TaskDefinition.TaskDefinitionArn)}}
			}
		}
	}
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
