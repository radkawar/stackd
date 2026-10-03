package appconfig

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/awsctx"
)

// ExtensionRollbackError is the documented AT_DEPLOYMENT_TICK rollback directive,
// not a failed Lambda call. The deployment owner records its description.
type ExtensionRollbackError struct{ Description string }

func (e *ExtensionRollbackError) Error() string { return e.Description }

type extensionPayloadResource struct {
	ID   string `json:"Id"`
	Name string `json:"Name,omitempty"`
}
type extensionPayloadContent struct {
	ContentType    string `json:"ContentType"`
	ContentVersion string `json:"ContentVersion"`
	Content        []byte `json:"Content"`
}
type extensionPayload struct {
	InvocationID             string                    `json:"InvocationId"`
	Parameters               map[string]string         `json:"Parameters"`
	Type                     string                    `json:"Type"`
	Application              extensionPayloadResource  `json:"Application"`
	Environment              *extensionPayloadResource `json:"Environment,omitempty"`
	ConfigurationProfile     *extensionPayloadResource `json:"ConfigurationProfile,omitempty"`
	ConfigurationProfileType string                    `json:"ConfigurationProfileType,omitempty"`
	ContentType              string                    `json:"ContentType,omitempty"`
	ContentVersion           string                    `json:"ContentVersion,omitempty"`
	Content                  *[]byte                   `json:"Content,omitempty"`
	PreviousContent          *extensionPayloadContent  `json:"PreviousContent,omitempty"`
	DeploymentNumber         int32                     `json:"DeploymentNumber,omitempty"`
	Description              string                    `json:"Description"`
	ConfigurationVersion     string                    `json:"ConfigurationVersion,omitempty"`
	DeploymentState          string                    `json:"DeploymentState,omitempty"`
	PercentageComplete       string                    `json:"PercentageComplete,omitempty"`
}

var extensionEventTypes = map[string]string{
	"PRE_CREATE_HOSTED_CONFIGURATION_VERSION": "PreCreateHostedConfigurationVersion",
	"PRE_START_DEPLOYMENT":                    "PreStartDeployment",
	"AT_DEPLOYMENT_TICK":                      "AtDeploymentTick",
	"ON_DEPLOYMENT_START":                     "OnDeploymentStart",
	"ON_DEPLOYMENT_STEP":                      "OnDeploymentStep",
	"ON_DEPLOYMENT_BAKING":                    "OnDeploymentBaking",
	"ON_DEPLOYMENT_COMPLETE":                  "OnDeploymentComplete",
	"ON_DEPLOYMENT_ROLLED_BACK":               "OnDeploymentRolledBack",
}

func (s *Service) runExtensions(ctx context.Context, point string, application Application, environment *Environment, profile *Profile, content ConfigurationContent, deployment *Deployment) (ConfigurationContent, []AppliedExtension, []ActionInvocation, error) {
	eventType, ok := extensionEventTypes[point]
	if !ok {
		return content, nil, nil, failure("BadRequestException", "Unknown extension action point.")
	}
	scope := application.Scope
	var applied []AppliedExtension
	var previous *HostedVersion
	hasActions := false
	if deployment != nil && point != "PRE_START_DEPLOYMENT" {
		applied = deployment.Extensions
		for _, row := range applied {
			for _, action := range row.Actions {
				if action.Point == point {
					hasActions = true
					break
				}
			}
		}
	} else {
		err := s.repository.View(ctx, func(r Reader) error {
			associations, err := r.Associations(scope)
			if err != nil {
				return err
			}
			// Associations are scoped and ordered by their persisted identifier. Each
			// captured action is immutable for this deployment even if its catalog
			// version is updated or removed while customer code is executing.
			for _, association := range associations {
				matched := association.ResourceARN == appARN(scope, application.ID)
				if environment != nil {
					matched = matched || association.ResourceARN == envARN(scope, application.ID, environment.ID)
				}
				if profile != nil {
					matched = matched || association.ResourceARN == profileARN(scope, application.ID, profile.ID)
				}
				if !matched {
					continue
				}
				extension, err := findExtension(r, scope, association.ExtensionID, association.ExtensionVersion)
				if err != nil {
					return err
				}
				parameters := maps.Clone(association.Parameters)
				if parameters == nil {
					parameters = map[string]string{}
				}
				if point == "PRE_START_DEPLOYMENT" && deployment != nil {
					for key, values := range deployment.DynamicParameters {
						ref, name, ok := strings.Cut(key, "#")
						if !ok || len(values) != 1 {
							return failure("BadRequestException", "Invalid dynamic extension parameter.")
						}
						if ref != extension.ID && ref != extension.ARN && ref != arn(scope, "extension/"+extension.ID) {
							continue
						}
						found := false
						for _, parameter := range extension.Parameters {
							if parameter.Name == name && parameter.Dynamic {
								found = true
								break
							}
						}
						if !found {
							return failure("BadRequestException", "The extension parameter is not dynamic: "+name)
						}
						parameters[name] = values[0]
					}
				}
				applied = append(applied, AppliedExtension{AssociationID: association.ID, ExtensionID: extension.ID, Version: extension.Version, Parameters: parameters, Actions: slices.Clone(extension.Actions)})
				for _, action := range extension.Actions {
					if action.Point == point {
						hasActions = true
						break
					}
				}
			}
			if point == "PRE_START_DEPLOYMENT" && deployment != nil {
				for key := range deployment.DynamicParameters {
					ref, _, _ := strings.Cut(key, "#")
					matched := false
					for _, row := range applied {
						if ref == row.ExtensionID || ref == extensionARN(scope, row.ExtensionID, row.Version) || ref == arn(scope, "extension/"+row.ExtensionID) {
							matched = true
							break
						}
					}
					if !matched {
						return failure("BadRequestException", "Dynamic parameter does not identify an associated extension: "+ref)
					}
				}
			}
			if hasActions && point == "PRE_CREATE_HOSTED_CONFIGURATION_VERSION" && profile != nil {
				rows, err := r.HostedVersions(scope, application.ID, profile.ID)
				if err != nil {
					return err
				}
				for _, row := range rows {
					if previous == nil || row.Number > previous.Number {
						v := row
						previous = &v
					}
				}
			}
			return nil
		})
		if err != nil {
			return content, nil, nil, err
		}
	}
	if !hasActions {
		return content, applied, nil, nil
	}
	payload := extensionPayload{Type: eventType, Application: extensionPayloadResource{ID: application.ID}, Description: content.Description}
	synchronous := strings.HasPrefix(point, "PRE_") || point == "AT_DEPLOYMENT_TICK"
	if strings.HasPrefix(point, "PRE_") {
		payload.Application.Name = application.Name
		payload.ContentType = content.ContentType
		payload.ContentVersion = content.Version
		payload.Content = &content.Content
	}
	if environment != nil {
		payload.Environment = &extensionPayloadResource{ID: environment.ID}
		if strings.HasPrefix(point, "PRE_") {
			payload.Environment.Name = environment.Name
		}
	}
	if profile != nil {
		payload.ConfigurationProfile = &extensionPayloadResource{ID: profile.ID, Name: profile.Name}
		payload.ConfigurationProfileType = profile.Type
	}
	if deployment != nil {
		payload.DeploymentNumber = deployment.Number
		payload.Description = deployment.Description
		if !strings.HasPrefix(point, "PRE_") {
			payload.ConfigurationVersion = deployment.ConfigurationVersion
		}
		if point == "AT_DEPLOYMENT_TICK" {
			payload.DeploymentState = deployment.State
			payload.PercentageComplete = strconv.FormatFloat(deployment.Percentage, 'f', 1, 64)
		}
	}
	if previous != nil {
		plain := previous.Content
		if previous.KMSKeyARN != "" {
			if s.effects == nil {
				return content, applied, nil, failure("InternalServerException", "AppConfig effects are unavailable.")
			}
			var err error
			resource := profileARN(scope, application.ID, profile.ID) + "/hostedconfigurationversion/" + strconv.FormatInt(int64(previous.Number), 10)
			plain, err = s.effects.Unprotect(ctx, scope, previous.KMSKeyARN, resource, plain)
			if err != nil {
				return content, applied, nil, err
			}
		}
		payload.PreviousContent = &extensionPayloadContent{ContentType: previous.ContentType, ContentVersion: strconv.FormatInt(int64(previous.Number), 10), Content: plain}
	}
	source := appARN(scope, application.ID)
	if environment != nil {
		source = envARN(scope, application.ID, environment.ID)
	} else if profile != nil {
		source = profileARN(scope, application.ID, profile.ID)
	}
	ctx = awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "appconfig.amazonaws.com", SourceARN: source, Type: "AWSService"})
	var invocations []ActionInvocation
	for _, extension := range applied {
		for _, action := range extension.Actions {
			if action.Point != point {
				continue
			}
			invocation := ActionInvocation{ID: newID(), ExtensionID: extension.ExtensionID, ActionName: action.Name, URI: action.URI, RoleARN: action.RoleARN}
			payload.InvocationID = invocation.ID
			payload.Parameters = extension.Parameters
			request, err := json.Marshal(payload)
			var response []byte
			if err == nil {
				if s.effects == nil {
					err = failure("InternalServerException", "AppConfig effects are unavailable.")
				} else {
					response, err = s.effects.InvokeExtension(ctx, scope, action, request)
				}
			}
			if err == nil && synchronous && len(response) != 0 && string(response) != "null" {
				var result struct {
					Content                                *string
					Error, Message, Directive, Description string
				}
				if e := json.Unmarshal(response, &result); e != nil {
					err = failure("BadRequestException", "Extension returned invalid JSON.")
				} else if result.Error != "" {
					err = failure("BadRequestException", result.Error+": "+result.Message)
				} else if point == "AT_DEPLOYMENT_TICK" && result.Directive == "ROLL_BACK" {
					err = &ExtensionRollbackError{Description: result.Description}
				} else if point == "AT_DEPLOYMENT_TICK" && result.Directive != "" && result.Directive != "CONTINUE" {
					err = failure("BadRequestException", "Extension returned an invalid deployment directive.")
				} else if strings.HasPrefix(point, "PRE_") && result.Content != nil {
					decoded, e := base64.StdEncoding.DecodeString(*result.Content)
					if e != nil {
						err = failure("BadRequestException", "Extension Content must be base64 encoded.")
					} else {
						content.Content = decoded
					}
				}
			}
			if err != nil {
				wire := wireError(err)
				invocation.ErrorCode = wire.Code
				invocation.ErrorMessage = err.Error()
			}
			invocations = append(invocations, invocation)
			if err != nil {
				return content, applied, invocations, err
			}
		}
	}
	return content, applied, invocations, nil
}
