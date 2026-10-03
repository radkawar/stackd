package codebuild

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awscatalog"
	"stackd/journal"
)

const auditHidden = "HIDDEN_DUE_TO_SECURITY_REASONS"

func (s *Service) RequestErrorInput(operation awscatalog.Operation, request awsapi.Request) any {
	if s.recorder == nil {
		return nil
	}
	input, err := api.NewInput(string(operation.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("codebuild")
	if err := awsapi.BindJSON(model, operation.Input, request.JSON, input); err != nil {
		return nil
	}
	return input
}

var auditRequestDocument = func() awsapi.DocumentProjection {
	fields := map[string]awsapi.FieldProjection{
		"token":                 {Mode: awsapi.RedactValueField},
		"tags":                  {Mode: awsapi.RedactValueField},
		"encryptionKey":         {Mode: awsapi.RedactValueField},
		"encryptionKeyOverride": {Mode: awsapi.RedactValueField},
		"buildspecOverride":     {Mode: awsapi.RedactValueField},
	}
	for _, source := range []string{"source", "secondarySources", "secondarySourcesOverride"} {
		fields[source+".buildspec"] = awsapi.FieldProjection{Mode: awsapi.RedactValueField}
	}
	for _, variables := range []string{"environment.environmentVariables", "environmentVariablesOverride"} {
		for _, field := range []string{"name", "value", "type"} {
			fields[variables+"."+field] = awsapi.FieldProjection{Mode: awsapi.RedactValueField}
		}
	}
	return awsapi.DocumentProjection{Fields: fields}
}()

var auditProjectDocument = func() awsapi.DocumentProjection {
	fields := make(map[string]awsapi.FieldProjection, len(auditRequestDocument.Fields)+3)
	for name, field := range auditRequestDocument.Fields {
		fields["project."+name] = field
	}
	fields["project.created"] = awsapi.FieldProjection{TimeLayout: time.RFC3339}
	fields["project.lastModified"] = awsapi.FieldProjection{TimeLayout: time.RFC3339}
	fields["project.projectVisibility"] = awsapi.FieldProjection{Mode: awsapi.OmitField}
	return awsapi.DocumentProjection{Fields: fields}
}()

var auditBuildDocument = func() awsapi.DocumentProjection {
	fields := make(map[string]awsapi.FieldProjection, len(auditRequestDocument.Fields)+6)
	for name, field := range auditRequestDocument.Fields {
		fields["build."+name] = field
	}
	for _, name := range []string{"name", "value"} {
		fields["build.exportedEnvironmentVariables."+name] = awsapi.FieldProjection{Mode: awsapi.RedactValueField}
	}
	for _, name := range []string{"startTime", "endTime", "phases.startTime", "phases.endTime"} {
		fields["build."+name] = awsapi.FieldProjection{TimeLayout: time.RFC3339}
	}
	return awsapi.DocumentProjection{Fields: fields}
}()

var auditPublicResponse = awsapi.DocumentProjection{}

func auditProjection(action string) apievents.Projection {
	// Native retains SourceAuth.type/resource, including in rejected requests.
	// These resource selectors must not be mistaken for ImportSourceCredentials.token.
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "List") || strings.HasPrefix(action, "BatchGet"), Request: auditRequestDocument}
	switch action {
	case "CreateProject", "UpdateProject":
		p.Response = &auditProjectDocument
	case "BatchDeleteBuilds":
		p.Response = &auditPublicResponse
	case "StartBuild", "StopBuild":
		p.Response = &auditBuildDocument
	}
	return p
}

func auditProjectARN(scope Scope, name string) string {
	if strings.HasPrefix(name, "arn:") {
		return name
	}
	return (ProjectKey{scope, name}).ARN()
}

func auditProjectResources(scope Scope, input any) []journal.APIEventResource {
	var names api.ProjectNames
	switch in := input.(type) {
	case *api.BatchGetProjectsInput:
		names = in.Names
	case *api.ListBuildsForProjectInput:
		if in.ProjectName != nil {
			names = api.ProjectNames{*in.ProjectName}
		}
	case *api.BatchGetBuildsInput:
		seen := map[string]bool{}
		for _, id := range in.Ids {
			name := string(id)
			if _, suffix, ok := strings.Cut(name, ":build/"); ok {
				name = suffix
			}
			name, _, _ = strings.Cut(name, ":")
			if !seen[name] {
				names = append(names, api.NonEmptyString(name))
				seen[name] = true
			}
		}
	}
	resources := make([]journal.APIEventResource, 0, len(names))
	for _, name := range names {
		resources = append(resources, journal.APIEventResource{AccountID: scope.AccountID, Type: "AWS::CodeBuild::Project", ARN: auditProjectARN(scope, string(name))})
	}
	return resources
}

func auditEnvironmentDefaults(environment map[string]any) {
	if environment == nil {
		return
	}
	if _, present := environment["privilegedMode"]; !present {
		environment["privilegedMode"] = false
	}
	if _, present := environment["imagePullCredentialsType"]; !present {
		environment["imagePullCredentialsType"] = "CODEBUILD"
	}
}

func completeAuditProjection(scope Scope, action string, call *journal.APICallCompleted) error {
	if action == "BatchDeleteBuilds" && call.ErrorCode == "" {
		var response map[string]any
		if err := json.Unmarshal(call.ResponseElements, &response); err != nil {
			return err
		}
		for _, field := range []string{"buildsDeleted", "buildsNotDeleted"} {
			if _, present := response[field]; !present {
				response[field] = []any{}
			}
		}
		var err error
		call.ResponseElements, err = json.Marshal(response)
		return err
	}
	if action != "CreateProject" && action != "UpdateProject" && action != "DeleteProject" {
		return nil
	}
	var request map[string]any
	if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
		return err
	}
	if name, ok := request["name"].(string); ok {
		request["name"] = auditProjectARN(scope, name)
	}
	if action == "CreateProject" {
		environment, _ := request["environment"].(map[string]any)
		auditEnvironmentDefaults(environment)
		if call.ErrorCode == "" {
			request["encryptionKey"] = auditHidden
		}
	}
	var err error
	call.RequestParameters, err = json.Marshal(request)
	if err != nil || call.ErrorCode != "" {
		return err
	}
	if action == "DeleteProject" {
		call.ResponseElements = json.RawMessage(`{"webhookDeletedStatus":"no_webhook"}`)
		return nil
	}
	var response map[string]any
	if err := json.Unmarshal(call.ResponseElements, &response); err != nil {
		return err
	}
	project, _ := response["project"].(map[string]any)
	if project != nil {
		project["encryptionKey"] = auditHidden
		project["badge"] = map[string]any{"badgeEnabled": false}
		if environment, ok := project["environment"].(map[string]any); ok {
			auditEnvironmentDefaults(environment)
		}
		if source, ok := project["source"].(map[string]any); ok {
			if _, present := source["insecureSsl"]; !present {
				source["insecureSsl"] = false
			}
		}
		if logs, ok := project["logsConfig"].(map[string]any); ok {
			if s3, ok := logs["s3Logs"].(map[string]any); ok {
				if _, present := s3["encryptionDisabled"]; !present {
					s3["encryptionDisabled"] = false
				}
			}
		}
		if secondary, present := request["secondarySources"]; present {
			project["secondarySources"] = secondary
		}
	}
	if action == "UpdateProject" {
		response["webhookDeletedStatus"] = "no_webhook"
	}
	call.ResponseElements, err = json.Marshal(response)
	return err
}

// The native build response includes artifact intent and log configuration that
// the public Build DTO does not model. Use the command's retained record, not a
// later project lookup: overrides and subsequent project edits must not alter it.
func completeBuildAudit(record *BuildRecord, call *journal.APICallCompleted) error {
	var response map[string]any
	if err := json.Unmarshal(call.ResponseElements, &response); err != nil {
		return err
	}
	build := response["build"].(map[string]any)
	if call.EventName == "StartBuild" {
		var request map[string]any
		if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
			return err
		}
		if limit, present := request["autoRetryLimitOverride"]; present {
			build["autoRetryConfig"] = map[string]any{"autoRetryLimit": limit, "autoRetryNumber": 0}
		}
	}
	build["encryptionKey"] = auditHidden
	if _, present := build["secondarySources"]; !present {
		build["secondarySources"] = []any{}
	}
	if _, present := build["secondarySourceVersions"]; !present {
		build["secondarySourceVersions"] = []any{}
	}
	if source, ok := build["source"].(map[string]any); ok {
		if _, present := source["insecureSsl"]; !present {
			source["insecureSsl"] = false
		}
	}
	if environment, ok := build["environment"].(map[string]any); ok {
		auditEnvironmentDefaults(environment)
		for _, phase := range record.Data.Phases {
			if value(phase.PhaseType) == "DOWNLOAD_SOURCE" && value(phase.PhaseStatus) == "SUCCEEDED" {
				environment["customEntrypoint"] = true
				break
			}
		}
	}
	artifacts, _ := build["artifacts"].(map[string]any)
	if artifacts == nil {
		artifacts = map[string]any{}
		build["artifacts"] = artifacts
	}
	artifacts["type"] = strings.ToLower(value(record.Artifacts.Type))
	if value(record.Artifacts.Type) == "NO_ARTIFACTS" {
		artifacts["location"] = ""
	} else {
		artifacts["name"] = value(record.Artifacts.Name)
		artifacts["path"] = value(record.Artifacts.Path)
		artifacts["packaging"] = strings.ToLower(value(record.Artifacts.Packaging))
		namespace := strings.ToLower(value(record.Artifacts.NamespaceType))
		if namespace == "build_id" {
			namespace = "buildId"
		}
		artifacts["namespaceType"] = namespace
		if _, present := artifacts["location"]; !present {
			artifacts["location"] = "arn:" + record.Key.Partition + ":s3:::" + value(record.Artifacts.Location) + "/" + artifactKey(record, record.Artifacts, "")
		}
		if _, present := artifacts["encryptionDisabled"]; !present {
			artifacts["encryptionDisabled"] = record.Artifacts.EncryptionDisabled != nil && *record.Artifacts.EncryptionDisabled
		}
	}
	logs, _ := build["logs"].(map[string]any)
	if logs == nil {
		logs = map[string]any{}
		build["logs"] = logs
	}
	model, _ := awscatalog.LookupService("codebuild")
	configJSON, err := awsapi.EncodeDocument(model, "com.amazonaws.codebuild#LogsConfig", &record.Logs, &auditPublicResponse)
	if err != nil {
		return err
	}
	var config map[string]any
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return err
	}
	for key, value := range config {
		logs[key] = value
	}
	if s3, ok := logs["s3Logs"].(map[string]any); ok {
		if _, present := s3["encryptionDisabled"]; !present {
			s3["encryptionDisabled"] = false
		}
	}
	if record.Logs.CloudWatchLogs != nil && value(record.Logs.CloudWatchLogs.Status) == "ENABLED" {
		group, stream := "null", "null"
		deepLink := "https://console.aws.amazon.com/cloudwatch/home?region=" + record.Key.Region + "#logsV2:log-groups"
		if record.Data.Logs != nil && record.Data.Logs.GroupName != nil {
			group, stream = value(record.Data.Logs.GroupName), value(record.Data.Logs.StreamName)
			escape := func(value string) string {
				return strings.ReplaceAll(url.QueryEscape(url.QueryEscape(value)), "%", "$")
			}
			deepLink += "/log-group/" + escape(group) + "/log-events/" + escape(stream)
		}
		logs["deepLink"] = deepLink
		logs["cloudWatchLogsArn"] = "arn:" + record.Key.Partition + ":logs:" + record.Key.Region + ":" + record.Key.AccountID + ":log-group:" + group + ":log-stream:" + stream
	}
	call.ResponseElements, err = json.Marshal(response)
	return err
}
