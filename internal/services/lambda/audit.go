package lambda

import (
	"context"
	"encoding/json"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Date/version spellings come from the native captures and Lambda's CloudTrail
// documentation; the legacy read spellings follow their versioned API models.
var auditProjections = map[string]apievents.Projection{
	"CreateFunction":                     {EventName: "CreateFunction20150331", Category: journal.CategoryManagement, Response: &lambdaConfigurationProjection},
	"GetFunctionConfiguration":           {EventName: "GetFunctionConfiguration20150331v2", Category: journal.CategoryManagement, ReadOnly: true},
	"GetFunction":                        {EventName: "GetFunction20150331v2", Category: journal.CategoryManagement, ReadOnly: true},
	"ListTags":                           {EventName: "ListTags20170331", Category: journal.CategoryManagement, ReadOnly: true},
	"TagResource":                        {EventName: "TagResource20170331v2", Category: journal.CategoryManagement},
	"UntagResource":                      {EventName: "UntagResource20170331v2", Category: journal.CategoryManagement},
	"ListFunctions":                      {EventName: "ListFunctions20150331", Category: journal.CategoryManagement, ReadOnly: true},
	"DeleteFunction":                     {EventName: "DeleteFunction20150331", Category: journal.CategoryManagement},
	"UpdateFunctionCode":                 {EventName: "UpdateFunctionCode20150331v2", Category: journal.CategoryManagement, Response: &lambdaConfigurationProjection},
	"UpdateFunctionConfiguration":        {EventName: "UpdateFunctionConfiguration20150331v2", Category: journal.CategoryManagement, Response: &lambdaConfigurationProjection},
	"PublishVersion":                     {EventName: "PublishVersion20150331", Category: journal.CategoryManagement, Response: &lambdaConfigurationProjection},
	"ListVersionsByFunction":             {EventName: "ListVersionsByFunction20150331", Category: journal.CategoryManagement, ReadOnly: true},
	"CreateAlias":                        {EventName: "CreateAlias20150331", Category: journal.CategoryManagement},
	"GetAlias":                           {EventName: "GetAlias20150331", Category: journal.CategoryManagement, ReadOnly: true},
	"UpdateAlias":                        {EventName: "UpdateAlias20150331", Category: journal.CategoryManagement},
	"DeleteAlias":                        {EventName: "DeleteAlias20150331", Category: journal.CategoryManagement},
	"ListAliases":                        {EventName: "ListAliases20150331", Category: journal.CategoryManagement, ReadOnly: true},
	"AddPermission":                      {EventName: "AddPermission20150331v2", Category: journal.CategoryManagement, Response: &awsapi.DocumentProjection{}},
	"GetPolicy":                          {EventName: "GetPolicy20150331v2", Category: journal.CategoryManagement, ReadOnly: true},
	"RemovePermission":                   {EventName: "RemovePermission20150331v2", Category: journal.CategoryManagement},
	"PutFunctionEventInvokeConfig":       {Category: journal.CategoryManagement},
	"UpdateFunctionEventInvokeConfig":    {Category: journal.CategoryManagement},
	"GetFunctionEventInvokeConfig":       {Category: journal.CategoryManagement, ReadOnly: true},
	"DeleteFunctionEventInvokeConfig":    {Category: journal.CategoryManagement},
	"ListFunctionEventInvokeConfigs":     {Category: journal.CategoryManagement, ReadOnly: true},
	"CreateFunctionUrlConfig":            {Category: journal.CategoryManagement, Response: &awsapi.DocumentProjection{}},
	"GetFunctionUrlConfig":               {Category: journal.CategoryManagement, ReadOnly: true},
	"UpdateFunctionUrlConfig":            {Category: journal.CategoryManagement, Response: &awsapi.DocumentProjection{}},
	"DeleteFunctionUrlConfig":            {Category: journal.CategoryManagement},
	"ListFunctionUrlConfigs":             {Category: journal.CategoryManagement, ReadOnly: true},
	"CreateEventSourceMapping":           {EventName: "CreateEventSourceMapping20150331", Category: journal.CategoryManagement, Response: &lambdaMappingProjection},
	"GetEventSourceMapping":              {EventName: "GetEventSourceMapping20150331", Category: journal.CategoryManagement, ReadOnly: true},
	"ListEventSourceMappings":            {EventName: "ListEventSourceMappings20150331", Category: journal.CategoryManagement, ReadOnly: true},
	"UpdateEventSourceMapping":           {EventName: "UpdateEventSourceMapping20150331", Category: journal.CategoryManagement, Response: &lambdaMappingProjection},
	"DeleteEventSourceMapping":           {EventName: "DeleteEventSourceMapping20150331", Category: journal.CategoryManagement, Response: &lambdaMappingProjection},
	"GetFunctionConcurrency":             {Category: journal.CategoryManagement, ReadOnly: true},
	"PutFunctionConcurrency":             {EventName: "PutFunctionConcurrency20171031", Category: journal.CategoryManagement},
	"DeleteFunctionConcurrency":          {EventName: "DeleteFunctionConcurrency20171031", Category: journal.CategoryManagement},
	"GetAccountSettings":                 {Category: journal.CategoryManagement, ReadOnly: true},
	"GetFunctionRecursionConfig":         {Category: journal.CategoryManagement, ReadOnly: true},
	"PutFunctionRecursionConfig":         {Category: journal.CategoryManagement},
	"GetRuntimeManagementConfig":         {Category: journal.CategoryManagement, ReadOnly: true},
	"PutRuntimeManagementConfig":         {Category: journal.CategoryManagement},
	"GetProvisionedConcurrencyConfig":    {Category: journal.CategoryManagement, ReadOnly: true},
	"PutProvisionedConcurrencyConfig":    {Category: journal.CategoryManagement},
	"DeleteProvisionedConcurrencyConfig": {Category: journal.CategoryManagement},
	"ListProvisionedConcurrencyConfigs":  {Category: journal.CategoryManagement, ReadOnly: true},
	"CreateCodeSigningConfig":            {Category: journal.CategoryManagement},
	"UpdateCodeSigningConfig":            {Category: journal.CategoryManagement},
	"GetCodeSigningConfig":               {Category: journal.CategoryManagement, ReadOnly: true},
	"DeleteCodeSigningConfig":            {Category: journal.CategoryManagement},
	"ListCodeSigningConfigs":             {Category: journal.CategoryManagement, ReadOnly: true},
	"GetFunctionCodeSigningConfig":       {Category: journal.CategoryManagement, ReadOnly: true},
	"PutFunctionCodeSigningConfig":       {Category: journal.CategoryManagement},
	"DeleteFunctionCodeSigningConfig":    {Category: journal.CategoryManagement},
	"ListFunctionsByCodeSigningConfig":   {Category: journal.CategoryManagement, ReadOnly: true},
	"PublishLayerVersion":                {EventName: "PublishLayerVersion20181031", Category: journal.CategoryManagement, Response: &lambdaLayerVersionProjection},
	"GetLayerVersion":                    {EventName: "GetLayerVersion20181031", Category: journal.CategoryManagement, ReadOnly: true},
	"GetLayerVersionByArn":               {EventName: "GetLayerVersionByArn20181031", Category: journal.CategoryManagement, ReadOnly: true},
	"ListLayers":                         {EventName: "ListLayers20181031", Category: journal.CategoryManagement, ReadOnly: true},
	"ListLayerVersions":                  {EventName: "ListLayerVersions20181031", Category: journal.CategoryManagement, ReadOnly: true},
	"AddLayerVersionPermission":          {EventName: "AddLayerVersionPermission20181031", Category: journal.CategoryManagement, Response: &awsapi.DocumentProjection{}},
	"GetLayerVersionPolicy":              {EventName: "GetLayerVersionPolicy20181031", Category: journal.CategoryManagement, ReadOnly: true},
	"RemoveLayerVersionPermission":       {EventName: "RemoveLayerVersionPermission20181031", Category: journal.CategoryManagement},
	"DeleteLayerVersion":                 {EventName: "DeleteLayerVersion20181031", Category: journal.CategoryManagement},
	"Invoke":                             {Category: journal.CategoryData},
	"InvokeWithResponseStream":           {Category: journal.CategoryData},
	"InvokeAsync":                        {Category: journal.CategoryData},
}

func init() {
	addCapacityAuditProjections(auditProjections)
}

var lambdaConfigurationProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Environment": {Mode: awsapi.RedactField},
}}
var lambdaRequestProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Environment":   {Mode: awsapi.RedactField},
	"InvokeArgs":    {Mode: awsapi.OmitField},
	"ClientContext": {Mode: awsapi.OmitField},
}}
var lambdaMappingProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"UUID":           {Name: "uUID"},
	"LastModified":   {TimeLayout: "Jan 2, 2006, 3:04:05 PM"},
	"FilterCriteria": {Mode: awsapi.RedactField},
}}

func projectLambdaCall(ctx context.Context, name string, input, output any, wire *awswire.Error) (journal.APICallCompleted, error) {
	projection, ok := auditProjections[name]
	if durable, durableCall := durableAuditProjection(name); durableCall {
		projection, ok = durable, true
	} else {
		projection.Request = lambdaRequestProjection
	}
	if !ok {
		return journal.APICallCompleted{}, awsapi.ErrUnknownOperation
	}
	switch name {
	case "CreateEventSourceMapping", "GetEventSourceMapping", "ListEventSourceMappings", "UpdateEventSourceMapping", "DeleteEventSourceMapping":
		projection.Request = lambdaMappingProjection
	}
	model, _ := awscatalog.LookupService("lambda")
	operation, _ := model.Operation(name)
	if in, ok := input.(*api.CreateFunctionInput); ok && in != nil && in.Environment == nil {
		// Native creation records the redacted environment even when omitted.
		projected := *in
		projected.Environment = &api.Environment{}
		input = &projected
	}
	call, err := projection.Call(model, operation, input, output, wire)
	if err != nil {
		return call, err
	}
	applyCodeSigningAudit(ctx, &call)
	projectDurableAudit(ctx, input, &call)
	call.EventID = apievents.EventID(ctx)
	if wire != nil && wire.Code == "AccessDeniedException" {
		call.ErrorCode = "AccessDenied"
	}
	return call, nil
}

func (s *Service) recordCall(ctx context.Context, name string, input, output any, wire *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	if name == "Invoke" {
		in, _ := input.(*api.InvokeInput)
		out, _ := output.(*invocationOutput)
		selected := ""
		if out != nil {
			selected = value(out.ExecutedVersion)
		}
		return s.recordInvocation(ctx, name, in, wire, selected)
	}
	if name == "InvokeWithResponseStream" {
		in, _ := input.(*api.InvokeWithResponseStreamInput)
		out, _ := output.(*invocationStream)
		selected := ""
		if out != nil {
			selected = value(out.output.ExecutedVersion)
		}
		return s.recordInvocation(ctx, name, streamingInvocationInput(in), wire, selected)
	}
	call, err := projectLambdaCall(ctx, name, input, output, wire)
	if err != nil {
		return err
	}
	scope, err := projectLayerAudit(ctx, input, &call)
	if err != nil {
		return err
	}
	var request struct {
		FunctionName string `json:"functionName"`
		Qualifier    string `json:"qualifier"`
		Name         string `json:"name"`
	}
	if json.Unmarshal(call.RequestParameters, &request) == nil && request.FunctionName != "" {
		if ref, invalid := parseFunctionReference(ctx, request.FunctionName, request.Qualifier); invalid == nil {
			key := ref.FunctionKey
			scope = ref.Scope
			// Lookup aliases are separate from document resources, and are
			// absent on native reads and event-config update/delete outcomes.
			lookup := name == "AddPermission" || name == "RemovePermission" || name == "PutFunctionEventInvokeConfig" || name == "PutFunctionConcurrency" || name == "DeleteFunctionConcurrency"
			if wire == nil {
				lookup = lookup || name == "CreateFunction" || name == "DeleteFunction" || name == "UpdateFunctionCode" || name == "UpdateFunctionConfiguration"
			}
			if lookup {
				call.Resources = []journal.APIResource{{Type: "AWS::Lambda::Function", Name: key.Name}}
			}
			if wire == nil {
				switch name {
				case "CreateAlias", "UpdateAlias":
					ref.Qualifier = request.Name
					call.Resources = []journal.APIResource{{Type: "AWS::Lambda::Alias", Name: ref.ARN()}}
				case "DeleteAlias":
					call.Resources = []journal.APIResource{{Type: "AWS::Lambda::Alias", Name: request.Name}, {Type: "AWS::Lambda::Function", Name: ref.Name}}
				}
			}
		}
	}
	tagOperation := name == "ListTags" || name == "TagResource" || name == "UntagResource"
	if tagOperation {
		var resource string
		switch in := input.(type) {
		case *api.ListTagsInput:
			if in != nil {
				resource = value(in.Resource)
			}
		case *api.TagResourceInput:
			if in != nil {
				resource = value(in.Resource)
			}
		case *api.UntagResourceInput:
			if in != nil {
				resource = value(in.Resource)
			}
		}
		if ref, invalid := parseFunctionReference(ctx, resource, ""); invalid == nil {
			scope = ref.Scope
			call.EventResources = []journal.APIEventResource{{AccountID: ref.Account, Type: "function", ARN: resource}}
			if name != "ListTags" && (wire == nil || wire.Code != "AccessDeniedException") {
				call.Resources = []journal.APIResource{{Name: resource}}
			}
		}
		if key, invalid := parseEventSourceMappingARN(ctx, resource); invalid == nil {
			scope = key.Scope
			call.EventResources = []journal.APIEventResource{{AccountID: key.Account, Type: "event-source-mapping", ARN: resource}}
			if name != "ListTags" && (wire == nil || wire.Code != "AccessDeniedException") {
				call.Resources = []journal.APIResource{{Name: resource}}
			}
		}
		if key, invalid := parseCodeSigningConfigARN(ctx, resource); invalid == nil {
			scope = key.Scope
			call.EventResources = []journal.APIEventResource{{AccountID: key.Account, Type: "code-signing-config", ARN: resource}}
			if name != "ListTags" && (wire == nil || wire.Code != "AccessDeniedException") {
				call.Resources = []journal.APIResource{{Name: resource}}
			}
		}
	}
	if (name == "GetFunctionConcurrency" || name == "GetFunction" || tagOperation) && wire != nil && wire.Code == "AccessDeniedException" {
		call.RequestParameters = nil
	}
	switch name {
	case "GetEventSourceMapping", "DeleteEventSourceMapping":
		var id string
		switch in := input.(type) {
		case *api.GetEventSourceMappingInput:
			id = value(in.UUID)
		case *api.DeleteEventSourceMappingInput:
			id = value(in.UUID)
		}
		if wire == nil || wire.Code == "AccessDeniedException" {
			key := EventSourceMappingKey{Scope: scopeFor(ctx), UUID: id}
			call.EventResources = []journal.APIEventResource{{AccountID: key.Account, Type: "event-source-mapping", ARN: key.ARN()}}
		}
	}
	switch name {
	case "CreateEventSourceMapping", "GetEventSourceMapping", "ListEventSourceMappings", "UpdateEventSourceMapping", "DeleteEventSourceMapping":
		if wire != nil && wire.Code == "AccessDeniedException" {
			call.RequestParameters = nil
		}
	}
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}, call)
}

func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, wire *awswire.Error) error {
	if _, ok := s.operations[string(request.Operation.Name)]; !ok {
		return nil
	}
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, wire)
}
