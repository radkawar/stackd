package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"stackd/internal/services/cloudformation"
)

func cfnRESTPointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}
func cfnRESTMethodPath(setting map[string]any) string {
	path := cfnComputeString(setting, "ResourcePath")
	if path == "*" || path == "/*" {
		path = "*"
	} else {
		// CFN's ResourcePath is already encoded as /~1pets~1child; permit
		// literal resource paths as well and normalize to the owner's JSON pointer.
		if strings.Contains(path, "~1") {
			path = strings.TrimPrefix(path, "/")
		} else {
			path = cfnRESTPointer(path)
		}
	}
	return path + "/" + cfnComputeString(setting, "HttpMethod")
}
func cfnRESTStagePatches(current, p map[string]any) []any {
	patches := []any{cfnRESTPatch("replace", "/description", cfnComputeString(p, "Description")), cfnRESTPatch("replace", "/deploymentId", p["DeploymentId"]), cfnRESTPatch("remove", "/variables", nil)}
	variables, _ := cfnComputeObject(p["Variables"])
	for _, key := range cfnRESTKeys(variables) {
		patches = append(patches, cfnRESTPatch("add", "/variables/"+cfnRESTPointer(key), variables[key]))
	}
	if current["AccessLogSetting"] != nil {
		patches = append(patches, cfnRESTPatch("remove", "/accessLogSettings", nil))
	}
	if access, ok := cfnComputeObject(p["AccessLogSetting"]); ok {
		patches = append(patches, cfnRESTPatch("replace", "/accessLogSettings/destinationArn", access["DestinationArn"]), cfnRESTPatch("replace", "/accessLogSettings/format", access["Format"]))
	}
	previous, _ := current["MethodSettings"].([]any)
	for _, v := range previous {
		setting, _ := cfnComputeObject(v)
		patches = append(patches, cfnRESTPatch("remove", "/"+cfnRESTMethodPath(setting), nil))
	}
	settings, _ := p["MethodSettings"].([]any)
	for _, v := range settings {
		setting, _ := cfnComputeObject(v)
		path := "/" + cfnRESTMethodPath(setting)
		patches = append(patches, cfnRESTPatch("replace", path+"/metrics/enabled", cfnComputeDefault(setting, "MetricsEnabled", false)), cfnRESTPatch("replace", path+"/logging/loglevel", cfnComputeDefault(setting, "LoggingLevel", "OFF")), cfnRESTPatch("replace", path+"/logging/dataTrace", cfnComputeDefault(setting, "DataTraceEnabled", false)))
		for _, field := range []string{"ThrottlingBurstLimit", "ThrottlingRateLimit"} {
			if value, ok := setting[field]; ok {
				wire := "burstLimit"
				if field == "ThrottlingRateLimit" {
					wire = "rateLimit"
				}
				patches = append(patches, cfnRESTPatch("replace", path+"/throttling/"+wire, value))
			}
		}
	}
	return patches
}
func (h cfnRESTGateway) configureStage(ctx context.Context, r cloudformation.ResourceRequest) error {
	current, err := h.read(ctx, r)
	if err != nil {
		return err
	}
	input, err := h.identity(r)
	if err != nil {
		return err
	}
	p := cfnComputeCopy(r.Properties, "Description", "DeploymentId", "Variables", "AccessLogSetting", "MethodSettings")
	if p["DeploymentId"] == nil {
		p["DeploymentId"] = current["DeploymentId"]
	}
	input["patchOperations"] = cfnRESTStagePatches(current, p)
	if _, err := h.call(ctx, "UpdateStage", input); err != nil {
		return err
	}
	return h.updateTags(ctx, r, current)
}
func (h cfnRESTGateway) configureDeploymentStage(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeString(r.Properties, "StageName")
	if name == "" {
		return nil
	}
	input, err := h.identity(r)
	if err != nil {
		return err
	}
	stageHandler := cfnRESTGateway{h.commands, "Stage"}
	request := r
	request.PhysicalID = fmt.Sprint(input["restApiId"]) + "/" + name
	description, _ := cfnComputeObject(r.Properties["StageDescription"])
	p := cfnComputeCopy(description, "Description", "Variables", "Tags", "AccessLogSetting", "MethodSettings", "CacheClusterEnabled", "TracingEnabled")
	p["RestApiId"], p["DeploymentId"], p["StageName"] = input["restApiId"], input["deploymentId"], name
	if description != nil && (description["MetricsEnabled"] != nil || description["LoggingLevel"] != nil || description["DataTraceEnabled"] != nil || description["ThrottlingBurstLimit"] != nil || description["ThrottlingRateLimit"] != nil) {
		settings, _ := p["MethodSettings"].([]any)
		all := cfnComputeCopy(description, "MetricsEnabled", "LoggingLevel", "DataTraceEnabled", "ThrottlingBurstLimit", "ThrottlingRateLimit")
		all["ResourcePath"], all["HttpMethod"] = "/*", "*"
		p["MethodSettings"] = append([]any{all}, settings...)
	}
	request.Properties = p
	// CreateDeployment creates/moves its stage transactionally. Recovery can also
	// recreate a stage removed after the deployment commit, without resnapshotting.
	deploymentCtx := h.context(ctx, r, true, false, nil)
	_, err = stageHandler.read(deploymentCtx, request)
	if cfnRESTMissing(err) {
		stageInput := cfnRESTInput(p, "RestApiId", "DeploymentId", "StageName", "Description", "Variables", "CacheClusterEnabled", "TracingEnabled")
		stageInput["tags"] = cfnRESTUserTags(request)
		if _, err = stageHandler.call(stageHandler.context(ctx, request, false, false, nil), "CreateStage", stageInput); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	// Keep the Deployment binding for convergence: existing native stages retain
	// their owner, and separately owned stages cannot lend this request authority.
	return stageHandler.configureStage(deploymentCtx, request)
}
func cfnRESTUsagePatches(current, p map[string]any) []any {
	patches := []any{cfnRESTPatch("replace", "/name", cfnComputeDefault(p, "UsagePlanName", current["UsagePlanName"])), cfnRESTPatch("replace", "/description", cfnComputeString(p, "Description"))}
	for _, key := range []string{"Throttle", "Quota"} {
		base := "/" + cfnRESTWire(key)
		if current[key] != nil {
			patches = append(patches, cfnRESTPatch("remove", base, nil))
		}
		if settings, ok := cfnComputeObject(p[key]); ok {
			fields := []string{"BurstLimit", "RateLimit"}
			if key == "Quota" {
				fields = []string{"Limit", "Offset", "Period"}
			}
			for _, field := range fields {
				v, ok := settings[field]
				if !ok && (key == "Throttle" || field == "Offset") {
					v, ok = 0, true
				}
				if ok {
					patches = append(patches, cfnRESTPatch("replace", base+"/"+cfnRESTWire(field), v))
				}
			}
		}
	}
	for _, stage := range cfnRESTStageList(current, "ApiStages", "ApiId", "Stage", ":") {
		patches = append(patches, cfnRESTPatch("remove", "/apiStages", stage))
	}
	stages, _ := p["ApiStages"].([]any)
	for _, v := range stages {
		stage, _ := cfnComputeObject(v)
		key := cfnComputeString(stage, "ApiId") + ":" + cfnComputeString(stage, "Stage")
		patches = append(patches, cfnRESTPatch("add", "/apiStages", key))
		if throttles, ok := cfnComputeObject(stage["Throttle"]); ok {
			wire := map[string]any{}
			for key, v := range throttles {
				setting, _ := cfnComputeObject(v)
				wire[key] = cfnRESTNestedWire(setting)
			}
			body, _ := json.Marshal(wire)
			patches = append(patches, cfnRESTPatch("replace", "/apiStages/"+key+"/throttle", string(body)))
		}
	}
	return patches
}

func cfnRESTMethodThrottleValidation(setting map[string]any) error {
	if n, ok, err := cfnAppInteger(setting, "ThrottlingBurstLimit"); err != nil {
		return err
	} else if ok && n < 0 {
		return fmt.Errorf("ThrottlingBurstLimit must be a non-negative integer")
	}
	if n, ok, err := cfnAppFloat(setting, "ThrottlingRateLimit"); err != nil {
		return err
	} else if ok && n < 0 {
		return fmt.Errorf("ThrottlingRateLimit must be a finite non-negative number")
	}
	return nil
}
