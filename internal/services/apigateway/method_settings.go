package apigateway

import (
	"strings"

	api "stackd/internal/awsapi/apigateway"
)

func methodSettingsOutput(settings map[string]MethodSettings) api.MapOfMethodSettings {
	out := make(api.MapOfMethodSettings, len(settings))
	for key, setting := range settings {
		out[api.String(key)] = api.MethodSetting{
			MetricsEnabled: new(api.Boolean(setting.MetricsEnabled)), LoggingLevel: optional(setting.LoggingLevel), DataTraceEnabled: new(api.Boolean(setting.DataTraceEnabled)),
			ThrottlingBurstLimit: new(api.Integer(5000)), ThrottlingRateLimit: new(api.Double(10000)),
			CachingEnabled: new(api.Boolean(false)), CacheTtlInSeconds: new(api.Integer(300)), CacheDataEncrypted: new(api.Boolean(false)),
			RequireAuthorizationForCacheControl:    new(api.Boolean(true)),
			UnauthorizedCacheControlHeaderStrategy: new(api.UnauthorizedCacheControlHeaderStrategySUCCEED_WITH_RESPONSE_HEADER),
		}
	}
	return out
}

func patchMethodSetting(p api.PatchOperation, suffix string, row *StageRecord) error {
	key := strings.TrimPrefix(strings.TrimSuffix(value(p.Path), suffix), "/")
	separator := strings.LastIndexByte(key, '/')
	if separator < 1 || separator == len(key)-1 {
		return bad("Method settings must identify a resource path and HTTP method")
	}
	if _, err := pointerPart(key[:separator]); err != nil {
		return err
	}
	var text string
	if err := replace(p, &text); err != nil {
		return err
	}
	if row.MethodSettings == nil {
		row.MethodSettings = map[string]MethodSettings{}
	}
	setting := row.MethodSettings[key]
	switch suffix {
	case "/metrics/enabled":
		// Native metrics/enabled and logging/dataTrace coerce other strings to
		// false; this is not the admission rule for every boolean patch.
		setting.MetricsEnabled = strings.EqualFold(text, "true")
	case "/logging/dataTrace":
		setting.DataTraceEnabled = strings.EqualFold(text, "true")
	case "/logging/loglevel":
		switch text {
		case "OFF", "ERROR", "INFO":
			setting.LoggingLevel = text
		default:
			return bad("Invalid logging level specified: " + text)
		}
	}
	row.MethodSettings[key] = setting
	return nil
}

func removeMethodSetting(p api.PatchOperation, row *StageRecord) error {
	var ignored string
	if err := patchString(p, &ignored, "remove"); err != nil {
		return err
	}
	delete(row.MethodSettings, strings.TrimPrefix(value(p.Path), "/"))
	return nil
}

func effectiveMethodSettings(settings map[string]MethodSettings, path, method string) MethodSettings {
	var selected MethodSettings
	score, selectedKey := -1, ""
	for key, setting := range settings {
		separator := strings.LastIndexByte(key, '/')
		if separator < 1 || separator == len(key)-1 {
			continue
		}
		resource, err := pointerPart(key[:separator])
		if err != nil {
			continue
		}
		verb := key[separator+1:]
		rank := 0
		if resource != "*" {
			if "/"+strings.TrimPrefix(resource, "/") != path {
				continue
			}
			rank += 2
		}
		if verb != "*" {
			if verb != method {
				continue
			}
			rank++
		}
		if rank > score || rank == score && key < selectedKey {
			selected, score, selectedKey = setting, rank, key
		}
	}
	return selected
}
