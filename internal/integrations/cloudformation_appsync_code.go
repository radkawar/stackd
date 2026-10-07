package integrations

import (
	"context"
	"fmt"
	"net/url"
	"stackd/internal/services/cloudformation"
	"strings"
)

func cfnAppSyncS3Text(ctx context.Context, c StepFunctionsCommands, location string) (string, error) {
	provider, ok := c.providers["s3"]
	if !ok {
		return "", fmt.Errorf("S3 object owner unavailable")
	}
	source, ok := provider.executor.(CloudFormationTemplateObjects)
	if !ok {
		return "", fmt.Errorf("S3 object owner has no authorized reader")
	}
	if strings.HasPrefix(location, "s3://") {
		u, err := url.Parse(location)
		if err != nil || u.Host == "" || u.Path == "" {
			return "", fmt.Errorf("invalid S3 location")
		}
		location = "https://" + u.Host + ".s3.amazonaws.com" + u.EscapedPath()
		if u.RawQuery != "" {
			location += "?" + u.RawQuery
		}
	}
	return (CloudFormationTemplateSource{S3: source}).ReadTemplate(ctx, location)
}
func cfnAppSyncCodeInput(ctx context.Context, c StepFunctionsCommands, p cloudformation.Properties, fields []string) (map[string]any, error) {
	in := cfnDeveloperInput(p, fields...)
	for _, key := range []string{"Code", "RequestMappingTemplate", "ResponseMappingTemplate"} {
		s3key := key + "S3Location"
		if p[key] != nil && p[s3key] != nil {
			return nil, fmt.Errorf("%s and %s are mutually exclusive", key, s3key)
		}
		if location := cfnComputeString(p, s3key); location != "" {
			text, err := cfnAppSyncS3Text(ctx, c, location)
			if err != nil {
				return nil, err
			}
			in[cfnDeveloperWireName(key)] = text
		}
		delete(in, cfnDeveloperWireName(s3key))
	}
	return in, nil
}
