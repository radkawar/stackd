package integrations

import (
	"fmt"

	api "stackd/internal/awsapi/s3"
)

// cfnS3Cors follows the AWS::S3::Bucket CorsConfiguration registry shape. The
// S3 owner validates origins, methods and headers through PutBucketCors.
type cfnS3Cors struct{ CorsRules []cfnS3CorsRule }
type cfnS3CorsRule struct {
	ID             string `json:"Id"`
	AllowedHeaders []string
	AllowedMethods []string
	AllowedOrigins []string
	ExposedHeaders []string
	MaxAge         *cfnMessagingInt
}

func cfnS3CorsStrings[T ~string](values []string) []T {
	if values == nil {
		return nil
	}
	out := make([]T, len(values))
	for i, value := range values {
		out[i] = T(value)
	}
	return out
}

func (p *cfnS3Cors) native() (*api.CORSConfiguration, error) {
	if p == nil {
		return nil, nil
	}
	if len(p.CorsRules) == 0 {
		return nil, fmt.Errorf("CorsConfiguration requires CorsRules")
	}
	out := &api.CORSConfiguration{CORSRules: make(api.CORSRules, 0, len(p.CorsRules))}
	for _, rule := range p.CorsRules {
		if len(rule.AllowedMethods) == 0 || len(rule.AllowedOrigins) == 0 {
			return nil, fmt.Errorf("CORS rules require AllowedMethods and AllowedOrigins")
		}
		native := api.CORSRule{
			AllowedHeaders: cfnS3CorsStrings[api.AllowedHeader](rule.AllowedHeaders),
			AllowedMethods: cfnS3CorsStrings[api.AllowedMethod](rule.AllowedMethods),
			AllowedOrigins: cfnS3CorsStrings[api.AllowedOrigin](rule.AllowedOrigins),
			ExposeHeaders:  cfnS3CorsStrings[api.ExposeHeader](rule.ExposedHeaders),
		}
		if rule.ID != "" {
			native.ID = new(api.ID(rule.ID))
		}
		if rule.MaxAge != nil {
			if *rule.MaxAge < 0 || *rule.MaxAge > 2147483647 {
				return nil, fmt.Errorf("CORS MaxAge must be a nonnegative 32-bit integer")
			}
			native.MaxAgeSeconds = new(api.MaxAgeSeconds(*rule.MaxAge))
		}
		out.CORSRules = append(out.CORSRules, native)
	}
	return out, nil
}

func cfnS3ReadCorsStrings[T ~string](values []T) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = string(value)
	}
	return out
}

func cfnS3ReadCors(out *api.GetBucketCorsOutput) map[string]any {
	rules := make([]any, 0, len(out.CORSRules))
	for _, rule := range out.CORSRules {
		p := map[string]any{"AllowedMethods": cfnS3ReadCorsStrings(rule.AllowedMethods), "AllowedOrigins": cfnS3ReadCorsStrings(rule.AllowedOrigins)}
		if len(rule.AllowedHeaders) != 0 {
			p["AllowedHeaders"] = cfnS3ReadCorsStrings(rule.AllowedHeaders)
		}
		if len(rule.ExposeHeaders) != 0 {
			p["ExposedHeaders"] = cfnS3ReadCorsStrings(rule.ExposeHeaders)
		}
		if rule.ID != nil {
			p["Id"] = string(*rule.ID)
		}
		if rule.MaxAgeSeconds != nil {
			p["MaxAge"] = int32(*rule.MaxAgeSeconds)
		}
		rules = append(rules, p)
	}
	return map[string]any{"CorsRules": rules}
}
