package s3

import (
	"context"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) getBucketCors(ctx context.Context, in *api.GetBucketCorsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketCors", value(in.Bucket), "", "cors")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketCORS", "", nil); w != nil {
			return w
		}
		rules, err := tx.BucketCORS(b.Key)
		if err != nil {
			return err
		}
		if len(rules) == 0 {
			wire := failure("NoSuchCORSConfiguration", "The CORS configuration does not exist", 404)
			wire.BucketName = c.bucket
			return wire
		}
		result := &api.GetBucketCorsOutput{CORSRules: make(api.CORSRules, len(rules))}
		for i, rule := range rules {
			result.CORSRules[i] = api.CORSRule{
				ID: (*api.ID)(rule.ID), MaxAgeSeconds: (*api.MaxAgeSeconds)(rule.MaxAgeSeconds),
				AllowedOrigins: corsStrings[api.AllowedOrigin](rule.AllowedOrigins),
				AllowedMethods: corsStrings[api.AllowedMethod](rule.AllowedMethods),
				AllowedHeaders: corsStrings[api.AllowedHeader](rule.AllowedHeaders),
				ExposeHeaders:  corsStrings[api.ExposeHeader](rule.ExposeHeaders),
			}
		}
		return out.prepare(c, result)
	})
	return out, wire
}

func (s *Service) putBucketCors(ctx context.Context, in *api.PutBucketCorsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketCors", value(in.Bucket), "", "cors")
	corsParameters(c, in.CORSConfiguration)
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutBucketCORS", "", nil); w != nil {
			return w
		}
		request, _ := awsapi.FromContext(ctx)
		if len(request.Body) > 65536 {
			wire := failure("MaxMessageLengthExceeded", "Your request was too big.", 400)
			wire.MaxMessageLengthBytes = 65536
			return wire
		}
		config := in.CORSConfiguration
		if len(config.CORSRules) == 0 {
			return malformedXML()
		}
		if len(config.CORSRules) > 100 {
			return failure("InvalidRequest", "The number of CORS rules should not exceed allowed limit of 100 rules.", 400)
		}
		rules := make([]CORSRule, len(config.CORSRules))
		for i, rule := range config.CORSRules {
			if w := validateCORSRule(rule); w != nil {
				return w
			}
			rules[i] = CORSRule{
				ID: (*string)(rule.ID), MaxAgeSeconds: (*int32)(rule.MaxAgeSeconds),
				AllowedOrigins: corsStrings[string](rule.AllowedOrigins),
				AllowedMethods: corsStrings[string](rule.AllowedMethods),
				AllowedHeaders: corsStrings[string](rule.AllowedHeaders),
				ExposeHeaders:  corsStrings[string](rule.ExposeHeaders),
			}
		}
		if err := tx.ReplaceBucketCORS(b.Key, rules); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketCorsOutput{})
	})
	return out, wire
}

func (s *Service) deleteBucketCors(ctx context.Context, in *api.DeleteBucketCorsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeleteBucketCors", value(in.Bucket), "", "cors")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutBucketCORS", "", nil); w != nil {
			return w
		}
		if err := tx.ReplaceBucketCORS(b.Key, nil); err != nil {
			return err
		}
		return out.prepare(c, &api.DeleteBucketCorsOutput{})
	})
	return out, wire
}

func corsStrings[To, From ~string](in []From) []To {
	if in == nil {
		return nil
	}
	out := make([]To, len(in))
	for i, text := range in {
		out[i] = To(text)
	}
	return out
}

func validateCORSRule(rule api.CORSRule) *awswire.Error {
	if len(rule.AllowedMethods) == 0 || len(rule.AllowedOrigins) == 0 {
		return malformedXML()
	}
	for _, method := range rule.AllowedMethods {
		switch method {
		case "GET", "HEAD", "PUT", "POST", "DELETE":
		default:
			return failure("InvalidRequest", "Found unsupported HTTP method in CORS config. Unsupported method is "+string(method), 400)
		}
	}
	for _, origin := range rule.AllowedOrigins {
		if strings.Count(string(origin), "*") > 1 {
			return failure("InvalidRequest", "AllowedOrigin \""+string(origin)+"\" can not have more than one wildcard.", 400)
		}
	}
	for _, header := range rule.AllowedHeaders {
		if strings.Count(string(header), "*") > 1 {
			return failure("InvalidRequest", "AllowedHeader \""+string(header)+"\" can not have more than one wildcard.", 400)
		}
		if !corsHeaderToken(string(header)) {
			return failure("InvalidRequest", "AllowedHeader \""+string(header)+"\" contains invalid character.", 400)
		}
	}
	for _, header := range rule.ExposeHeaders {
		if strings.Contains(string(header), "*") {
			return failure("InvalidRequest", "ExposeHeader \""+string(header)+"\" contains wildcard. We currently do not support wildcard for ExposeHeader.", 400)
		}
		if !corsHeaderToken(string(header)) {
			return failure("InvalidRequest", "ExposeHeader \""+string(header)+"\" contains invalid character.", 400)
		}
	}
	return nil
}

// CloudTrail projects XML singleton elements as scalars, not SDK arrays.
func corsParameters(c *apiCall, config *api.CORSConfiguration) {
	c.params["cors"] = ""
	if config == nil {
		return
	}
	document := map[string]any{"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/"}
	for _, rule := range config.CORSRules {
		entry := map[string]any{}
		corsAuditList(entry, "AllowedMethod", rule.AllowedMethods)
		corsAuditList(entry, "AllowedOrigin", rule.AllowedOrigins)
		corsAuditList(entry, "AllowedHeader", rule.AllowedHeaders)
		corsAuditList(entry, "ExposeHeader", rule.ExposeHeaders)
		if rule.ID != nil {
			entry["ID"] = xmlAuditScalar(string(*rule.ID))
		}
		if rule.MaxAgeSeconds != nil {
			entry["MaxAgeSeconds"] = *rule.MaxAgeSeconds
		}
		var projected any = entry
		if len(entry) == 0 {
			projected = ""
		}
		appendNotificationElement(document, "CORSRule", projected)
	}
	c.params["CORSConfiguration"] = document
}

func corsAuditList[T ~string](document map[string]any, name string, values []T) {
	for _, value := range values {
		projected := xmlAuditScalar(string(value))
		if projected != nil {
			appendNotificationElement(document, name, projected)
		}
	}
}
