package s3

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) getBucketWebsite(ctx context.Context, in *api.GetBucketWebsiteInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketWebsite", value(in.Bucket), "", "website")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketWebsite", "", nil); w != nil {
			return w
		}
		config, err := tx.BucketWebsite(b.Key)
		if err != nil {
			return err
		}
		if config == nil {
			return noWebsite(c.bucket)
		}
		model := websiteModel(config)
		return out.prepare(c, &api.GetBucketWebsiteOutput{IndexDocument: model.IndexDocument, ErrorDocument: model.ErrorDocument, RedirectAllRequestsTo: model.RedirectAllRequestsTo, RoutingRules: model.RoutingRules})
	})
	return out, wire
}

func (s *Service) putBucketWebsite(ctx context.Context, in *api.PutBucketWebsiteInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketWebsite", value(in.Bucket), "", "website")
	websiteParameters(c, in.WebsiteConfiguration)
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutBucketWebsite", "", nil); w != nil {
			return w
		}
		config, w := admitWebsite(in.WebsiteConfiguration)
		if w != nil {
			return w
		}
		// TODO: Comeback model native website configuration propagation; no fixed delay is established.
		if err := tx.ReplaceBucketWebsite(b.Key, config); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketWebsiteOutput{})
	})
	return out, wire
}

func (s *Service) deleteBucketWebsite(ctx context.Context, in *api.DeleteBucketWebsiteInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeleteBucketWebsite", value(in.Bucket), "", "website")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "DeleteBucketWebsite", "", nil); w != nil {
			return w
		}
		if err := tx.ReplaceBucketWebsite(b.Key, nil); err != nil {
			return err
		}
		return out.prepare(c, &api.DeleteBucketWebsiteOutput{})
	})
	return out, wire
}

func noWebsite(bucket string) *awswire.Error {
	wire := failure("NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration", 404)
	wire.BucketName = bucket
	return wire
}
func websiteInvalid(message string) *awswire.Error { return failure("InvalidRequest", message, 400) }

func websiteRequestError(name string, err error) *awswire.Error {
	if name != "PutBucketWebsite" {
		return nil
	}
	var validation *awsapi.ValidationError
	if !errors.As(err, &validation) {
		return nil
	}
	if validation.Constraint == "enum" && strings.HasSuffix(validation.Path, ".Protocol") {
		return websiteInvalid("Invalid protocol, protocol can be http or https. If not defined the protocol will be selected automatically.")
	}
	if validation.Constraint == "length.min" && validation.Path == "WebsiteConfiguration.ErrorDocument.Key" {
		return argumentError("ErrorDocument", "", "The ErrorDocument Key is not well formed")
	}
	return nil
}

func admitWebsite(in *api.WebsiteConfiguration) (*WebsiteConfiguration, *awswire.Error) {
	out := &WebsiteConfiguration{}
	if redirect := in.RedirectAllRequestsTo; redirect != nil {
		if in.IndexDocument != nil || in.ErrorDocument != nil || len(in.RoutingRules) != 0 {
			return nil, argumentError("RedirectAllRequestsTo", "not null", "RedirectAllRequestsTo cannot be provided in conjunction with other Routing Rules.")
		}
		if *redirect.HostName == "" {
			return nil, websiteInvalid("A host name must be provided to redirect all requests (e.g. \"example.com\").")
		}
		out.RedirectAll = &WebsiteRedirectAll{HostName: value(redirect.HostName), Protocol: (*string)(redirect.Protocol)}
		return out, nil
	}
	if in.IndexDocument == nil {
		return nil, argumentError("IndexDocument", "null", "A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty")
	}
	suffix := value(in.IndexDocument.Suffix)
	if suffix == "" || strings.Contains(suffix, "/") {
		return nil, argumentError("IndexDocument", suffix, "The IndexDocument Suffix is not well formed")
	}
	out.IndexSuffix = new(suffix)
	if in.ErrorDocument != nil {
		out.ErrorKey = (*string)(in.ErrorDocument.Key)
	}
	if len(in.RoutingRules) > 50 {
		return nil, websiteInvalid("The number of routing rules must not exceed 50.")
	}
	for _, rule := range in.RoutingRules {
		r := WebsiteRoutingRule{}
		if condition := rule.Condition; condition != nil {
			if condition.KeyPrefixEquals == nil && condition.HttpErrorCodeReturnedEquals == nil {
				return nil, websiteInvalid("Condition cannot be empty. To redirect all requests without a condition, the condition element shouldn't be present.")
			}
			if condition.HttpErrorCodeReturnedEquals != nil {
				if w := websiteStatus(value(condition.HttpErrorCodeReturnedEquals), false); w != nil {
					return nil, w
				}
			}
			r.Condition = &WebsiteCondition{KeyPrefix: (*string)(condition.KeyPrefixEquals), ErrorCode: (*string)(condition.HttpErrorCodeReturnedEquals)}
		}
		d := rule.Redirect
		if d.ReplaceKeyWith != nil && d.ReplaceKeyPrefixWith != nil {
			return nil, websiteInvalid("You can only define ReplaceKeyPrefix or ReplaceKey but not both.")
		}
		if d.HttpRedirectCode != nil {
			if w := websiteStatus(value(d.HttpRedirectCode), true); w != nil {
				return nil, w
			}
		}
		r.Redirect = WebsiteRedirect{HostName: (*string)(d.HostName), Protocol: (*string)(d.Protocol), StatusCode: (*string)(d.HttpRedirectCode), ReplaceKey: (*string)(d.ReplaceKeyWith), ReplaceKeyPrefix: (*string)(d.ReplaceKeyPrefixWith)}
		out.Rules = append(out.Rules, r)
	}
	return out, nil
}

// Native captures sample these ranges, rather than exhaustively enumerating
// them. Admit defined HTTP codes, not arbitrary unassigned 3xx/4xx/5xx values.
func websiteStatus(text string, redirect bool) *awswire.Error {
	code, err := strconv.Atoi(text)
	if err != nil {
		return malformedXML()
	}
	valid := code >= 400 && code < 600
	kind, allowed := "error", "4XX or 5XX"
	if redirect {
		valid, kind, allowed = code > 300 && code < 400, "redirect", "3XX except 300"
	}
	if !valid || http.StatusText(code) == "" {
		return websiteInvalid(fmt.Sprintf("The provided HTTP %s code (%s) is not valid. Valid codes are %s.", kind, text, allowed))
	}
	return nil
}

func websiteModel(config *WebsiteConfiguration) *api.WebsiteConfiguration {
	out := &api.WebsiteConfiguration{}
	if config.IndexSuffix != nil {
		out.IndexDocument = &api.IndexDocument{Suffix: (*api.Suffix)(config.IndexSuffix)}
	}
	if config.ErrorKey != nil {
		out.ErrorDocument = &api.ErrorDocument{Key: (*api.ObjectKey)(config.ErrorKey)}
	}
	if d := config.RedirectAll; d != nil {
		out.RedirectAllRequestsTo = &api.RedirectAllRequestsTo{HostName: new(api.HostName(d.HostName)), Protocol: (*api.Protocol)(d.Protocol)}
	}
	for _, r := range config.Rules {
		rule := api.RoutingRule{}
		if c := r.Condition; c != nil {
			rule.Condition = &api.Condition{KeyPrefixEquals: (*api.KeyPrefixEquals)(c.KeyPrefix), HttpErrorCodeReturnedEquals: (*api.HttpErrorCodeReturnedEquals)(c.ErrorCode)}
		}
		d := r.Redirect
		rule.Redirect = &api.Redirect{HostName: (*api.HostName)(d.HostName), Protocol: (*api.Protocol)(d.Protocol), HttpRedirectCode: (*api.HttpRedirectCode)(d.StatusCode), ReplaceKeyWith: (*api.ReplaceKeyWith)(d.ReplaceKey), ReplaceKeyPrefixWith: (*api.ReplaceKeyPrefixWith)(d.ReplaceKeyPrefix)}
		out.RoutingRules = append(out.RoutingRules, rule)
	}
	return out
}

func websiteParameters(c *apiCall, in *api.WebsiteConfiguration) {
	if in == nil {
		return
	}
	doc := map[string]any{"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/"}
	if in.IndexDocument != nil {
		x := map[string]any{}
		if in.IndexDocument.Suffix != nil {
			x["Suffix"] = value(in.IndexDocument.Suffix)
		}
		doc["IndexDocument"] = websiteAuditElement(x)
	}
	if in.ErrorDocument != nil {
		x := map[string]any{}
		if in.ErrorDocument.Key != nil {
			x["Key"] = value(in.ErrorDocument.Key)
		}
		doc["ErrorDocument"] = websiteAuditElement(x)
	}
	if d := in.RedirectAllRequestsTo; d != nil {
		x := map[string]any{}
		if d.HostName != nil {
			x["HostName"] = value(d.HostName)
		}
		if d.Protocol != nil {
			x["Protocol"] = value(d.Protocol)
		}
		doc["RedirectAllRequestsTo"] = websiteAuditElement(x)
	}
	rules := make([]any, 0, len(in.RoutingRules))
	for _, r := range in.RoutingRules {
		x := map[string]any{}
		if condition := r.Condition; condition != nil {
			y := map[string]any{}
			if condition.KeyPrefixEquals != nil {
				y["KeyPrefixEquals"] = value(condition.KeyPrefixEquals)
			}
			if condition.HttpErrorCodeReturnedEquals != nil {
				y["HttpErrorCodeReturnedEquals"] = websiteAuditStatus(value(condition.HttpErrorCodeReturnedEquals))
			}
			x["Condition"] = websiteAuditElement(y)
		}
		if d := r.Redirect; d != nil {
			y := map[string]any{}
			for _, field := range [...]struct {
				name  string
				value *string
			}{
				{"HostName", (*string)(d.HostName)},
				{"Protocol", (*string)(d.Protocol)},
				{"ReplaceKeyWith", (*string)(d.ReplaceKeyWith)},
				{"ReplaceKeyPrefixWith", (*string)(d.ReplaceKeyPrefixWith)},
			} {
				if field.value != nil {
					y[field.name] = *field.value
				}
			}
			if d.HttpRedirectCode != nil {
				y["HttpRedirectCode"] = websiteAuditStatus(value(d.HttpRedirectCode))
			}
			x["Redirect"] = websiteAuditElement(y)
		}
		rules = append(rules, websiteAuditElement(x))
	}
	if len(rules) == 1 {
		doc["RoutingRules"] = map[string]any{"RoutingRule": rules[0]}
	} else if len(rules) > 1 {
		doc["RoutingRules"] = map[string]any{"RoutingRule": rules}
	}
	c.params["WebsiteConfiguration"] = doc
}
func websiteAuditStatus(value string) any {
	if n, err := strconv.Atoi(value); err == nil {
		return n
	}
	return value
}

func websiteAuditElement(fields map[string]any) any {
	if len(fields) == 0 {
		return ""
	}
	return fields
}
