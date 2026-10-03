package s3

import (
	"database/sql"
	"errors"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) BucketCORS(key domain.BucketKey) ([]domain.CORSRule, error) {
	rows, err := r.q.GetBucketCORSRules(r.ctx, sqlcgen.GetBucketCORSRulesParams{Partition: key.Partition, BucketName: key.Name})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	out := make([]domain.CORSRule, len(rows))
	for i, row := range rows {
		out[i] = domain.CORSRule{ID: row.ID, MaxAgeSeconds: row.MaxAgeSeconds}
	}
	values, err := r.q.GetBucketCORSValues(r.ctx, sqlcgen.GetBucketCORSValuesParams{Partition: key.Partition, BucketName: key.Name})
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		rule := &out[value.RulePosition]
		switch value.Kind {
		case "origin":
			rule.AllowedOrigins = append(rule.AllowedOrigins, value.Value)
		case "method":
			rule.AllowedMethods = append(rule.AllowedMethods, value.Value)
		case "allowed_header":
			rule.AllowedHeaders = append(rule.AllowedHeaders, value.Value)
		case "expose_header":
			rule.ExposeHeaders = append(rule.ExposeHeaders, value.Value)
		}
	}
	return out, nil
}

func (w writer) ReplaceBucketCORS(key domain.BucketKey, rules []domain.CORSRule) error {
	if err := w.q.DeleteBucketCORS(w.ctx, sqlcgen.DeleteBucketCORSParams{Partition: key.Partition, BucketName: key.Name}); err != nil {
		return err
	}
	for i, rule := range rules {
		if err := w.q.PutBucketCORSRule(w.ctx, sqlcgen.PutBucketCORSRuleParams{
			Partition: key.Partition, BucketName: key.Name, Position: int64(i), ID: rule.ID, MaxAgeSeconds: rule.MaxAgeSeconds,
		}); err != nil {
			return err
		}
		for _, list := range []struct {
			kind   string
			values []string
		}{
			{"origin", rule.AllowedOrigins}, {"method", rule.AllowedMethods},
			{"allowed_header", rule.AllowedHeaders}, {"expose_header", rule.ExposeHeaders},
		} {
			for position, value := range list.values {
				if err := w.q.PutBucketCORSValue(w.ctx, sqlcgen.PutBucketCORSValueParams{
					Partition: key.Partition, BucketName: key.Name, RulePosition: int64(i),
					Kind: list.kind, Position: int64(position), Value: value,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (r reader) BucketWebsite(key domain.BucketKey) (*domain.WebsiteConfiguration, error) {
	row, err := r.q.GetBucketWebsite(r.ctx, sqlcgen.GetBucketWebsiteParams{Partition: key.Partition, BucketName: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &domain.WebsiteConfiguration{IndexSuffix: row.IndexSuffix, ErrorKey: row.ErrorKey}
	if row.RedirectHost != nil {
		out.RedirectAll = &domain.WebsiteRedirectAll{HostName: *row.RedirectHost, Protocol: row.RedirectProtocol}
	}
	rules, err := r.q.GetBucketWebsiteRules(r.ctx, sqlcgen.GetBucketWebsiteRulesParams{Partition: key.Partition, BucketName: key.Name})
	if err != nil {
		return nil, err
	}
	out.Rules = make([]domain.WebsiteRoutingRule, len(rules))
	for i, rule := range rules {
		out.Rules[i].Redirect = domain.WebsiteRedirect{
			HostName: rule.RedirectHost, Protocol: rule.RedirectProtocol, StatusCode: rule.RedirectCode,
			ReplaceKeyPrefix: rule.ReplaceKeyPrefix, ReplaceKey: rule.ReplaceKey,
		}
		if rule.HasCondition {
			out.Rules[i].Condition = &domain.WebsiteCondition{KeyPrefix: rule.ConditionPrefix, ErrorCode: rule.ConditionError}
		}
	}
	return out, nil
}

func (w writer) ReplaceBucketWebsite(key domain.BucketKey, config *domain.WebsiteConfiguration) error {
	if err := w.q.DeleteBucketWebsite(w.ctx, sqlcgen.DeleteBucketWebsiteParams{Partition: key.Partition, BucketName: key.Name}); err != nil {
		return err
	}
	if config == nil {
		return nil
	}
	params := sqlcgen.PutBucketWebsiteParams{Partition: key.Partition, BucketName: key.Name, IndexSuffix: config.IndexSuffix, ErrorKey: config.ErrorKey}
	if config.RedirectAll != nil {
		params.RedirectHost = &config.RedirectAll.HostName
		params.RedirectProtocol = config.RedirectAll.Protocol
	}
	if err := w.q.PutBucketWebsite(w.ctx, params); err != nil {
		return err
	}
	for i, rule := range config.Rules {
		params := sqlcgen.PutBucketWebsiteRuleParams{
			Partition: key.Partition, BucketName: key.Name, Position: int64(i), HasCondition: rule.Condition != nil,
			RedirectHost: rule.Redirect.HostName, RedirectProtocol: rule.Redirect.Protocol, RedirectCode: rule.Redirect.StatusCode,
			ReplaceKeyPrefix: rule.Redirect.ReplaceKeyPrefix, ReplaceKey: rule.Redirect.ReplaceKey,
		}
		if rule.Condition != nil {
			params.ConditionPrefix, params.ConditionError = rule.Condition.KeyPrefix, rule.Condition.ErrorCode
		}
		if err := w.q.PutBucketWebsiteRule(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}
