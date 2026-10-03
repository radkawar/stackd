package opensearch

import (
	domain "stackd/storage/opensearch"
	"stackd/storage/sqlite/opensearch/internal/sqlcgen"
)

func (r reader) advancedOptions(k domain.Key) (map[string]string, error) {
	rows, err := r.q.ListAdvancedOptions(r.ctx, sqlcgen.ListAdvancedOptionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.OptionKey] = row.OptionValue
	}
	return out, nil
}

func (w writer) putAdvancedOptions(k domain.Key, options map[string]string) error {
	if err := w.q.DeleteAdvancedOptions(w.ctx, sqlcgen.DeleteAdvancedOptionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for key, value := range options {
		if err := w.q.PutAdvancedOption(w.ctx, sqlcgen.PutAdvancedOptionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, OptionKey: key, OptionValue: value}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) policyPrincipals(k domain.Key) (map[string]string, error) {
	rows, err := r.q.ListPolicyPrincipals(r.ctx, sqlcgen.ListPolicyPrincipalsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.PrincipalArn] = row.PrincipalID
	}
	return out, nil
}

func (w writer) putPolicyPrincipals(k domain.Key, principals map[string]string) error {
	if err := w.q.DeletePolicyPrincipals(w.ctx, sqlcgen.DeletePolicyPrincipalsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for arn, id := range principals {
		if err := w.q.PutPolicyPrincipal(w.ctx, sqlcgen.PutPolicyPrincipalParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, PrincipalArn: arn, PrincipalID: id}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) tags(k domain.Key) (map[string]string, error) {
	rows, err := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.TagKey] = row.TagValue
	}
	return out, nil
}

func (w writer) putTags(k domain.Key, tags map[string]string) error {
	if err := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for key, value := range tags {
		if err := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	return nil
}
