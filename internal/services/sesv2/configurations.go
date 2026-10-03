package sesv2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	api "stackd/internal/awsapi/sesv2"
)

var resourceName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type pageCursor struct {
	Scope              Scope
	Collection, Filter string
	After              string
}

func page[T any](rows []T, scope Scope, collection, filter string, token *api.NextToken, size *api.MaxItems, name func(T) string) (int, int, *api.NextToken, error) {
	n := 100
	if size != nil {
		n = int(*size)
	}
	if n < 1 || n > 1000 {
		return 0, 0, nil, bad("Invalid page size.")
	}
	last := ""
	if value(token) != "" {
		raw, e := base64.RawURLEncoding.DecodeString(value(token))
		var cursor pageCursor
		if e != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Scope != scope || cursor.Collection != collection || cursor.Filter != filter || cursor.After == "" {
			return 0, 0, nil, bad("Invalid next token.")
		}
		last = cursor.After
	}
	start := sort.Search(len(rows), func(i int) bool { return name(rows[i]) > last })
	end := min(start+n, len(rows))
	var next *api.NextToken
	if end < len(rows) {
		raw, e := json.Marshal(pageCursor{Scope: scope, Collection: collection, Filter: filter, After: name(rows[end-1])})
		if e != nil {
			return 0, 0, nil, e
		}
		next = new(api.NextToken(base64.RawURLEncoding.EncodeToString(raw)))
	}
	return start, end, next, nil
}
func (s *Service) createConfigurationSet(tx Transaction, in *api.CreateConfigurationSetInput) (*api.CreateConfigurationSetOutput, error) {
	name := value(in.ConfigurationSetName)
	if !resourceName.MatchString(name) {
		return nil, bad("Invalid configuration set name.")
	}
	if in.TrackingOptions != nil || in.DeliveryOptions != nil || in.ReputationOptions != nil || in.SuppressionOptions != nil || in.VdmOptions != nil || in.ArchivingOptions != nil || in.MessageSecurityOptions != nil {
		return nil, unsupported("Only configuration-set sending options are implemented.")
	}
	k := ResourceKey{scopeFor(tx.Context()), name}
	tags, e := parseTags(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "CreateConfigurationSet", k.ARN("configuration-set"), nil, tagConditions(tags)); e != nil {
		return nil, e
	}
	if _, e = tx.ConfigurationSet(k); e == nil {
		return nil, failure("AlreadyExistsException", "Configuration set already exists.", 400)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	enabled := true
	if in.SendingOptions != nil && in.SendingOptions.SendingEnabled != nil {
		enabled = bool(*in.SendingOptions.SendingEnabled)
	}
	return &api.CreateConfigurationSetOutput{}, tx.PutConfigurationSet(ConfigurationSet{k, enabled, tags})
}
func (s *Service) getConfigurationSet(tx Transaction, in *api.GetConfigurationSetInput) (*api.GetConfigurationSetOutput, error) {
	k := ResourceKey{scopeFor(tx.Context()), value(in.ConfigurationSetName)}
	v, e := tx.ConfigurationSet(k)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "GetConfigurationSet", k.ARN("configuration-set"), v.Tags, nil); e != nil {
		return nil, e
	}
	return &api.GetConfigurationSetOutput{ConfigurationSetName: new(api.ConfigurationSetName(k.Name)), SendingOptions: &api.SendingOptions{SendingEnabled: new(api.Enabled(v.SendingEnabled))}, Tags: apiTags(v.Tags)}, nil
}
func (s *Service) deleteConfigurationSet(tx Transaction, in *api.DeleteConfigurationSetInput) (*api.DeleteConfigurationSetOutput, error) {
	k := ResourceKey{scopeFor(tx.Context()), value(in.ConfigurationSetName)}
	v, e := tx.ConfigurationSet(k)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "DeleteConfigurationSet", k.ARN("configuration-set"), v.Tags, nil); e != nil {
		return nil, e
	}
	return &api.DeleteConfigurationSetOutput{}, tx.DeleteConfigurationSet(k)
}
func (s *Service) listConfigurationSets(tx Transaction, in *api.ListConfigurationSetsInput) (*api.ListConfigurationSetsOutput, error) {
	if e := s.authorize(tx, "ListConfigurationSets", "*", nil, nil); e != nil {
		return nil, e
	}
	rows, e := tx.ConfigurationSets(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	start, end, next, e := page(rows, scopeFor(tx.Context()), "configuration-sets", "", in.NextToken, in.PageSize, func(v ConfigurationSet) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.ListConfigurationSetsOutput{ConfigurationSets: api.ConfigurationSetNameList{}, NextToken: next}
	for _, v := range rows[start:end] {
		out.ConfigurationSets = append(out.ConfigurationSets, api.ConfigurationSetName(v.Key.Name))
	}
	return out, nil
}
func (s *Service) putConfigurationSending(tx Transaction, in *api.PutConfigurationSetSendingOptionsInput) (*api.PutConfigurationSetSendingOptionsOutput, error) {
	k := ResourceKey{scopeFor(tx.Context()), value(in.ConfigurationSetName)}
	v, e := tx.ConfigurationSet(k)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "PutConfigurationSetSendingOptions", k.ARN("configuration-set"), v.Tags, nil); e != nil {
		return nil, e
	}
	if in.SendingEnabled == nil {
		return nil, bad("SendingEnabled is required.")
	}
	v.SendingEnabled = bool(*in.SendingEnabled)
	return &api.PutConfigurationSetSendingOptionsOutput{}, tx.PutConfigurationSet(v)
}
