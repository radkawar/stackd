package mq

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"regexp"
	api "stackd/internal/awsapi/mq"
	"strconv"
	"strings"
)

var configurationName = regexp.MustCompile(`^[A-Za-z0-9_.~-]{1,150}$`)

func registerConfigurations(s *Service) {
	register(s, "CreateConfiguration", s.createConfiguration)
	register(s, "DescribeConfiguration", s.describeConfiguration)
	register(s, "UpdateConfiguration", s.updateConfiguration)
	register(s, "DeleteConfiguration", s.deleteConfiguration)
	register(s, "DescribeConfigurationRevision", s.describeConfigurationRevision)
	register(s, "ListConfigurations", s.listConfigurations)
	register(s, "ListConfigurationRevisions", s.listConfigurationRevisions)
}

// engineVersion selects the public API release, not the runtime's patch version.
// ActiveMQ's 5.18 API release is backed by the pinned native 5.18.7 runtime.
func engineVersion(engine, version string) (string, error) {
	supported := ""
	switch engine {
	case "ACTIVEMQ":
		supported = "5.18"
	case "RABBITMQ":
		supported = "3.13.7"
	default:
		return "", invalid("EngineType must be ACTIVEMQ or RABBITMQ")
	}
	if version != "" && version != supported {
		return "", invalidAttribute("engineVersion", "Configured native runtime supports API engine version "+supported)
	}
	return supported, nil
}
func number[T ~int32](p **T, v int) { x := T(v); *p = &x }
func revisionOutput(v ConfigurationRevisionRecord) *api.ConfigurationRevision {
	o := &api.ConfigurationRevision{}
	number(&o.Revision, v.Revision)
	text(&o.Description, v.Description)
	timestamp(&o.Created, v.Created)
	return o
}
func (s *Service) initialConfiguration(sc Scope, name, engine, version string) ConfigurationRecord {
	id := "c-" + uuid.NewString()
	now := s.clock.Now()
	return ConfigurationRecord{
		Scope: sc, ID: id, ARN: "arn:" + sc.Partition + ":mq:" + sc.Region + ":" + sc.AccountID + ":configuration:" + id,
		Name: name, Engine: engine, EngineVersion: version, AuthenticationStrategy: "SIMPLE",
		Created: now, Tags: map[string]string{},
		Revisions: []ConfigurationRevisionRecord{{Revision: 1, Created: now, Data: DefaultConfiguration(engine)}},
	}
}

func configurationOutput(v ConfigurationRecord) api.Configuration {
	o := api.Configuration{}
	text(&o.Id, v.ID)
	text(&o.Arn, v.ARN)
	text(&o.Name, v.Name)
	text(&o.Description, v.Description)
	text(&o.EngineType, v.Engine)
	text(&o.EngineVersion, v.EngineVersion)
	text(&o.AuthenticationStrategy, v.AuthenticationStrategy)
	timestamp(&o.Created, v.Created)
	tagMap(&o.Tags, v.Tags)
	o.LatestRevision = revisionOutput(v.Revisions[len(v.Revisions)-1])
	return o
}
func (s *Service) loadConfiguration(ctx context.Context, r Reader, id, action string, conditions ...map[string][]string) (ConfigurationRecord, error) {
	sc := scopeFor(ctx)
	if strings.HasPrefix(id, "arn:") {
		p := strings.Split(id, ":")
		if len(p) != 7 || p[1] != sc.Partition || p[2] != "mq" || p[3] != sc.Region || p[4] != sc.AccountID || p[5] != "configuration" {
			return ConfigurationRecord{}, configurationNotFound(id)
		}
		id = p[6]
	}
	v, e := r.Configuration(sc, id)
	if e != nil {
		if errors.Is(e, ErrNotFound) {
			return v, configurationNotFound(id)
		}
		return v, e
	}
	var attributes map[string][]string
	if len(conditions) != 0 {
		attributes = conditions[0]
	}
	e = s.authorize(ctx, BrokerRecord{ARN: v.ARN, Tags: v.Tags}, action, attributes)
	return v, e
}

func configurationNotFound(id string) error {
	return notFound("configuration-id", "Configuration ID ["+id+"] can't be found. Make sure it exists.")
}

func configurationRevisionNotFound(id, revision string) error {
	return notFound("configuration-revision", "Revision ["+revision+"] of configuration ["+id+"] can't be found. Make sure it exists.")
}
func (s *Service) createConfiguration(ctx context.Context, t Transaction, in *api.CreateConfigurationInput) (*api.CreateConfigurationOutput, error) {
	name, engine := value(in.Name), value(in.EngineType)
	if !configurationName.MatchString(name) {
		return nil, invalid("Invalid configuration name")
	}
	version, e := engineVersion(engine, value(in.EngineVersion))
	if e != nil {
		return nil, e
	}
	auth := value(in.AuthenticationStrategy)
	if auth == "" {
		auth = "SIMPLE"
	}
	if auth != "SIMPLE" {
		return nil, invalid("LDAP and configuration-managed authentication require an unavailable native authentication owner")
	}
	v := s.initialConfiguration(scopeFor(ctx), name, engine, version)
	conditions := map[string][]string{}
	for k, x := range in.Tags {
		v.Tags[string(k)] = string(x)
		conditions["aws:RequestTag/"+string(k)] = []string{string(x)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(k))
	}
	if e = validateTags(v.Tags); e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, BrokerRecord{ARN: v.ARN, Tags: v.Tags}, "CreateConfiguration", conditions); e != nil {
		return nil, e
	}
	if e = t.PutConfiguration(v); e != nil {
		return nil, e
	}
	o := &api.CreateConfigurationOutput{}
	text(&o.Id, v.ID)
	text(&o.Arn, v.ARN)
	text(&o.Name, v.Name)
	text(&o.AuthenticationStrategy, auth)
	timestamp(&o.Created, v.Created)
	o.LatestRevision = revisionOutput(v.Revisions[0])
	return o, nil
}
func (s *Service) describeConfiguration(ctx context.Context, t Transaction, in *api.DescribeConfigurationInput) (*api.DescribeConfigurationOutput, error) {
	v, e := s.loadConfiguration(ctx, t, value(in.ConfigurationId), "DescribeConfiguration")
	if e != nil {
		return nil, e
	}
	c := configurationOutput(v)
	return &api.DescribeConfigurationOutput{Arn: c.Arn, Id: c.Id, Name: c.Name, Description: c.Description, EngineType: c.EngineType, EngineVersion: c.EngineVersion, AuthenticationStrategy: c.AuthenticationStrategy, Created: c.Created, Tags: c.Tags, LatestRevision: c.LatestRevision}, nil
}
func (s *Service) updateConfiguration(ctx context.Context, t Transaction, in *api.UpdateConfigurationInput) (*api.UpdateConfigurationOutput, error) {
	v, e := s.loadConfiguration(ctx, t, value(in.ConfigurationId), "UpdateConfiguration")
	if e != nil {
		return nil, e
	}
	raw, e := base64.StdEncoding.DecodeString(value(in.Data))
	if e != nil {
		return nil, invalid("Data must be base64 encoded")
	}
	data, warnings, e := sanitizeConfiguration(v.Engine, string(raw))
	if e != nil {
		return nil, invalidAttribute("data", e.Error())
	}
	rev := ConfigurationRevisionRecord{Revision: len(v.Revisions) + 1, Created: s.clock.Now(), Description: value(in.Description), Data: data}
	v.Revisions = append(v.Revisions, rev)
	if in.Description != nil {
		v.Description = value(in.Description)
	}
	if e = t.PutConfiguration(v); e != nil {
		return nil, e
	}
	o := &api.UpdateConfigurationOutput{LatestRevision: revisionOutput(rev), Warnings: warnings}
	text(&o.Id, v.ID)
	text(&o.Arn, v.ARN)
	text(&o.Name, v.Name)
	timestamp(&o.Created, v.Created)
	return o, nil
}
func (s *Service) deleteConfiguration(ctx context.Context, t Transaction, in *api.DeleteConfigurationInput) (*api.DeleteConfigurationOutput, error) {
	v, e := s.loadConfiguration(ctx, t, value(in.ConfigurationId), "DeleteConfiguration")
	if e != nil {
		return nil, e
	}
	brokers, e := t.AllBrokers()
	if e != nil {
		return nil, e
	}
	for _, b := range brokers {
		if b.Scope == v.Scope && (b.Configuration.ID == v.ID || b.PendingConfiguration.ID == v.ID) {
			return nil, failure("ConflictException", "Configuration is associated with a broker", 409)
		}
	}
	if e = t.DeleteConfiguration(v.Scope, v.ID); e != nil {
		return nil, e
	}
	o := &api.DeleteConfigurationOutput{}
	text(&o.ConfigurationId, v.ID)
	return o, nil
}
func (s *Service) describeConfigurationRevision(ctx context.Context, t Transaction, in *api.DescribeConfigurationRevisionInput) (*api.DescribeConfigurationRevisionOutput, error) {
	revision := value(in.ConfigurationRevision)
	n, e := strconv.ParseInt(revision, 10, 32)
	if e != nil || strings.HasPrefix(revision, "+") {
		return nil, invalidAttribute("configuration-revision", "Invalid revision ID. Specify only integers from -2147483648 to 2147483647.")
	}
	v, e := s.loadConfiguration(ctx, t, value(in.ConfigurationId), "DescribeConfigurationRevision")
	if e != nil {
		if errors.Is(e, ErrNotFound) {
			return nil, configurationRevisionNotFound(value(in.ConfigurationId), strconv.FormatInt(n, 10))
		}
		return nil, e
	}
	if n < 1 || n > int64(len(v.Revisions)) {
		return nil, configurationRevisionNotFound(v.ID, strconv.FormatInt(n, 10))
	}
	rev := v.Revisions[n-1]
	o := &api.DescribeConfigurationRevisionOutput{}
	text(&o.ConfigurationId, v.ID)
	text(&o.Data, base64.StdEncoding.EncodeToString([]byte(rev.Data)))
	text(&o.Description, rev.Description)
	timestamp(&o.Created, rev.Created)
	return o, nil
}
func (s *Service) listConfigurations(ctx context.Context, t Transaction, in *api.ListConfigurationsInput) (*api.ListConfigurationsOutput, error) {
	if e := s.authorize(ctx, BrokerRecord{}, "ListConfigurations", nil); e != nil {
		return nil, e
	}
	limit, after, e := page(ctx, "configurations", in.MaxResults, value(in.NextToken))
	if e != nil {
		return nil, e
	}
	rows, e := t.AllConfigurations()
	if e != nil {
		return nil, e
	}
	o := &api.ListConfigurationsOutput{}
	number(&o.MaxResults, limit)
	last := ""
	for _, v := range rows {
		if v.Scope != scopeFor(ctx) || v.ARN <= after {
			continue
		}
		if len(o.Configurations) == limit {
			text(&o.NextToken, pageToken(ctx, "configurations", last))
			break
		}
		o.Configurations = append(o.Configurations, configurationOutput(v))
		last = v.ARN
	}
	return o, nil
}
func (s *Service) listConfigurationRevisions(ctx context.Context, t Transaction, in *api.ListConfigurationRevisionsInput) (*api.ListConfigurationRevisionsOutput, error) {
	v, e := s.loadConfiguration(ctx, t, value(in.ConfigurationId), "ListConfigurationRevisions")
	if e != nil {
		return nil, e
	}
	kind := "revisions:" + v.ID
	limit, after, e := page(ctx, kind, in.MaxResults, value(in.NextToken))
	if e != nil {
		return nil, e
	}
	start := 0
	if after != "" {
		start, e = strconv.Atoi(after)
		if e != nil || start < 0 || start > len(v.Revisions) {
			return nil, invalidAttribute("nextToken", "Invalid NextToken")
		}
	}
	o := &api.ListConfigurationRevisionsOutput{}
	text(&o.ConfigurationId, v.ID)
	number(&o.MaxResults, limit)
	end := min(start+limit, len(v.Revisions))
	for _, rev := range v.Revisions[start:end] {
		o.Revisions = append(o.Revisions, *revisionOutput(rev))
	}
	// Native MQ returns a cursor for every nonempty page, including the last.
	// Only the subsequent empty page terminates pagination.
	if end > start {
		text(&o.NextToken, pageToken(ctx, kind, strconv.Itoa(end)))
	}
	return o, nil
}
func (s *Service) resolveConfiguration(ctx context.Context, t Transaction, b BrokerRecord, in *api.ConfigurationId) (ConfigurationReference, error) {
	v, e := t.Configuration(b.Scope, value(in.Id))
	if e != nil {
		return ConfigurationReference{}, e
	}
	if v.Engine != b.Engine || v.EngineVersion != b.EngineVersion {
		return ConfigurationReference{}, invalid("Configuration engine and version must match broker")
	}
	n := len(v.Revisions)
	if in.Revision != nil {
		n = int(*in.Revision)
	}
	if n < 1 || n > len(v.Revisions) {
		return ConfigurationReference{}, ErrNotFound
	}
	return ConfigurationReference{ID: v.ID, Revision: n, Data: v.Revisions[n-1].Data}, nil
}
func configurationReference(v ConfigurationReference) *api.ConfigurationId {
	if v.ID == "" {
		return nil
	}
	o := &api.ConfigurationId{}
	text(&o.Id, v.ID)
	number(&o.Revision, v.Revision)
	return o
}
func page(ctx context.Context, kind string, max *api.MaxResults, token string) (int, string, error) {
	limit := 20
	if max != nil {
		limit = int(*max)
	}
	if limit < 5 || limit > 100 {
		return 0, "", invalidAttribute("maxResults", "Invalid max results value ["+strconv.Itoa(limit)+"]. Specify an integer between [5] and [100].")
	}
	if token == "" {
		return limit, "", nil
	}
	raw, e := base64.RawURLEncoding.DecodeString(token)
	prefix := pagePrefix(ctx, kind)
	if e != nil || !strings.HasPrefix(string(raw), prefix) {
		return 0, "", invalidAttribute("nextToken", "Invalid next token ["+token+"]. Make sure you copied the token correctly.")
	}
	return limit, strings.TrimPrefix(string(raw), prefix), nil
}
func pagePrefix(ctx context.Context, kind string) string {
	sc := scopeFor(ctx)
	return sc.Partition + "\x00" + sc.AccountID + "\x00" + sc.Region + "\x00" + kind + "\x00"
}
func pageToken(ctx context.Context, kind, last string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(pagePrefix(ctx, kind) + last))
}
