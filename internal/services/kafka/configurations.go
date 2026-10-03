package kafka

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	api "stackd/internal/awsapi/kafka"
	"strings"
)

func registerConfigurations(s *Service) {
	register(s, "CreateConfiguration", s.createConfiguration)
	register(s, "DescribeConfiguration", s.describeConfiguration)
	register(s, "DescribeConfigurationRevision", s.describeRevision)
	register(s, "ListConfigurations", s.listConfigurations)
	register(s, "ListConfigurationRevisions", s.listRevisions)
	register(s, "UpdateConfiguration", s.updateConfiguration)
	register(s, "DeleteConfiguration", s.deleteConfiguration)
	register(s, "ListKafkaVersions", func(ctx context.Context, t Transaction, in *api.ListKafkaVersionsInput) (*api.ListKafkaVersionsOutput, error) {
		if e := s.authorize(ctx, ClusterRecord{}, "ListKafkaVersions", nil); e != nil {
			return nil, e
		}
		rows, next, e := page([]string{"3.7.1"}, in.MaxResults, value(in.NextToken), pageBinding(ctx, "ListKafkaVersions", ""), func(v string) string { return v })
		if e != nil {
			return nil, e
		}
		out := &api.ListKafkaVersionsOutput{}
		for _, v := range rows {
			k := api.KafkaVersion{}
			text(&k.Version, v)
			text(&k.Status, "ACTIVE")
			out.KafkaVersions = append(out.KafkaVersions, k)
		}
		if next != "" {
			text(&out.NextToken, next)
		}
		return out, nil
	})
}
func revisionInfo(r RevisionRecord) *api.ConfigurationRevision {
	out := &api.ConfigurationRevision{CreationTime: new(r.Created)}
	number(&out.Revision, r.Revision)
	if r.Description != "" {
		text(&out.Description, r.Description)
	}
	return out
}
func (s *Service) createConfiguration(ctx context.Context, t Transaction, in *api.CreateConfigurationInput) (*api.CreateConfigurationOutput, error) {
	if e := s.authorize(ctx, ClusterRecord{}, "CreateConfiguration", nil); e != nil {
		return nil, e
	}
	name := value(in.Name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "/: \t\n") {
		return nil, invalid("Invalid configuration name")
	}
	rows, e := t.Configurations(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if v.Name == name {
			return nil, parameterError(conflict("A configuration with this name already exists"), "name")
		}
	}
	if _, e = parseProperties(string(in.ServerProperties), false); e != nil {
		return nil, parameterError(invalid(e.Error()), "serverproperties")
	}
	sc := scopeFor(ctx)
	v := ConfigurationRecord{Scope: sc, ARN: "arn:" + sc.Partition + ":kafka:" + sc.Region + ":" + sc.AccountID + ":configuration/" + name + "/" + uuid.NewString(), Name: name, Description: value(in.Description), Created: s.clock.Now(), LatestRevision: 1, KafkaVersions: plainList(in.KafkaVersions)}
	r := RevisionRecord{ARN: v.ARN, Revision: 1, Description: v.Description, ServerProperties: string(in.ServerProperties), Created: v.Created}
	if e = t.PutConfiguration(v); e != nil {
		return nil, e
	}
	if e = t.PutRevision(r); e != nil {
		return nil, e
	}
	out := &api.CreateConfigurationOutput{CreationTime: new(v.Created), LatestRevision: revisionInfo(r), State: new(api.ConfigurationStateACTIVE)}
	text(&out.Arn, v.ARN)
	text(&out.Name, v.Name)
	return out, nil
}
func (s *Service) updateConfiguration(ctx context.Context, t Transaction, in *api.UpdateConfigurationInput) (*api.UpdateConfigurationOutput, error) {
	v, e := s.configuration(ctx, t, value(in.Arn), "UpdateConfiguration")
	if e != nil {
		return nil, e
	}
	if _, e = parseProperties(string(in.ServerProperties), false); e != nil {
		return nil, parameterError(invalid(e.Error()), "serverproperties")
	}
	v.LatestRevision++
	r := RevisionRecord{ARN: v.ARN, Revision: v.LatestRevision, Description: value(in.Description), ServerProperties: string(in.ServerProperties), Created: s.clock.Now()}
	if e = t.PutRevision(r); e != nil {
		return nil, e
	}
	if e = t.PutConfiguration(v); e != nil {
		return nil, e
	}
	out := &api.UpdateConfigurationOutput{LatestRevision: revisionInfo(r)}
	text(&out.Arn, v.ARN)
	return out, nil
}
func (s *Service) describeConfiguration(ctx context.Context, t Transaction, in *api.DescribeConfigurationInput) (*api.DescribeConfigurationOutput, error) {
	v, e := s.configuration(ctx, t, value(in.Arn), "DescribeConfiguration")
	if e != nil {
		return nil, e
	}
	r, e := t.Revision(v.ARN, v.LatestRevision)
	if e != nil {
		return nil, e
	}
	out := &api.DescribeConfigurationOutput{CreationTime: new(v.Created), LatestRevision: revisionInfo(r), State: new(api.ConfigurationStateACTIVE)}
	text(&out.Arn, v.ARN)
	text(&out.Name, v.Name)
	if v.Description != "" {
		text(&out.Description, v.Description)
	}
	stringList(&out.KafkaVersions, v.KafkaVersions)
	return out, nil
}
func (s *Service) describeRevision(ctx context.Context, t Transaction, in *api.DescribeConfigurationRevisionInput) (*api.DescribeConfigurationRevisionOutput, error) {
	v, e := s.configuration(ctx, t, value(in.Arn), "DescribeConfigurationRevision")
	if e != nil {
		return nil, e
	}
	if in.Revision == nil {
		return nil, invalid("Revision is required")
	}
	r, e := t.Revision(v.ARN, int64(*in.Revision))
	if e != nil {
		return nil, invalid("Configuration revision does not exist")
	}
	out := &api.DescribeConfigurationRevisionOutput{CreationTime: new(r.Created), ServerProperties: []byte(r.ServerProperties)}
	text(&out.Arn, r.ARN)
	number(&out.Revision, r.Revision)
	if r.Description != "" {
		text(&out.Description, r.Description)
	}
	return out, nil
}
func (s *Service) listConfigurations(ctx context.Context, t Transaction, in *api.ListConfigurationsInput) (*api.ListConfigurationsOutput, error) {
	if e := s.authorize(ctx, ClusterRecord{}, "ListConfigurations", nil); e != nil {
		return nil, e
	}
	rows, e := t.Configurations(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	rows, next, e := page(rows, in.MaxResults, value(in.NextToken), pageBinding(ctx, "ListConfigurations", ""), func(v ConfigurationRecord) string { return v.ARN })
	if e != nil {
		return nil, e
	}
	out := &api.ListConfigurationsOutput{}
	for _, v := range rows {
		r, e := t.Revision(v.ARN, v.LatestRevision)
		if e != nil {
			return nil, e
		}
		c := api.Configuration{CreationTime: new(v.Created), LatestRevision: revisionInfo(r), State: new(api.ConfigurationStateACTIVE)}
		text(&c.Arn, v.ARN)
		text(&c.Name, v.Name)
		text(&c.Description, v.Description)
		stringList(&c.KafkaVersions, v.KafkaVersions)
		out.Configurations = append(out.Configurations, c)
	}
	if next != "" {
		text(&out.NextToken, next)
	}
	return out, nil
}
func (s *Service) listRevisions(ctx context.Context, t Transaction, in *api.ListConfigurationRevisionsInput) (*api.ListConfigurationRevisionsOutput, error) {
	v, e := s.configuration(ctx, t, value(in.Arn), "ListConfigurationRevisions")
	if e != nil {
		return nil, e
	}
	rows, e := t.Revisions(v.ARN)
	if e != nil {
		return nil, e
	}
	rows, next, e := page(rows, in.MaxResults, value(in.NextToken), pageBinding(ctx, "ListConfigurationRevisions", v.ARN), func(v RevisionRecord) string { return fmt.Sprintf("%020d", v.Revision) })
	if e != nil {
		return nil, e
	}
	out := &api.ListConfigurationRevisionsOutput{}
	for _, r := range rows {
		out.Revisions = append(out.Revisions, *revisionInfo(r))
	}
	if next != "" {
		text(&out.NextToken, next)
	}
	return out, nil
}
func (s *Service) deleteConfiguration(ctx context.Context, t Transaction, in *api.DeleteConfigurationInput) (*api.DeleteConfigurationOutput, error) {
	v, e := s.configuration(ctx, t, value(in.Arn), "DeleteConfiguration")
	if e != nil {
		return nil, e
	}
	all, e := t.Clusters(v.Scope)
	if e != nil {
		return nil, e
	}
	for _, c := range all {
		if c.ConfigurationARN == v.ARN || c.PendingConfigurationARN == v.ARN {
			return nil, invalid("Configuration is in use by a cluster")
		}
	}
	if e = t.DeleteConfiguration(v.ARN); e != nil {
		return nil, e
	}
	out := &api.DeleteConfigurationOutput{State: new(api.ConfigurationStateDELETING)}
	text(&out.Arn, v.ARN)
	return out, nil
}
