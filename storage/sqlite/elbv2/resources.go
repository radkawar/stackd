package elbv2

import (
	"encoding/json"
	api "stackd/internal/awsapi/elbv2"
	domain "stackd/storage/elbv2"
	"stackd/storage/sqlite/elbv2/internal/sqlcgen"
	"time"
)

func (r reader) loadBalancer(row sqlcgen.Elbv2LoadBalancer) (domain.LoadBalancerRecord, error) {
	v := domain.LoadBalancerRecord{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, DeletionProtection: row.DeletionProtection != 0, IdleTimeout: time.Duration(row.IdleTimeout), Deleting: row.Deleting != 0, NextReconcile: readTime(row.NextReconcile), Version: uint64(row.Version), AttachmentIDs: map[string]string{}, AttachmentGenerations: map[string]uint64{}}
	v.NextMetricAt = readTime(row.NextMetricAt)
	d := &v.Data
	text(&d.LoadBalancerArn, row.Arn)
	text(&d.LoadBalancerName, row.Name)
	if row.Created != timeValue(time.Time{}) {
		t := api.CreatedTime(readTime(row.Created))
		d.CreatedTime = &t
	}
	text(&d.Scheme, row.Scheme)
	text(&d.Type, row.Type)
	text(&d.IpAddressType, row.IpAddressType)
	text(&d.VpcId, row.VpcID)
	text(&d.DNSName, row.DnsName)
	text(&d.CanonicalHostedZoneId, row.HostedZoneID)
	if row.State != "" {
		d.State = &api.LoadBalancerState{}
		text(&d.State.Code, row.State)
		text(&d.State.Reason, row.StateReason)
	}
	if e := json.Unmarshal(row.Zones, &d.AvailabilityZones); e != nil {
		return v, e
	}
	if e := json.Unmarshal(row.SecurityGroups, &d.SecurityGroups); e != nil {
		return v, e
	}
	tags, e := r.tags(v.Scope, row.Arn)
	if e != nil {
		return v, e
	}
	v.Tags = tags
	attachments, e := r.q.ListAttachments(r.ctx, sqlcgen.ListAttachmentsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: row.Arn})
	if e != nil {
		return v, e
	}
	for _, a := range attachments {
		if a.InterfaceID != "" {
			v.AttachmentIDs[a.SubnetID] = a.InterfaceID
		}
		v.AttachmentGenerations[a.SubnetID] = uint64(a.Generation)
	}
	return v, nil
}
func (w writer) PutLoadBalancer(v domain.LoadBalancerRecord) error {
	d := v.Data
	zones, e := json.Marshal(d.AvailabilityZones)
	if e != nil {
		return e
	}
	groups, e := json.Marshal(d.SecurityGroups)
	if e != nil {
		return e
	}
	state, reason := "", ""
	if d.State != nil {
		state = value(d.State.Code)
		reason = value(d.State.Reason)
	}
	created := time.Time{}
	if d.CreatedTime != nil {
		created = time.Time(*d.CreatedTime)
	}
	if e = w.q.PutLoadBalancer(w.ctx, sqlcgen.PutLoadBalancerParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: value(d.LoadBalancerArn), Name: value(d.LoadBalancerName), Created: timeValue(created), Scheme: value(d.Scheme), Type: value(d.Type), IpAddressType: value(d.IpAddressType), VpcID: value(d.VpcId), DnsName: value(d.DNSName), HostedZoneID: value(d.CanonicalHostedZoneId), State: state, StateReason: reason, Zones: zones, SecurityGroups: groups, DeletionProtection: flag(v.DeletionProtection), IdleTimeout: int64(v.IdleTimeout), Deleting: flag(v.Deleting), NextReconcile: timeValue(v.NextReconcile), Version: int64(v.Version)}); e != nil {
		return e
	}
	if e = w.putTags(v.Scope, value(d.LoadBalancerArn), v.Tags); e != nil {
		return e
	}
	if e = w.q.DeleteAttachments(w.ctx, sqlcgen.DeleteAttachmentsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: value(d.LoadBalancerArn)}); e != nil {
		return e
	}
	for subnet, generation := range v.AttachmentGenerations {
		if e = w.q.PutAttachment(w.ctx, sqlcgen.PutAttachmentParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: value(d.LoadBalancerArn), SubnetID: subnet, InterfaceID: v.AttachmentIDs[subnet], Generation: int64(generation)}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) targetGroup(row sqlcgen.Elbv2TargetGroup) (domain.TargetGroupRecord, error) {
	v := domain.TargetGroupRecord{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, DeregistrationDelay: time.Duration(row.DeregistrationDelay)}
	d := &v.Data
	text(&d.TargetGroupArn, row.Arn)
	text(&d.TargetGroupName, row.Name)
	text(&d.Protocol, row.Protocol)
	number(&d.Port, row.Port)
	text(&d.ProtocolVersion, row.ProtocolVersion)
	text(&d.TargetType, row.TargetType)
	text(&d.IpAddressType, row.IpAddressType)
	text(&d.VpcId, row.VpcID)
	boolean(&d.HealthCheckEnabled, row.HealthEnabled)
	text(&d.HealthCheckProtocol, row.HealthProtocol)
	text(&d.HealthCheckPort, row.HealthPort)
	text(&d.HealthCheckPath, row.HealthPath)
	number(&d.HealthCheckIntervalSeconds, row.HealthInterval)
	number(&d.HealthCheckTimeoutSeconds, row.HealthTimeout)
	number(&d.HealthyThresholdCount, row.HealthyThreshold)
	number(&d.UnhealthyThresholdCount, row.UnhealthyThreshold)
	if row.Matcher != "" {
		d.Matcher = &api.Matcher{}
		text(&d.Matcher.HttpCode, row.Matcher)
	}
	if e := json.Unmarshal(row.LoadBalancerArns, &d.LoadBalancerArns); e != nil {
		return v, e
	}
	var e error
	v.Tags, e = r.tags(v.Scope, row.Arn)
	return v, e
}
func (w writer) PutTargetGroup(v domain.TargetGroupRecord) error {
	d := v.Data
	lbs, e := json.Marshal(d.LoadBalancerArns)
	if e != nil {
		return e
	}
	matcher := ""
	if d.Matcher != nil {
		matcher = value(d.Matcher.HttpCode)
	}
	if e = w.q.PutTargetGroup(w.ctx, sqlcgen.PutTargetGroupParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: value(d.TargetGroupArn), Name: value(d.TargetGroupName), Protocol: value(d.Protocol), Port: intValue(d.Port), ProtocolVersion: value(d.ProtocolVersion), TargetType: value(d.TargetType), IpAddressType: value(d.IpAddressType), VpcID: value(d.VpcId), HealthEnabled: boolValue(d.HealthCheckEnabled), HealthProtocol: value(d.HealthCheckProtocol), HealthPort: value(d.HealthCheckPort), HealthPath: value(d.HealthCheckPath), HealthInterval: intValue(d.HealthCheckIntervalSeconds), HealthTimeout: intValue(d.HealthCheckTimeoutSeconds), HealthyThreshold: intValue(d.HealthyThresholdCount), UnhealthyThreshold: intValue(d.UnhealthyThresholdCount), Matcher: matcher, LoadBalancerArns: lbs, DeregistrationDelay: int64(v.DeregistrationDelay)}); e != nil {
		return e
	}
	return w.putTags(v.Scope, value(d.TargetGroupArn), v.Tags)
}
func (r reader) listener(row sqlcgen.Elbv2Listener) (domain.ListenerRecord, error) {
	v := domain.ListenerRecord{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, CertificateID: row.CertificateID}
	d := &v.Data
	text(&d.ListenerArn, row.Arn)
	text(&d.LoadBalancerArn, row.LoadBalancerArn)
	text(&d.Protocol, row.Protocol)
	number(&d.Port, row.Port)
	text(&d.SslPolicy, row.SslPolicy)
	if e := json.Unmarshal(row.Certificates, &d.Certificates); e != nil {
		return v, e
	}
	if e := json.Unmarshal(row.Actions, &d.DefaultActions); e != nil {
		return v, e
	}
	var e error
	v.Tags, e = r.tags(v.Scope, row.Arn)
	return v, e
}
func (w writer) PutListener(v domain.ListenerRecord) error {
	d := v.Data
	certs, e := json.Marshal(d.Certificates)
	if e != nil {
		return e
	}
	actions, e := json.Marshal(d.DefaultActions)
	if e != nil {
		return e
	}
	if e = w.q.PutListener(w.ctx, sqlcgen.PutListenerParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: value(d.ListenerArn), LoadBalancerArn: value(d.LoadBalancerArn), Protocol: value(d.Protocol), Port: intValue(d.Port), SslPolicy: value(d.SslPolicy), CertificateID: v.CertificateID, Certificates: certs, Actions: actions}); e != nil {
		return e
	}
	return w.putTags(v.Scope, value(d.ListenerArn), v.Tags)
}
func (r reader) rule(row sqlcgen.Elbv2Rule) (domain.RuleRecord, error) {
	v := domain.RuleRecord{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ListenerARN: row.ListenerArn}
	d := &v.Data
	text(&d.RuleArn, row.Arn)
	text(&d.Priority, row.Priority)
	boolean(&d.IsDefault, row.IsDefault)
	if e := json.Unmarshal(row.Actions, &d.Actions); e != nil {
		return v, e
	}
	if e := json.Unmarshal(row.Conditions, &d.Conditions); e != nil {
		return v, e
	}
	var e error
	v.Tags, e = r.tags(v.Scope, row.Arn)
	return v, e
}
func (w writer) PutRule(v domain.RuleRecord) error {
	d := v.Data
	actions, e := json.Marshal(d.Actions)
	if e != nil {
		return e
	}
	conditions, e := json.Marshal(d.Conditions)
	if e != nil {
		return e
	}
	if e = w.q.PutRule(w.ctx, sqlcgen.PutRuleParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: value(d.RuleArn), ListenerArn: v.ListenerARN, Priority: value(d.Priority), IsDefault: boolValue(d.IsDefault), Conditions: conditions, Actions: actions}); e != nil {
		return e
	}
	return w.putTags(v.Scope, value(d.RuleArn), v.Tags)
}
