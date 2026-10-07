package mq

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"net"
	"net/url"
	"regexp"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/mq"
	"stackd/internal/awswire"
	"strings"
	"time"
)

var brokerName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,50}$`)

func registerBrokers(s *Service) {
	register(s, "CreateBroker", s.createBroker)
	register(s, "DescribeBroker", s.describeBroker)
	register(s, "ListBrokers", s.listBrokers)
	register(s, "DeleteBroker", s.deleteBroker)
	register(s, "RebootBroker", s.rebootBroker)
	register(s, "UpdateBroker", s.updateBroker)
	register(s, "DescribeSharedResources", s.describeSharedResources)
	register(s, "Promote", s.promote)
	registerTags(s)
}
func (s *Service) authorize(ctx context.Context, v BrokerRecord, action string, conditions map[string][]string) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, x := range v.Tags {
		conditions["aws:ResourceTag/"+k] = []string{x}
	}
	resource := v.ARN
	if resource == "" {
		resource = "*"
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "mq:" + action, ResourceARN: resource, EvaluationTime: &now, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}}); rejected != nil {
		return rejected
	}
	return nil
}
func (s *Service) load(ctx context.Context, r Reader, id, action string, conditions ...map[string][]string) (BrokerRecord, error) {
	sc := scopeFor(ctx)
	requestedARN := ""
	if strings.HasPrefix(id, "arn:") {
		requestedARN = id
	}
	if strings.HasPrefix(id, "arn:") {
		p := strings.Split(id, ":")
		if len(p) != 8 || p[1] != sc.Partition || p[2] != "mq" || p[3] != sc.Region || p[4] != sc.AccountID || p[5] != "broker" {
			return BrokerRecord{}, brokerNotFound(id)
		}
		id = p[7]
	}
	v, e := r.Broker(sc, id)
	if e != nil {
		if errors.Is(e, ErrNotFound) {
			return v, brokerNotFound(id)
		}
		return v, e
	}
	if (requestedARN != "" && requestedARN != v.ARN) || cloudFormationForeign(ctx, cloudFormationBroker, v.Ownership) {
		return BrokerRecord{}, brokerNotFound(id)
	}
	var attributes map[string][]string
	if len(conditions) != 0 {
		attributes = conditions[0]
	}
	if e = s.authorize(ctx, v, action, attributes); e != nil {
		return BrokerRecord{}, e
	}
	return v, nil
}

func brokerNotFound(id string) *awswire.Error {
	return notFound("broker-id", "Cannot find broker ID ["+id+"]. Verify that your broker exists or check broker permissions.")
}
func brokerNameConflict(name string) *awswire.Error {
	e := failure("ConflictException", "Broker named ["+name+"] already exists. Specify a unique broker name.", 409)
	e.Details = map[string]json.RawMessage{"errorAttribute": json.RawMessage(`"brokerName"`)}
	return e
}
func validateTags(tags map[string]string) error {
	if len(tags) > 50 {
		return invalid("A broker may have at most 50 tags")
	}
	for k, v := range tags {
		if k == "" || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return invalid("Invalid resource tag")
		}
	}
	return nil
}
func (s *Service) createBroker(ctx context.Context, t Transaction, in *api.CreateBrokerInput) (*api.CreateBrokerOutput, error) {
	name, engine := value(in.BrokerName), value(in.EngineType)
	if !brokerName.MatchString(name) {
		return nil, invalid("BrokerName must contain 1-50 letters, numbers, hyphens or underscores")
	}
	if engine != "RABBITMQ" && engine != "ACTIVEMQ" {
		return nil, invalid("EngineType must be ACTIVEMQ or RABBITMQ")
	}
	if value(in.DeploymentMode) != "SINGLE_INSTANCE" {
		return nil, invalid("Only a single real broker is implemented; standby and clustered deployments are unavailable")
	}
	if in.PubliclyAccessible == nil || !bool(*in.PubliclyAccessible) || len(in.SubnetIds) > 0 || len(in.SecurityGroups) > 0 {
		return nil, invalid("Private MQ networking requires the unimplemented MQ VPC/ENI owner; use an explicitly public broker")
	}
	if in.LdapServerMetadata != nil || value(in.AuthenticationStrategy) != "" && value(in.AuthenticationStrategy) != "SIMPLE" || in.DataReplicationMode != nil || in.DataReplicationPrimaryBrokerArn != nil || in.StorageSize != nil || in.StorageType != nil {
		return nil, invalid("LDAP, replication and managed storage require unavailable native owners")
	}
	if in.EncryptionOptions != nil {
		return nil, invalid("Managed broker storage encryption is not implemented")
	}
	if in.AutoMinorVersionUpgrade != nil && bool(*in.AutoMinorVersionUpgrade) {
		return nil, invalid("Automatic engine upgrades are not implemented")
	}
	if len(in.Users) == 0 || len(in.Users) > 200 || engine == "RABBITMQ" && len(in.Users) != 1 {
		return nil, invalid("ActiveMQ requires 1-200 users; RabbitMQ requires one initial administrator")
	}
	users := make([]UserRecord, 0, len(in.Users))
	for _, u := range in.Users {
		username, password := value(u.Username), value(u.Password)
		var groups []string
		console := false
		// Console access and groups are ActiveMQ-only fields. RabbitMQ's
		// administrator and subsequent users belong to the management API.
		if engine == "ACTIVEMQ" {
			groups, console = listStrings(u.Groups), truth(u.ConsoleAccess)
		}
		if err := validateUser(username, password, groups, truth(u.ReplicationUser)); err != nil {
			return nil, err
		}
		if findUser(users, username) >= 0 {
			return nil, invalid("Duplicate broker username")
		}
		users = append(users, UserRecord{Username: username, Password: password, Groups: groups, ConsoleAccess: console})
	}
	username, password := users[0].Username, users[0].Password
	version, e := engineVersion(engine, value(in.EngineVersion))
	if e != nil {
		return nil, e
	}
	instance := value(in.HostInstanceType)
	if s.runtime == nil {
		return nil, invalid("A real MQ runtime must be configured")
	}
	sc := scopeFor(ctx)
	id := "b-" + uuid.NewString()
	v := BrokerRecord{Scope: sc, ID: id, ARN: "arn:" + sc.Partition + ":mq:" + sc.Region + ":" + sc.AccountID + ":broker:" + name + ":" + id, Name: name, Engine: engine, EngineVersion: version, InstanceType: instance, State: "CREATION_IN_PROGRESS", CreatorRequestID: value(in.CreatorRequestId), Username: username, Password: password, Version: 1, Created: s.clock.Now(), Due: s.clock.Now(), Operation: "create", Tags: map[string]string{}}
	v.Users = users
	if claim, ok := cloudFormationClaim(ctx, cloudFormationBroker); ok {
		v.Ownership = claim
	}
	v.MaintenanceDay, v.MaintenanceTime, v.MaintenanceZone = "SUNDAY", "03:00", "UTC"
	if in.MaintenanceWindowStartTime != nil {
		if e := setMaintenance(&v, in.MaintenanceWindowStartTime); e != nil {
			return nil, e
		}
	}
	if in.Configuration != nil {
		ref, e := s.resolveConfiguration(ctx, t, v, in.Configuration)
		if e != nil {
			return nil, e
		}
		v.Configuration = ref
	}
	settings, e := s.logSettings(v, in.Logs, false)
	if e != nil {
		return nil, e
	}
	v.Logs = settings
	conditions := map[string][]string{}
	for k, x := range in.Tags {
		v.Tags[string(k)] = string(x)
		conditions["aws:RequestTag/"+string(k)] = []string{string(x)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(k))
	}
	if e := validateTags(v.Tags); e != nil {
		return nil, e
	}
	if e := s.authorize(ctx, v, "CreateBroker", conditions); e != nil {
		return nil, e
	}
	rows, e := t.AllBrokers()
	if e != nil {
		return nil, e
	}
	for _, existing := range rows {
		if existing.Scope != sc {
			continue
		}
		// Native replay ignores passwords, console access, tags and maintenance
		// changes; hashing the complete request would reject valid retries.
		// TODO: Comeback calibrate cross-name token reuse and remaining creation
		// fields; retain original instance/engine identity before their rollout.
		if v.CreatorRequestID != "" && existing.CreatorRequestID == v.CreatorRequestID {
			// A creator token is caller-supplied and may be public; only the
			// same private incarnation claim (or none on both) may replay it.
			if existing.Name != v.Name || existing.Engine != v.Engine || existing.Ownership != v.Ownership {
				return nil, failure("ConflictException", "CreatorRequestId has already been used", 409)
			}
			if existing.InstanceType != v.InstanceType {
				return nil, brokerNameConflict(name)
			}
			return brokerCreated(existing), nil
		}
		if existing.Name == name {
			return nil, brokerNameConflict(name)
		}
	}
	if instance != "mq.t3.micro" {
		return nil, invalid("The native single-broker runtime currently supports mq.t3.micro")
	}
	if v.Engine == "RABBITMQ" {
		if s.serviceLinkedRoles == nil {
			return nil, failure("InternalServerErrorException", "MQ service-linked role owner is unavailable", 500)
		}
		if err := s.serviceLinkedRoles.EnsureServiceLinkedRole(ctx, "mq.amazonaws.com"); err != nil {
			return nil, err
		}
	}
	if e = s.prepareLogGroups(ctx, &v, v.Logs); e != nil {
		return nil, e
	}
	if v.Engine == "ACTIVEMQ" && v.Configuration.ID == "" {
		// The automatic configuration is an independent resource, not a broker
		// snapshot. Commit it with admission, after replay and conflict checks.
		configuration := s.initialConfiguration(sc, name+"-configuration", engine, version)
		configuration.Revisions[0].Description = "Auto-generated default for " + configuration.Name + " on ActiveMQ " + version
		if e = t.PutConfiguration(configuration); e != nil {
			return nil, e
		}
		v.Configuration = ConfigurationReference{ID: configuration.ID, Revision: 1, Data: configuration.Revisions[0].Data}
	}
	if e = t.PutBroker(v); e != nil {
		return nil, e
	}
	return brokerCreated(v), nil
}
func brokerCreated(v BrokerRecord) *api.CreateBrokerOutput {
	o := &api.CreateBrokerOutput{}
	text(&o.BrokerArn, v.ARN)
	text(&o.BrokerId, v.ID)
	return o
}

// brokerEngineLabel preserves the native broker response spelling, which differs
// from the creation and catalog enum for ActiveMQ.
func brokerEngineLabel(engine string) string {
	if engine == "ACTIVEMQ" {
		return "ActiveMQ"
	}
	return engine
}

func (s *Service) describeBroker(ctx context.Context, t Transaction, in *api.DescribeBrokerInput) (*api.DescribeBrokerOutput, error) {
	v, e := s.load(ctx, t, value(in.BrokerId), "DescribeBroker")
	if e != nil {
		return nil, e
	}
	o := &api.DescribeBrokerOutput{}
	text(&o.BrokerArn, v.ARN)
	text(&o.BrokerId, v.ID)
	text(&o.BrokerName, v.Name)
	text(&o.BrokerState, v.State)
	text(&o.EngineType, brokerEngineLabel(v.Engine))
	text(&o.EngineVersion, v.EngineVersion)
	text(&o.HostInstanceType, v.InstanceType)
	text(&o.DeploymentMode, "SINGLE_INSTANCE")
	text(&o.AuthenticationStrategy, "SIMPLE")
	boolean(&o.PubliclyAccessible, true)
	boolean(&o.AutoMinorVersionUpgrade, false)
	timestamp(&o.Created, v.Created)
	tagMap(&o.Tags, v.Tags)
	for _, u := range brokerUsers(v) {
		o.Users = append(o.Users, userSummary(u))
	}
	o.MaintenanceWindowStartTime = maintenanceOutput(v)
	o.Logs = logsSummary(v)
	if v.Configuration.ID != "" || v.PendingConfiguration.ID != "" {
		o.Configurations = &api.Configurations{Current: configurationReference(v.Configuration), Pending: configurationReference(v.PendingConfiguration)}
		for _, ref := range v.ConfigurationHistory {
			o.Configurations.History = append(o.Configurations.History, *configurationReference(ref))
		}
	}
	if v.State == "RUNNING" {
		i := api.BrokerInstance{}
		stringList(&i.Endpoints, []string{v.Endpoint.Address})
		if endpoint, err := url.Parse(v.Endpoint.Address); err == nil {
			if ip := net.ParseIP(endpoint.Hostname()); ip != nil {
				text(&i.IpAddress, ip.String())
			}
		}
		if v.Endpoint.ConsoleURL != "" {
			text(&i.ConsoleURL, v.Endpoint.ConsoleURL)
		}
		o.BrokerInstances = append(o.BrokerInstances, i)
	}
	if v.Failure != "" {
		a := api.ActionRequired{}
		text(&a.ActionRequiredCode, "BROKER_ENGINE_UNAVAILABLE")
		text(&a.ActionRequiredInfo, v.Failure)
		o.ActionsRequired = append(o.ActionsRequired, a)
	}
	return o, nil
}
func timestamp(p **time.Time, v time.Time) { *p = &v }
func (s *Service) listBrokers(ctx context.Context, t Transaction, in *api.ListBrokersInput) (*api.ListBrokersOutput, error) {
	if e := s.authorize(ctx, BrokerRecord{}, "ListBrokers", nil); e != nil {
		return nil, e
	}
	limit, after, e := page(ctx, "brokers", in.MaxResults, value(in.NextToken))
	if e != nil {
		return nil, e
	}
	rows, e := t.AllBrokers()
	if e != nil {
		return nil, e
	}
	o := &api.ListBrokersOutput{}
	for _, v := range rows {
		if v.Scope != scopeFor(ctx) || v.ARN <= after {
			continue
		}
		if len(o.BrokerSummaries) == limit {
			last := value(o.BrokerSummaries[len(o.BrokerSummaries)-1].BrokerArn)
			text(&o.NextToken, pageToken(ctx, "brokers", last))
			break
		}
		b := api.BrokerSummary{}
		text(&b.BrokerArn, v.ARN)
		text(&b.BrokerId, v.ID)
		text(&b.BrokerName, v.Name)
		text(&b.BrokerState, v.State)
		text(&b.EngineType, brokerEngineLabel(v.Engine))
		text(&b.DeploymentMode, "SINGLE_INSTANCE")
		text(&b.HostInstanceType, v.InstanceType)
		timestamp(&b.Created, v.Created)
		o.BrokerSummaries = append(o.BrokerSummaries, b)
	}
	return o, nil
}
func (s *Service) deleteBroker(ctx context.Context, t Transaction, in *api.DeleteBrokerInput) (*api.DeleteBrokerOutput, error) {
	v, e := s.load(ctx, t, value(in.BrokerId), "DeleteBroker")
	if e != nil {
		return nil, e
	}
	v.State = "DELETION_IN_PROGRESS"
	v.Operation = "delete"
	v.Version++
	v.Due = s.clock.Now()
	v.Endpoint = Endpoint{}
	if e = t.PutBroker(v); e != nil {
		return nil, e
	}
	o := &api.DeleteBrokerOutput{}
	text(&o.BrokerId, v.ID)
	return o, nil
}
func (s *Service) rebootBroker(ctx context.Context, t Transaction, in *api.RebootBrokerInput) (*api.RebootBrokerOutput, error) {
	v, e := s.load(ctx, t, value(in.BrokerId), "RebootBroker")
	if e != nil {
		return nil, e
	}
	if v.State != "RUNNING" {
		return nil, failure("ConflictException", "Broker must be running before reboot", 409)
	}
	settings := v.Logs
	if v.PendingLogs != nil {
		settings = *v.PendingLogs
	}
	if e = s.prepareLogGroups(ctx, &v, settings); e != nil {
		return nil, e
	}
	v.State = "REBOOT_IN_PROGRESS"
	v.Operation = "reboot"
	v.Version++
	v.Due = s.clock.Now()
	v.Endpoint = Endpoint{}
	return &api.RebootBrokerOutput{}, t.PutBroker(v)
}
func (s *Service) ResolveBroker(ctx context.Context, arn string) (Connection, error) {
	var out Connection
	err := s.repository.View(ctx, func(r Reader) error {
		v, e := s.load(r.Context(), r, arn, "DescribeBroker")
		if e != nil {
			return e
		}
		if v.State != "RUNNING" || v.Endpoint.Address == "" {
			return errors.New("MQ broker is not running")
		}
		out = Connection{ID: v.ID, ARN: v.ARN, Engine: v.Engine, Endpoint: v.Endpoint}
		return nil
	})
	return out, err
}
