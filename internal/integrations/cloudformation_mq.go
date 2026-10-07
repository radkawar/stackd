package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/mq"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/mq"
	"strings"
)

func cfnMQTags[M ~map[K]V, K ~string, V ~string](raw M) map[string]string {
	tags := map[string]string{}
	for k, v := range raw {
		tags[string(k)] = string(v)
	}
	return tags
}
func cfnMQUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	desired := cfnResourceTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "mq", "DeleteTags", map[string]any{"ResourceArn": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "mq", "CreateTags", map[string]any{"ResourceArn": arn, "tags": desired})
}
func cfnMQBrokerGet(ctx context.Context, c StepFunctionsCommands, id string) (*api.DescribeBrokerOutput, error) {
	return cfnComputeCall[api.DescribeBrokerOutput](ctx, c, "mq", "DescribeBroker", map[string]any{"BrokerId": id})
}
func cfnMQBrokerIDs(ctx context.Context, c StepFunctionsCommands) ([]string, error) {
	ids := []string{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListBrokersOutput](ctx, c, "mq", "ListBrokers", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.BrokerSummaries {
			ids = append(ids, cfnComputeValue(v.BrokerId))
		}
		if cfnComputeValue(out.NextToken) == "" {
			return ids, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-amazonmq-broker.html
type cfnMQBroker struct{ commands StepFunctionsCommands }

func (h cfnMQBroker) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "BrokerName", "EngineType", "EngineVersion", "DeploymentMode", "HostInstanceType", "PubliclyAccessible", "AuthenticationStrategy", "LdapServerMetadata", "StorageType", "StorageSize", "EncryptionOptions", "Configuration", "DataReplicationMode", "DataReplicationPrimaryBrokerArn", "MaintenanceWindowStartTime", "AutoMinorVersionUpgrade", "Users", "Logs", "SecurityGroups", "SubnetIds", "Tags", "ResourceShareArns"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "BrokerName", "EngineType", "DeploymentMode", "HostInstanceType", "PubliclyAccessible", "Users"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnMQBroker) Replacement(a, b cloudformation.Properties) (bool, error) {
	keys := []string{"BrokerName", "EngineType", "EngineVersion", "DeploymentMode", "HostInstanceType", "PubliclyAccessible", "AuthenticationStrategy", "LdapServerMetadata", "StorageType", "StorageSize", "EncryptionOptions", "DataReplicationMode", "DataReplicationPrimaryBrokerArn", "SecurityGroups", "SubnetIds", "ResourceShareArns"}
	if cfnComputeString(b, "EngineType") == "RABBITMQ" {
		keys = append(keys, "Users")
	}
	// The native owner cannot clear a configuration or recover an automatically
	// chosen maintenance window in place; recreate rather than retain old state.
	if a["Configuration"] != nil && b["Configuration"] == nil || a["MaintenanceWindowStartTime"] != nil && b["MaintenanceWindowStartTime"] == nil {
		return true, h.Validate(b)
	}
	return cfnComputeChanged(a, b, keys...), h.Validate(b)
}

// cfnMQBrokerCreateContext binds the private incarnation claim persisted on
// the native broker row. Create and RecoverCreation always use it, including
// Cloud Control creates, so public tags or creator tokens never grant adoption.
func cfnMQBrokerCreateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return mq.WithCloudFormationBrokerOwner(ctx, cfnMessagingMarker(r))
}

// cfnMQBrokerContext fences stack-owned commands inside the native owner's
// transaction. Cloud Control reads and mutations use only current native IAM.
func cfnMQBrokerContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return cfnMQBrokerCreateContext(ctx, r)
}
func cfnMQNotAdmitted(kind string) error {
	return &awswire.Error{Code: "ResourceNotFoundException", Message: "This " + kind + " incarnation has no admitted native resource.", StatusCode: 404}
}

// find returns only a broker visible to ctx; fenced foreign brokers are absent.
func (h cfnMQBroker) find(ctx context.Context, name string) (*api.DescribeBrokerOutput, error) {
	ids, err := cfnMQBrokerIDs(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		v, err := cfnMQBrokerGet(ctx, h.commands, id)
		if cfnEngineMissing(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if cfnComputeValue(v.BrokerName) == name {
			return v, nil
		}
	}
	return nil, nil
}
func (h cfnMQBroker) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnMQBrokerCreateContext(ctx, r)
	name := cfnComputeString(r.Properties, "BrokerName")
	v, err := h.find(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if v != nil {
		r.PhysicalID = cfnComputeValue(v.BrokerId)
		result, err := h.Result(ctx, r)
		return cfnEngineAdmitted(r.PhysicalID, result, err)
	}
	input := cfnEngineLower(cfnComputeCopy(r.Properties, "BrokerName", "EngineType", "EngineVersion", "DeploymentMode", "HostInstanceType", "PubliclyAccessible", "AuthenticationStrategy", "LdapServerMetadata", "StorageType", "StorageSize", "EncryptionOptions", "Configuration", "DataReplicationMode", "DataReplicationPrimaryBrokerArn", "MaintenanceWindowStartTime", "AutoMinorVersionUpgrade", "Users", "Logs", "SecurityGroups", "SubnetIds", "ResourceShareArns")).(map[string]any)
	input["creatorRequestId"] = r.Token
	input["tags"] = cfnResourceTags(r)
	out, err := cfnComputeCall[api.CreateBrokerOutput](ctx, h.commands, "mq", "CreateBroker", input)
	if err != nil {
		// A modeled error may follow a committed admission whose reply was lost.
		if v, findErr := h.find(ctx, name); findErr == nil && v != nil {
			return cloudformation.ResourceResult{PhysicalID: cfnComputeValue(v.BrokerId), Ref: cfnComputeValue(v.BrokerId)}, err
		}
		return cloudformation.ResourceResult{}, cfnEngineCreateConflict(r, err)
	}
	r.PhysicalID = cfnComputeValue(out.BrokerId)
	result, err := h.Result(ctx, r)
	return cfnEngineAdmitted(r.PhysicalID, result, err)
}
func (h cfnMQBroker) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnMQBrokerCreateContext(ctx, r)
	v, err := h.find(ctx, cfnComputeString(r.Properties, "BrokerName"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if v == nil {
		return cloudformation.ResourceResult{}, cfnMQNotAdmitted("MQ broker")
	}
	r.PhysicalID = cfnComputeValue(v.BrokerId)
	result, err := h.Result(ctx, r)
	return cfnEngineAdmitted(r.PhysicalID, result, err)
}
func (h cfnMQBroker) users(ctx context.Context, r cloudformation.ResourceRequest, v *api.DescribeBrokerOutput) error {
	desired, ok := r.Properties["Users"].([]any)
	if !ok {
		return fmt.Errorf("users must be a list")
	}
	current := map[string]bool{}
	for _, u := range v.Users {
		current[cfnComputeValue(u.Username)] = true
	}
	wanted := map[string]bool{}
	previous, _ := r.Previous["Users"].([]any)
	old := map[string]map[string]any{}
	for _, raw := range previous {
		u, _ := cfnComputeObject(raw)
		old[cfnComputeString(u, "Username")] = u
	}
	for _, raw := range desired {
		u, ok := cfnComputeObject(raw)
		if !ok {
			return fmt.Errorf("users entries must be objects")
		}
		name := cfnComputeString(u, "Username")
		wanted[name] = true
		input := cfnEngineLower(u).(map[string]any)
		input["BrokerId"] = r.PhysicalID
		input["Username"] = name
		delete(input, "username")
		op := "CreateUser"
		if current[name] {
			op = "UpdateUser"
			if !cfnComputeChanged(old[name], u, "Password", "Groups", "ConsoleAccess", "ReplicationUser") {
				continue
			}
			if u["Groups"] == nil {
				input["groups"] = []string{}
			}
			if u["ConsoleAccess"] == nil {
				input["consoleAccess"] = false
			}
		}
		if err := cfnComputeRun(ctx, h.commands, "mq", op, input); err != nil {
			return err
		}
	}
	for name := range current {
		if !wanted[name] {
			if err := cfnComputeRun(ctx, h.commands, "mq", "DeleteUser", map[string]any{"BrokerId": r.PhysicalID, "Username": name}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (h cfnMQBroker) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	ctx = cfnMQBrokerContext(ctx, r)
	replacement, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replacement {
		return result, fmt.Errorf("native MQ engine, security or topology update requires replacement")
	}
	v, err := cfnMQBrokerGet(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags := cfnMQTags(v.Tags)
	control := cfnComputeChanged(r.Previous, r.Properties, "Configuration", "Logs", "MaintenanceWindowStartTime", "AutoMinorVersionUpgrade")
	users := cfnComputeChanged(r.Previous, r.Properties, "Users")
	if control {
		input := cfnEngineLower(cfnComputeCopy(r.Properties, "Configuration", "Logs", "MaintenanceWindowStartTime", "AutoMinorVersionUpgrade")).(map[string]any)
		input["BrokerId"] = r.PhysicalID
		if r.Properties["Configuration"] == nil && r.Previous["Configuration"] != nil {
			return result, fmt.Errorf("native broker configuration cannot be detached; select another configuration or replace")
		}
		if r.Properties["Logs"] == nil && r.Previous["Logs"] != nil {
			input["logs"] = map[string]any{"general": false, "audit": false}
		}
		if err = cfnComputeRun(ctx, h.commands, "mq", "UpdateBroker", input); err != nil {
			return result, err
		}
	}
	if users {
		if err = h.users(ctx, r, v); err != nil {
			return result, err
		}
	}
	if control || users {
		if err = cfnComputeRun(ctx, h.commands, "mq", "RebootBroker", map[string]any{"BrokerId": r.PhysicalID}); err != nil {
			return result, err
		}
	}
	if err = cfnMQUpdateTags(ctx, h.commands, r, cfnComputeValue(v.BrokerArn), tags); err != nil {
		return result, err
	}
	updated, err := h.Result(ctx, r)
	return cfnEngineAdmitted(r.PhysicalID, updated, err)
}

// Delete is fenced inside the native transaction: a broker carrying another
// private claim is absent to this incarnation and is never deleted.
func (h cfnMQBroker) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnMQBrokerContext(ctx, r)
	id := r.PhysicalID
	if id == "" {
		v, err := h.find(ctx, cfnComputeString(r.Properties, "BrokerName"))
		if err != nil {
			return err
		}
		if v == nil {
			return nil
		}
		id = cfnComputeValue(v.BrokerId)
	}
	v, err := cfnMQBrokerGet(ctx, h.commands, id)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(v.BrokerState) == "DELETION_IN_PROGRESS" {
		return nil
	}
	if err = cfnComputeRun(ctx, h.commands, "mq", "DeleteBroker", map[string]any{"BrokerId": id}); cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnMQBroker) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ctx = cfnMQBrokerContext(ctx, r)
	v, err := cfnMQBrokerGet(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	engine := strings.ToUpper(cfnComputeValue(v.EngineType))
	p := cloudformation.Properties{"Id": cfnComputeValue(v.BrokerId), "Arn": cfnComputeValue(v.BrokerArn), "BrokerName": cfnComputeValue(v.BrokerName), "EngineType": engine, "EngineVersion": cfnComputeValue(v.EngineVersion), "EngineVersionCurrent": cfnComputeValue(v.EngineVersion), "HostInstanceType": cfnComputeValue(v.HostInstanceType), "DeploymentMode": cfnComputeValue(v.DeploymentMode), "PubliclyAccessible": v.PubliclyAccessible, "AuthenticationStrategy": cfnComputeValue(v.AuthenticationStrategy), "AutoMinorVersionUpgrade": v.AutoMinorVersionUpgrade, "Tags": cfnResourcePublicTags(cfnMQTags(v.Tags))}
	if v.Configurations != nil && v.Configurations.Current != nil {
		p["Configuration"] = map[string]any{"Id": cfnComputeValue(v.Configurations.Current.Id), "Revision": v.Configurations.Current.Revision}
		p["ConfigurationId"] = cfnComputeValue(v.Configurations.Current.Id)
		p["ConfigurationRevision"] = v.Configurations.Current.Revision
	}
	if v.MaintenanceWindowStartTime != nil {
		p["MaintenanceWindowStartTime"], err = cfnEngineNativeObject(v.MaintenanceWindowStartTime)
		if err != nil {
			return nil, err
		}
	}
	if v.Logs != nil {
		p["Logs"] = map[string]any{"General": v.Logs.General, "Audit": v.Logs.Audit}
	}
	users := []any{}
	for _, u := range v.Users {
		user := map[string]any{"Username": cfnComputeValue(u.Username)}
		if engine == "ACTIVEMQ" {
			out, e := cfnComputeCall[api.DescribeUserOutput](ctx, h.commands, "mq", "DescribeUser", map[string]any{"BrokerId": r.PhysicalID, "Username": cfnComputeValue(u.Username)})
			if e != nil {
				return nil, e
			}
			user["Groups"] = cfnEngineList(out.Groups)
			user["ConsoleAccess"] = out.ConsoleAccess
		}
		users = append(users, user)
	}
	p["Users"] = users
	endpoints := map[string][]string{"AmqpEndpoints": {}, "MqttEndpoints": {}, "StompEndpoints": {}, "WssEndpoints": {}, "OpenWireEndpoints": {}, "ConsoleURLs": {}, "IpAddresses": {}}
	for _, instance := range v.BrokerInstances {
		if instance.IpAddress != nil {
			endpoints["IpAddresses"] = append(endpoints["IpAddresses"], cfnComputeValue(instance.IpAddress))
		}
	}
	for _, instance := range v.BrokerInstances {
		if instance.ConsoleURL != nil {
			endpoints["ConsoleURLs"] = append(endpoints["ConsoleURLs"], cfnComputeValue(instance.ConsoleURL))
		}
		for _, raw := range instance.Endpoints {
			endpoint := string(raw)
			key := ""
			switch {
			case strings.HasPrefix(endpoint, "amqp"):
				key = "AmqpEndpoints"
			case strings.HasPrefix(endpoint, "mqtt"):
				key = "MqttEndpoints"
			case strings.HasPrefix(endpoint, "stomp"):
				key = "StompEndpoints"
			case strings.HasPrefix(endpoint, "ws"):
				key = "WssEndpoints"
			case strings.HasPrefix(endpoint, "ssl"), strings.HasPrefix(endpoint, "tcp"):
				key = "OpenWireEndpoints"
			}
			if key != "" {
				endpoints[key] = append(endpoints[key], endpoint)
			}
		}
	}
	for k, x := range endpoints {
		p[k] = x
	}
	return p, nil
}
func (h cfnMQBroker) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	ids, err := cfnMQBrokerIDs(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	result := []cloudformation.ResourceDescription{}
	for _, id := range ids {
		r.PhysicalID = id
		p, err := h.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		result = append(result, cloudformation.ResourceDescription{Identifier: id, Properties: p})
	}
	return result, nil
}
func (h cfnMQBroker) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := cfnMQBrokerGet(cfnMQBrokerContext(ctx, r), h.commands, r.PhysicalID)
	if err != nil {
		return false, err
	}
	stable, err := cfnEngineStable(cfnComputeValue(v.BrokerState), "RUNNING")
	if !stable || err != nil {
		return stable, err
	}
	if v.Configurations != nil && v.Configurations.Pending != nil {
		return false, nil
	}
	for _, u := range v.Users {
		if cfnComputeValue(u.PendingChange) != "" {
			return false, nil
		}
	}
	return true, nil
}
func (h cfnMQBroker) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := cfnMQBrokerGet(cfnMQBrokerContext(ctx, r), h.commands, r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnMQBroker) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-amazonmq-configuration.html
type cfnMQConfiguration struct{ commands StepFunctionsCommands }

func (h cfnMQConfiguration) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "AuthenticationStrategy", "EngineType", "EngineVersion", "Data", "Description", "Name", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "EngineType", "Name"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnMQConfiguration) Replacement(a, b cloudformation.Properties) (bool, error) {
	if a["Data"] != nil && b["Data"] == nil {
		return true, h.Validate(b)
	}
	return cfnComputeChanged(a, b, "AuthenticationStrategy", "EngineType", "EngineVersion", "Name"), h.Validate(b)
}
func (h cfnMQConfiguration) get(ctx context.Context, id string) (*api.DescribeConfigurationOutput, error) {
	return cfnComputeCall[api.DescribeConfigurationOutput](ctx, h.commands, "mq", "DescribeConfiguration", map[string]any{"ConfigurationId": id})
}

// cfnMQConfigurationCreateContext binds the private claim persisted on the
// native configuration row; Create and RecoverCreation always use it.
func cfnMQConfigurationCreateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return mq.WithCloudFormationConfigurationOwner(ctx, cfnMessagingMarker(r))
}

// cfnMQConfigurationContext fences stack-owned commands; Cloud Control uses
// only current native IAM.
func cfnMQConfigurationContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return cfnMQConfigurationCreateContext(ctx, r)
}

// find returns the configuration visible to ctx. Native configuration names
// are not unique, so every same-name candidate is checked by the owner fence.
func (h cfnMQConfiguration) find(ctx context.Context, name string) (string, error) {
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListConfigurationsOutput](ctx, h.commands, "mq", "ListConfigurations", input)
		if err != nil {
			return "", err
		}
		for _, v := range out.Configurations {
			if cfnComputeValue(v.Name) != name {
				continue
			}
			_, err := h.get(ctx, cfnComputeValue(v.Id))
			if cfnEngineMissing(err) {
				continue
			}
			if err != nil {
				return "", err
			}
			return cfnComputeValue(v.Id), nil
		}
		if cfnComputeValue(out.NextToken) == "" {
			return "", nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMQConfiguration) apply(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.Properties["Data"] == nil && r.Properties["Description"] == nil && r.Previous["Description"] == nil {
		return nil
	}
	data := cfnComputeString(r.Properties, "Data")
	if r.Properties["Data"] == nil {
		v, err := h.get(ctx, r.PhysicalID)
		if err != nil {
			return err
		}
		if v.LatestRevision == nil || v.LatestRevision.Revision == nil {
			return fmt.Errorf("MQ configuration has no revision")
		}
		out, err := cfnComputeCall[api.DescribeConfigurationRevisionOutput](ctx, h.commands, "mq", "DescribeConfigurationRevision", map[string]any{"ConfigurationId": r.PhysicalID, "ConfigurationRevision": fmt.Sprint(*v.LatestRevision.Revision)})
		if err != nil {
			return err
		}
		data = cfnComputeValue(out.Data)
	}
	return cfnComputeRun(ctx, h.commands, "mq", "UpdateConfiguration", map[string]any{"ConfigurationId": r.PhysicalID, "data": data, "description": cfnComputeDefault(r.Properties, "Description", "")})
}
func (h cfnMQConfiguration) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnMQConfigurationCreateContext(ctx, r)
	name := cfnComputeString(r.Properties, "Name")
	id, err := h.find(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	apply := id == ""
	if id != "" {
		v, e := h.get(ctx, id)
		if e != nil {
			return cloudformation.ResourceResult{PhysicalID: id, Ref: id}, e
		}
		apply = v.LatestRevision != nil && v.LatestRevision.Revision != nil && *v.LatestRevision.Revision == 1
	} else {
		input := cfnEngineLower(cfnComputeCopy(r.Properties, "Name", "EngineType", "EngineVersion", "AuthenticationStrategy")).(map[string]any)
		input["tags"] = cfnResourceTags(r)
		out, e := cfnComputeCall[api.CreateConfigurationOutput](ctx, h.commands, "mq", "CreateConfiguration", input)
		if e != nil {
			// A modeled error may follow a committed admission whose reply was lost.
			if id, findErr := h.find(ctx, name); findErr == nil && id != "" {
				return cloudformation.ResourceResult{PhysicalID: id, Ref: id}, e
			}
			return cloudformation.ResourceResult{}, e
		}
		id = cfnComputeValue(out.Id)
	}
	r.PhysicalID = id
	result := cloudformation.ResourceResult{PhysicalID: id, Ref: id}
	if apply {
		if err = h.apply(ctx, r); err != nil {
			return result, err
		}
	}
	created, err := h.Result(ctx, r)
	return cfnEngineAdmitted(id, created, err)
}
func (h cfnMQConfiguration) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnMQConfigurationCreateContext(ctx, r)
	id, err := h.find(ctx, cfnComputeString(r.Properties, "Name"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if id == "" {
		return cloudformation.ResourceResult{}, cfnMQNotAdmitted("MQ configuration")
	}
	r.PhysicalID = id
	result, err := h.Result(ctx, r)
	return cfnEngineAdmitted(id, result, err)
}
func (h cfnMQConfiguration) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	ctx = cfnMQConfigurationContext(ctx, r)
	replacement, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replacement {
		return result, fmt.Errorf("MQ configuration engine or identity requires replacement")
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags := cfnMQTags(v.Tags)
	if cfnComputeChanged(r.Previous, r.Properties, "Data", "Description") {
		if err = h.apply(ctx, r); err != nil {
			return result, err
		}
	}
	if err = cfnMQUpdateTags(ctx, h.commands, r, cfnComputeValue(v.Arn), tags); err != nil {
		return result, err
	}
	updated, err := h.Result(ctx, r)
	return cfnEngineAdmitted(r.PhysicalID, updated, err)
}

// Delete is fenced inside the native transaction: a configuration carrying
// another private claim is absent to this incarnation and is never deleted.
func (h cfnMQConfiguration) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnMQConfigurationContext(ctx, r)
	id := r.PhysicalID
	if id == "" {
		var err error
		id, err = h.find(ctx, cfnComputeString(r.Properties, "Name"))
		if err != nil {
			return err
		}
		if id == "" {
			return nil
		}
	}
	if err := cfnComputeRun(ctx, h.commands, "mq", "DeleteConfiguration", map[string]any{"ConfigurationId": id}); !cfnEngineMissing(err) {
		return err
	}
	return nil
}
func (h cfnMQConfiguration) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ctx = cfnMQConfigurationContext(ctx, r)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"Id": cfnComputeValue(v.Id), "Arn": cfnComputeValue(v.Arn), "Name": cfnComputeValue(v.Name), "EngineType": cfnComputeValue(v.EngineType), "EngineVersion": cfnComputeValue(v.EngineVersion), "AuthenticationStrategy": cfnComputeValue(v.AuthenticationStrategy), "Description": cfnComputeValue(v.Description), "Tags": cfnResourcePublicTags(cfnMQTags(v.Tags))}
	if v.LatestRevision != nil && v.LatestRevision.Revision != nil {
		p["Revision"] = int32(*v.LatestRevision.Revision)
		out, err := cfnComputeCall[api.DescribeConfigurationRevisionOutput](ctx, h.commands, "mq", "DescribeConfigurationRevision", map[string]any{"ConfigurationId": r.PhysicalID, "ConfigurationRevision": fmt.Sprint(*v.LatestRevision.Revision)})
		if err != nil {
			return nil, err
		}
		p["Data"] = cfnComputeValue(out.Data)
	}
	return p, nil
}
func (h cfnMQConfiguration) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListConfigurationsOutput](ctx, h.commands, "mq", "ListConfigurations", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Configurations {
			r.PhysicalID = cfnComputeValue(v.Id)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMQConfiguration) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}
