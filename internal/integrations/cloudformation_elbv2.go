package integrations

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/services/cloudformation"
)

// Elastic Load Balancing v2 CloudFormation adapters. Native listeners and data
// plane forwarding remain effects of the ELBv2 owner's runtime.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-loadbalancer.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-targetgroup.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-listener.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-listenerrule.html

var cfnELBMissingCodes = []string{"LoadBalancerNotFound", "TargetGroupNotFound", "ListenerNotFound", "RuleNotFound"}

func cfnELBMissing(err error) bool { return cfnCSMissing(err, cfnELBMissingCodes...) }

func cfnELBTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.DescribeTagsOutput](ctx, c, "elbv2", "DescribeTags", map[string]any{"ResourceArns": []string{arn}})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, description := range out.TagDescriptions {
		for _, tag := range description.Tags {
			tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
		}
	}
	return tags, nil
}
func cfnELBTagList(tags map[string]string) []map[string]string { return cfnComputeTagList(tags) }
func cfnELBReconcileTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	added, removed := cfnCSTagChanges(current, cfnResourceTags(r))
	if len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "elbv2", "RemoveTags", map[string]any{"ResourceArns": []string{arn}, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(added) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "elbv2", "AddTags", map[string]any{"ResourceArns": []string{arn}, "Tags": cfnELBTagList(added)})
}
func cfnELBPublicTags(ctx context.Context, c StepFunctionsCommands, arn string) ([]any, error) {
	tags, err := cfnELBTags(ctx, c, arn)
	if err != nil {
		return nil, err
	}
	return cfnCSTagMapList(tags), nil
}

// cfnELBName keeps generated names within ELB's 32 character, alphanumeric and
// hyphen rule without a leading or trailing hyphen.
func cfnELBName(r cloudformation.ResourceRequest, property string) string {
	name := cfnComputeName(r, property, 32)
	if r.PhysicalID != "" || cfnComputeString(r.Properties, property) != "" {
		return name
	}
	hash := cfnComputeHash(r.StackID + "/" + r.LogicalID + "/" + r.Token)
	prefix := strings.Trim(strings.TrimSuffix(name, "-"+hash), "-")
	if prefix == "" {
		prefix = "stack"
	}
	return prefix + "-" + hash
}

// ---- AWS::ElasticLoadBalancingV2::LoadBalancer ----

type cfnELBLoadBalancer struct{ commands StepFunctionsCommands }

const cfnELBLoadBalancerType = "AWS::ElasticLoadBalancingV2::LoadBalancer"

func (h cfnELBLoadBalancer) Validate(p cloudformation.Properties) error {
	return cfnCSValidate(cfnELBLoadBalancerType, p, "MinimumLoadBalancerCapacity", "EnableCapacityReservationProvisionStabilize", "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic")
}
func (h cfnELBLoadBalancer) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnELBLoadBalancerType, a, b)
}
func (h cfnELBLoadBalancer) get(ctx context.Context, input map[string]any) (*api.LoadBalancer, error) {
	out, err := cfnComputeCall[api.DescribeLoadBalancersOutput](ctx, h.commands, "elbv2", "DescribeLoadBalancers", input)
	if err != nil {
		return nil, err
	}
	if len(out.LoadBalancers) != 1 {
		return nil, cfnCSNotFound("load balancer")
	}
	return &out.LoadBalancers[0], nil
}
func cfnELBLoadBalancerResult(lb *api.LoadBalancer) cloudformation.ResourceResult {
	arn := cfnComputeValue(lb.LoadBalancerArn)
	_, full, _ := strings.Cut(arn, ":loadbalancer/")
	groups := make([]any, 0, len(lb.SecurityGroups))
	for _, group := range lb.SecurityGroups {
		groups = append(groups, string(group))
	}
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{
		"LoadBalancerArn": arn, "DNSName": cfnComputeValue(lb.DNSName), "CanonicalHostedZoneID": cfnComputeValue(lb.CanonicalHostedZoneId),
		"LoadBalancerFullName": full, "LoadBalancerName": cfnComputeValue(lb.LoadBalancerName), "SecurityGroups": groups,
	}}
}
func (h cfnELBLoadBalancer) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnELBName(cloudformation.ResourceRequest{StackID: r.StackID, StackName: r.StackName, LogicalID: r.LogicalID, Token: r.Token, Properties: r.Properties}, "Name")
	lb, err := h.get(ctx, map[string]any{"Names": []string{name}})
	if err == nil {
		if err := cfnNativeComputeOwned(ctx, r, cfnComputeValue(lb.LoadBalancerArn)); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
	} else if !cfnELBMissing(err) {
		return cloudformation.ResourceResult{}, err
	} else {
		input := cfnCSRename(r.Properties, nil, "Tags", "LoadBalancerAttributes", "Ipv4IpamPoolId")
		input["Name"] = name
		input["Tags"] = cfnELBTagList(cfnResourceTags(r))
		if pool, ok := r.Properties["Ipv4IpamPoolId"]; ok {
			input["IpamPools"] = map[string]any{"Ipv4IpamPoolId": pool}
		}
		out, err := cfnCSCall[api.CreateLoadBalancerOutput](ctx, h.commands, "elbv2", "CreateLoadBalancer", input)
		if err != nil {
			if recovered, readErr := h.get(ctx, map[string]any{"Names": []string{name}}); readErr == nil && cfnNativeComputeOwned(ctx, r, cfnComputeValue(recovered.LoadBalancerArn)) == nil {
				return cfnELBLoadBalancerResult(recovered), err
			}
			return cloudformation.ResourceResult{}, err
		}
		if len(out.LoadBalancers) != 1 {
			return cloudformation.ResourceResult{}, fmt.Errorf("CreateLoadBalancer returned %d load balancers", len(out.LoadBalancers))
		}
		lb = &out.LoadBalancers[0]
	}
	result := cfnELBLoadBalancerResult(lb)
	if err := cfnNativeComputeOwned(ctx, r, result.PhysicalID); err != nil {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
	}
	return result, h.attributes(ctx, r, result.PhysicalID)
}
func (h cfnELBLoadBalancer) attributes(ctx context.Context, r cloudformation.ResourceRequest, arn string) error {
	attributes, ok := r.Properties["LoadBalancerAttributes"]
	if !ok || reflect.DeepEqual(attributes, r.Previous["LoadBalancerAttributes"]) {
		return nil
	}
	return cfnCSRun(ctx, h.commands, "elbv2", "ModifyLoadBalancerAttributes", map[string]any{"LoadBalancerArn": arn, "Attributes": attributes})
}
func (h cfnELBLoadBalancer) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	lb, err := h.get(ctx, map[string]any{"LoadBalancerArns": []string{r.PhysicalID}})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tags, err := cfnELBTags(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, r.PhysicalID); err != nil {
		return cfnELBLoadBalancerResult(lb), err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Subnets", "SubnetMappings") {
		input := cfnComputeCopy(r.Properties, "Subnets", "SubnetMappings")
		input["LoadBalancerArn"] = r.PhysicalID
		if err := cfnCSRun(ctx, h.commands, "elbv2", "SetSubnets", input); err != nil {
			return cfnELBLoadBalancerResult(lb), err
		}
	}
	if cfnComputeChanged(r.Previous, r.Properties, "SecurityGroups") {
		if err := cfnCSRun(ctx, h.commands, "elbv2", "SetSecurityGroups", map[string]any{"LoadBalancerArn": r.PhysicalID, "SecurityGroups": cfnComputeDefault(r.Properties, "SecurityGroups", []any{})}); err != nil {
			return cfnELBLoadBalancerResult(lb), err
		}
	}
	if cfnComputeChanged(r.Previous, r.Properties, "IpAddressType", "EnablePrefixForIpv6SourceNat", "Ipv4IpamPoolId") {
		input := map[string]any{"LoadBalancerArn": r.PhysicalID, "IpAddressType": cfnComputeDefault(r.Properties, "IpAddressType", "ipv4")}
		if r.Properties["EnablePrefixForIpv6SourceNat"] != nil {
			input["EnablePrefixForIpv6SourceNat"] = r.Properties["EnablePrefixForIpv6SourceNat"]
		}
		if r.Properties["Ipv4IpamPoolId"] != nil {
			return cfnELBLoadBalancerResult(lb), cfnCSUnsupported("IPAM pool updates are not implemented by the ELBv2 owner")
		}
		if err := cfnCSRun(ctx, h.commands, "elbv2", "SetIpAddressType", input); err != nil {
			return cfnELBLoadBalancerResult(lb), err
		}
	}
	if err := h.attributes(ctx, r, r.PhysicalID); err != nil {
		return cfnELBLoadBalancerResult(lb), err
	}
	if err := cfnELBReconcileTags(ctx, h.commands, r, r.PhysicalID, tags); err != nil {
		return cfnELBLoadBalancerResult(lb), err
	}
	if lb, err = h.get(ctx, map[string]any{"LoadBalancerArns": []string{r.PhysicalID}}); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnELBLoadBalancerResult(lb), nil
}

// Stabilize waits for the provisioning load balancer to become active.
func (h cfnELBLoadBalancer) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	lb, err := h.get(ctx, map[string]any{"LoadBalancerArns": []string{r.PhysicalID}})
	if err != nil {
		return false, err
	}
	if lb.State == nil {
		return false, nil
	}
	switch state := cfnComputeValue(lb.State.Code); state {
	case "active":
		return true, nil
	case "failed":
		reason := ""
		if lb.State.Reason != nil {
			reason = string(*lb.State.Reason)
		}
		return false, fmt.Errorf("load balancer provisioning failed: %s", reason)
	default:
		return false, nil
	}
}

// Result refreshes security groups and DNS published by the owner.
func (h cfnELBLoadBalancer) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	lb, err := h.get(ctx, map[string]any{"LoadBalancerArns": []string{r.PhysicalID}})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnELBLoadBalancerResult(lb), nil
}
func (h cfnELBLoadBalancer) locate(ctx context.Context, r cloudformation.ResourceRequest) (*api.LoadBalancer, error) {
	if r.PhysicalID != "" {
		return h.get(ctx, map[string]any{"LoadBalancerArns": []string{r.PhysicalID}})
	}
	return h.get(ctx, map[string]any{"Names": []string{cfnELBName(r, "Name")}})
}
func (h cfnELBLoadBalancer) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	lb, err := h.locate(ctx, r)
	if cfnELBMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	arn := cfnComputeValue(lb.LoadBalancerArn)
	_, err = cfnELBTags(ctx, h.commands, arn)
	if cfnELBMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, arn); err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "elbv2", "DeleteLoadBalancer", map[string]any{"LoadBalancerArn": arn})
	if cfnELBMissing(err) {
		return nil
	}
	return err
}
func (h cfnELBLoadBalancer) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.locate(ctx, r)
	if cfnELBMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnELBLoadBalancer) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	lb, err := h.get(ctx, map[string]any{"LoadBalancerArns": []string{r.PhysicalID}})
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(lb, map[string]string{"LoadBalancerName": "Name", "CanonicalHostedZoneId": "CanonicalHostedZoneID"})
	if err != nil {
		return nil, err
	}
	for key, value := range cfnELBLoadBalancerResult(lb).Attributes {
		p[key] = value
	}
	subnets := []any{}
	for _, zone := range lb.AvailabilityZones {
		subnets = append(subnets, cfnComputeValue(zone.SubnetId))
	}
	p["Subnets"] = subnets
	attributes, err := cfnComputeCall[api.DescribeLoadBalancerAttributesOutput](ctx, h.commands, "elbv2", "DescribeLoadBalancerAttributes", map[string]any{"LoadBalancerArn": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	projected, err := cfnCSProject(map[string]any{"loadBalancerAttributes": attributes.Attributes}, nil)
	if err != nil {
		return nil, err
	}
	p["LoadBalancerAttributes"] = projected["LoadBalancerAttributes"]
	if p["Tags"], err = cfnELBPublicTags(ctx, h.commands, r.PhysicalID); err != nil {
		return nil, err
	}
	return cfnCSKeep(p, "LoadBalancerArn", "Name", "LoadBalancerName", "LoadBalancerFullName", "DNSName", "CanonicalHostedZoneID", "Scheme", "Type", "IpAddressType", "SecurityGroups", "Subnets", "LoadBalancerAttributes", "Tags"), nil
}
func (h cfnELBLoadBalancer) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeLoadBalancersOutput](ctx, h.commands, "elbv2", "DescribeLoadBalancers", input)
		if err != nil {
			return nil, err
		}
		for _, lb := range out.LoadBalancers {
			arn := cfnComputeValue(lb.LoadBalancerArn)
			rows = append(rows, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"LoadBalancerArn": arn}})
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return rows, nil
		}
		input["Marker"] = cfnComputeValue(out.NextMarker)
	}
}

// ---- AWS::ElasticLoadBalancingV2::TargetGroup ----

type cfnELBTargetGroup struct{ commands StepFunctionsCommands }

const cfnELBTargetGroupType = "AWS::ElasticLoadBalancingV2::TargetGroup"

func (h cfnELBTargetGroup) Validate(p cloudformation.Properties) error {
	return cfnCSValidate(cfnELBTargetGroupType, p)
}
func (h cfnELBTargetGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnELBTargetGroupType, a, b)
}
func (h cfnELBTargetGroup) get(ctx context.Context, input map[string]any) (*api.TargetGroup, error) {
	out, err := cfnComputeCall[api.DescribeTargetGroupsOutput](ctx, h.commands, "elbv2", "DescribeTargetGroups", input)
	if err != nil {
		return nil, err
	}
	if len(out.TargetGroups) != 1 {
		return nil, cfnCSNotFound("target group")
	}
	return &out.TargetGroups[0], nil
}
func cfnELBTargetGroupResult(tg *api.TargetGroup) cloudformation.ResourceResult {
	arn := cfnComputeValue(tg.TargetGroupArn)
	// TargetGroupFullName is the ARN resource suffix "targetgroup/<name>/<id>".
	_, suffix, _ := strings.Cut(arn, ":targetgroup/")
	full := "targetgroup/" + suffix
	balancers := make([]any, 0, len(tg.LoadBalancerArns))
	for _, lb := range tg.LoadBalancerArns {
		balancers = append(balancers, string(lb))
	}
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"TargetGroupArn": arn, "TargetGroupFullName": full, "TargetGroupName": cfnComputeValue(tg.TargetGroupName), "LoadBalancerArns": balancers}}
}
func (h cfnELBTargetGroup) locate(ctx context.Context, r cloudformation.ResourceRequest) (*api.TargetGroup, error) {
	if r.PhysicalID != "" {
		return h.get(ctx, map[string]any{"TargetGroupArns": []string{r.PhysicalID}})
	}
	return h.get(ctx, map[string]any{"Names": []string{cfnELBName(r, "Name")}})
}
func (h cfnELBTargetGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnELBName(cloudformation.ResourceRequest{StackID: r.StackID, StackName: r.StackName, LogicalID: r.LogicalID, Token: r.Token, Properties: r.Properties}, "Name")
	tg, err := h.get(ctx, map[string]any{"Names": []string{name}})
	if err == nil {
		if err := cfnNativeComputeOwned(ctx, r, cfnComputeValue(tg.TargetGroupArn)); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
	} else if !cfnELBMissing(err) {
		return cloudformation.ResourceResult{}, err
	} else {
		input := cfnCSRename(r.Properties, nil, "Tags", "TargetGroupAttributes", "Targets")
		input["Name"] = name
		input["Tags"] = cfnELBTagList(cfnResourceTags(r))
		out, err := cfnCSCall[api.CreateTargetGroupOutput](ctx, h.commands, "elbv2", "CreateTargetGroup", input)
		if err != nil {
			if recovered, readErr := h.get(ctx, map[string]any{"Names": []string{name}}); readErr == nil && cfnNativeComputeOwned(ctx, r, cfnComputeValue(recovered.TargetGroupArn)) == nil {
				return cfnELBTargetGroupResult(recovered), err
			}
			return cloudformation.ResourceResult{}, err
		}
		if len(out.TargetGroups) != 1 {
			return cloudformation.ResourceResult{}, fmt.Errorf("CreateTargetGroup returned %d target groups", len(out.TargetGroups))
		}
		tg = &out.TargetGroups[0]
	}
	result := cfnELBTargetGroupResult(tg)
	if err := cfnNativeComputeOwned(ctx, r, result.PhysicalID); err != nil {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
	}
	if err := h.attributes(ctx, r, result.PhysicalID); err != nil {
		return result, err
	}
	return result, h.targets(ctx, r, result.PhysicalID)
}
func (h cfnELBTargetGroup) attributes(ctx context.Context, r cloudformation.ResourceRequest, arn string) error {
	attributes, ok := r.Properties["TargetGroupAttributes"]
	if !ok || reflect.DeepEqual(attributes, r.Previous["TargetGroupAttributes"]) {
		return nil
	}
	return cfnCSRun(ctx, h.commands, "elbv2", "ModifyTargetGroupAttributes", map[string]any{"TargetGroupArn": arn, "Attributes": attributes})
}

// targets registers desired Targets and deregisters removed ones.
func (h cfnELBTargetGroup) targets(ctx context.Context, r cloudformation.ResourceRequest, arn string) error {
	if reflect.DeepEqual(r.Properties["Targets"], r.Previous["Targets"]) && r.Previous != nil {
		return nil
	}
	desired, _ := r.Properties["Targets"].([]any)
	keys := map[string]bool{}
	for _, raw := range desired {
		target, _ := cfnComputeObject(raw)
		keys[fmt.Sprint(target["Id"], "/", target["Port"], "/", target["AvailabilityZone"])] = true
	}
	if len(desired) > 0 {
		if err := cfnCSRun(ctx, h.commands, "elbv2", "RegisterTargets", map[string]any{"TargetGroupArn": arn, "Targets": desired}); err != nil {
			return err
		}
	}
	previous, _ := r.Previous["Targets"].([]any)
	var removed []any
	for _, raw := range previous {
		target, _ := cfnComputeObject(raw)
		if !keys[fmt.Sprint(target["Id"], "/", target["Port"], "/", target["AvailabilityZone"])] {
			removed = append(removed, raw)
		}
	}
	if len(removed) == 0 {
		return nil
	}
	return cfnCSRun(ctx, h.commands, "elbv2", "DeregisterTargets", map[string]any{"TargetGroupArn": arn, "Targets": removed})
}
func (h cfnELBTargetGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tg, err := h.get(ctx, map[string]any{"TargetGroupArns": []string{r.PhysicalID}})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnELBTargetGroupResult(tg)
	tags, err := cfnELBTags(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return result, err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	health := []string{"HealthCheckEnabled", "HealthCheckIntervalSeconds", "HealthCheckPath", "HealthCheckPort", "HealthCheckProtocol", "HealthCheckTimeoutSeconds", "HealthyThresholdCount", "UnhealthyThresholdCount", "Matcher"}
	if cfnComputeChanged(r.Previous, r.Properties, health...) {
		input := cfnComputeCopy(r.Properties, health...)
		input["TargetGroupArn"] = r.PhysicalID
		if err := cfnCSRun(ctx, h.commands, "elbv2", "ModifyTargetGroup", input); err != nil {
			return result, err
		}
	}
	if err := h.attributes(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	if err := h.targets(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	return result, cfnELBReconcileTags(ctx, h.commands, r, r.PhysicalID, tags)
}

// Result refreshes LoadBalancerArns after listener/rule associations change.
func (h cfnELBTargetGroup) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	tg, err := h.get(ctx, map[string]any{"TargetGroupArns": []string{r.PhysicalID}})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnELBTargetGroupResult(tg), nil
}
func (h cfnELBTargetGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	tg, err := h.locate(ctx, r)
	if cfnELBMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	arn := cfnComputeValue(tg.TargetGroupArn)
	_, err = cfnELBTags(ctx, h.commands, arn)
	if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, arn); err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "elbv2", "DeleteTargetGroup", map[string]any{"TargetGroupArn": arn})
	if cfnELBMissing(err) {
		return nil
	}
	return err
}
func (h cfnELBTargetGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	tg, err := h.get(ctx, map[string]any{"TargetGroupArns": []string{r.PhysicalID}})
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(tg, map[string]string{"TargetGroupName": "Name"})
	if err != nil {
		return nil, err
	}
	for key, value := range cfnELBTargetGroupResult(tg).Attributes {
		p[key] = value
	}
	attributes, err := cfnComputeCall[api.DescribeTargetGroupAttributesOutput](ctx, h.commands, "elbv2", "DescribeTargetGroupAttributes", map[string]any{"TargetGroupArn": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	health, err := cfnComputeCall[api.DescribeTargetHealthOutput](ctx, h.commands, "elbv2", "DescribeTargetHealth", map[string]any{"TargetGroupArn": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	targets := make([]any, 0, len(health.TargetHealthDescriptions))
	for _, description := range health.TargetHealthDescriptions {
		if description.Target != nil {
			targets = append(targets, description.Target)
		}
	}
	projected, err := cfnCSProject(map[string]any{"targetGroupAttributes": attributes.Attributes, "targets": targets}, nil)
	if err != nil {
		return nil, err
	}
	p["TargetGroupAttributes"], p["Targets"] = projected["TargetGroupAttributes"], projected["Targets"]
	if p["Tags"], err = cfnELBPublicTags(ctx, h.commands, r.PhysicalID); err != nil {
		return nil, err
	}
	return cfnCSKeep(p, "TargetGroupArn", "Name", "TargetGroupName", "TargetGroupFullName", "LoadBalancerArns", "Protocol", "ProtocolVersion", "Port", "VpcId", "TargetType", "IpAddressType", "HealthCheckEnabled", "HealthCheckIntervalSeconds", "HealthCheckPath", "HealthCheckPort", "HealthCheckProtocol", "HealthCheckTimeoutSeconds", "HealthyThresholdCount", "UnhealthyThresholdCount", "Matcher", "TargetGroupAttributes", "Targets", "Tags"), nil
}
func (h cfnELBTargetGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeTargetGroupsOutput](ctx, h.commands, "elbv2", "DescribeTargetGroups", input)
		if err != nil {
			return nil, err
		}
		for _, tg := range out.TargetGroups {
			arn := cfnComputeValue(tg.TargetGroupArn)
			rows = append(rows, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"TargetGroupArn": arn}})
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return rows, nil
		}
		input["Marker"] = cfnComputeValue(out.NextMarker)
	}
}

// ---- AWS::ElasticLoadBalancingV2::Listener ----

type cfnELBListener struct{ commands StepFunctionsCommands }

const cfnELBListenerType = "AWS::ElasticLoadBalancingV2::Listener"

func (h cfnELBListener) Validate(p cloudformation.Properties) error {
	// The ELBv2 owner implements no listener attribute control.
	return cfnCSValidate(cfnELBListenerType, p, "ListenerAttributes")
}
func (h cfnELBListener) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnELBListenerType, a, b)
}
func (h cfnELBListener) get(ctx context.Context, arn string) (*api.Listener, error) {
	out, err := cfnComputeCall[api.DescribeListenersOutput](ctx, h.commands, "elbv2", "DescribeListeners", map[string]any{"ListenerArns": []string{arn}})
	if err != nil {
		return nil, err
	}
	if len(out.Listeners) != 1 {
		return nil, cfnCSNotFound("listener " + arn)
	}
	return &out.Listeners[0], nil
}
func cfnELBListenerResult(arn string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"ListenerArn": arn}}
}

// owned recovers this incarnation's listener on its load balancer.
func (h cfnELBListener) owned(ctx context.Context, r cloudformation.ResourceRequest) (*api.Listener, error) {
	input := map[string]any{"LoadBalancerArn": cfnComputeString(r.Properties, "LoadBalancerArn")}
	for {
		out, err := cfnComputeCall[api.DescribeListenersOutput](ctx, h.commands, "elbv2", "DescribeListeners", input)
		if cfnELBMissing(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		for i := range out.Listeners {
			if cfnNativeComputeOwned(ctx, r, cfnComputeValue(out.Listeners[i].ListenerArn)) == nil {
				return &out.Listeners[i], nil
			}
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return nil, nil
		}
		input["Marker"] = cfnComputeValue(out.NextMarker)
	}
}
func (h cfnELBListener) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if listener, err := h.owned(ctx, r); err != nil || listener != nil {
		if listener == nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnELBListenerResult(cfnComputeValue(listener.ListenerArn)), nil
	}
	input := cfnCSRename(r.Properties, nil, "Tags")
	input["Tags"] = cfnELBTagList(cfnResourceTags(r))
	out, err := cfnCSCall[api.CreateListenerOutput](ctx, h.commands, "elbv2", "CreateListener", input)
	if err != nil {
		if listener, readErr := h.owned(ctx, r); readErr == nil && listener != nil {
			return cfnELBListenerResult(cfnComputeValue(listener.ListenerArn)), err
		}
		return cloudformation.ResourceResult{}, err
	}
	if len(out.Listeners) != 1 {
		return cloudformation.ResourceResult{}, fmt.Errorf("CreateListener returned %d listeners", len(out.Listeners))
	}
	arn := cfnComputeValue(out.Listeners[0].ListenerArn)
	// An identical existing listener is returned idempotently by the owner;
	// verify it is this incarnation's before reporting success.
	if err := cfnNativeComputeOwned(ctx, r, arn); err != nil {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
	}
	return cfnELBListenerResult(arn), nil
}
func (h cfnELBListener) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnELBListenerResult(r.PhysicalID)
	if _, err := h.get(ctx, r.PhysicalID); err != nil {
		return result, err
	}
	tags, err := cfnELBTags(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return result, err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	mutable := []string{"Port", "Protocol", "SslPolicy", "Certificates", "DefaultActions", "AlpnPolicy", "MutualAuthentication"}
	if cfnComputeChanged(r.Previous, r.Properties, mutable...) {
		input := cfnComputeCopy(r.Properties, mutable...)
		input["ListenerArn"] = r.PhysicalID
		if err := cfnCSRun(ctx, h.commands, "elbv2", "ModifyListener", input); err != nil {
			return result, err
		}
	}
	return result, cfnELBReconcileTags(ctx, h.commands, r, r.PhysicalID, tags)
}
func (h cfnELBListener) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	arn := r.PhysicalID
	if arn == "" {
		ctx = cfnNativeComputeContext(ctx, r, true)
		listener, err := h.owned(ctx, r)
		if err != nil || listener == nil {
			return err
		}
		arn = cfnComputeValue(listener.ListenerArn)
		r.PhysicalID = arn
		ctx = cfnNativeComputeContext(ctx, r, false)
	}
	_, err := h.get(ctx, arn)
	if cfnELBMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, arn); err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "elbv2", "DeleteListener", map[string]any{"ListenerArn": arn})
	if cfnELBMissing(err) {
		return nil
	}
	return err
}
func (h cfnELBListener) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	listener, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(listener, nil)
	if err != nil {
		return nil, err
	}
	if p["Tags"], err = cfnELBPublicTags(ctx, h.commands, r.PhysicalID); err != nil {
		return nil, err
	}
	return cfnCSKeep(p, "ListenerArn", "LoadBalancerArn", "Port", "Protocol", "SslPolicy", "Certificates", "DefaultActions", "AlpnPolicy", "MutualAuthentication", "Tags"), nil
}
func (h cfnELBListener) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	balancers, err := cfnELBLoadBalancer(h).List(ctx, r)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, lb := range balancers {
		input := map[string]any{"LoadBalancerArn": lb.Identifier}
		for {
			out, err := cfnComputeCall[api.DescribeListenersOutput](ctx, h.commands, "elbv2", "DescribeListeners", input)
			if cfnELBMissing(err) {
				break
			}
			if err != nil {
				return nil, err
			}
			for _, listener := range out.Listeners {
				arn := cfnComputeValue(listener.ListenerArn)
				rows = append(rows, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"ListenerArn": arn, "LoadBalancerArn": lb.Identifier}})
			}
			if cfnComputeValue(out.NextMarker) == "" {
				break
			}
			input["Marker"] = cfnComputeValue(out.NextMarker)
		}
	}
	return rows, nil
}

// ---- AWS::ElasticLoadBalancingV2::ListenerRule ----

type cfnELBRule struct{ commands StepFunctionsCommands }

const cfnELBRuleType = "AWS::ElasticLoadBalancingV2::ListenerRule"

func (h cfnELBRule) Validate(p cloudformation.Properties) error {
	if err := cfnCSValidate(cfnELBRuleType, p); err != nil {
		return err
	}
	if p["ListenerArn"] == nil {
		return fmt.Errorf("ListenerArn is required")
	}
	return nil
}
func (h cfnELBRule) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnELBRuleType, a, b)
}
func (h cfnELBRule) get(ctx context.Context, arn string) (*api.Rule, error) {
	out, err := cfnComputeCall[api.DescribeRulesOutput](ctx, h.commands, "elbv2", "DescribeRules", map[string]any{"RuleArns": []string{arn}})
	if err != nil {
		return nil, err
	}
	if len(out.Rules) != 1 {
		return nil, cfnCSNotFound("listener rule " + arn)
	}
	return &out.Rules[0], nil
}
func cfnELBRuleResult(rule *api.Rule) cloudformation.ResourceResult {
	arn := cfnComputeValue(rule.RuleArn)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"RuleArn": arn, "IsDefault": rule.IsDefault != nil && bool(*rule.IsDefault)}}
}
func (h cfnELBRule) owned(ctx context.Context, r cloudformation.ResourceRequest) (*api.Rule, error) {
	input := map[string]any{"ListenerArn": cfnComputeString(r.Properties, "ListenerArn")}
	for {
		out, err := cfnComputeCall[api.DescribeRulesOutput](ctx, h.commands, "elbv2", "DescribeRules", input)
		if cfnELBMissing(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		for i := range out.Rules {
			if out.Rules[i].IsDefault != nil && bool(*out.Rules[i].IsDefault) {
				continue
			}
			if cfnNativeComputeOwned(ctx, r, cfnComputeValue(out.Rules[i].RuleArn)) == nil {
				return &out.Rules[i], nil
			}
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return nil, nil
		}
		input["Marker"] = cfnComputeValue(out.NextMarker)
	}
}
func (h cfnELBRule) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if rule, err := h.owned(ctx, r); err != nil || rule != nil {
		if rule == nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnELBRuleResult(rule), nil
	}
	input := cfnCSRename(r.Properties, nil, "Tags")
	input["Tags"] = cfnELBTagList(cfnResourceTags(r))
	out, err := cfnCSCall[api.CreateRuleOutput](ctx, h.commands, "elbv2", "CreateRule", input)
	if err != nil {
		if rule, readErr := h.owned(ctx, r); readErr == nil && rule != nil {
			return cfnELBRuleResult(rule), err
		}
		return cloudformation.ResourceResult{}, err
	}
	if len(out.Rules) != 1 {
		return cloudformation.ResourceResult{}, fmt.Errorf("CreateRule returned %d rules", len(out.Rules))
	}
	return cfnELBRuleResult(&out.Rules[0]), nil
}
func (h cfnELBRule) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	rule, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnELBRuleResult(rule)
	tags, err := cfnELBTags(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return result, err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Actions", "Conditions", "Transforms") {
		input := cfnComputeCopy(r.Properties, "Actions", "Conditions", "Transforms")
		input["RuleArn"] = r.PhysicalID
		if _, ok := input["Transforms"]; !ok && r.Previous["Transforms"] != nil {
			input["ResetTransforms"] = true
		}
		if err := cfnCSRun(ctx, h.commands, "elbv2", "ModifyRule", input); err != nil {
			return result, err
		}
	}
	if priority := fmt.Sprint(r.Properties["Priority"]); priority != cfnComputeValue(rule.Priority) {
		n, err := strconv.Atoi(priority)
		if err != nil {
			return result, fmt.Errorf("priority must be an integer")
		}
		if err := cfnCSRun(ctx, h.commands, "elbv2", "SetRulePriorities", map[string]any{"RulePriorities": []any{map[string]any{"RuleArn": r.PhysicalID, "Priority": n}}}); err != nil {
			return result, err
		}
	}
	return result, cfnELBReconcileTags(ctx, h.commands, r, r.PhysicalID, tags)
}
func (h cfnELBRule) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	arn := r.PhysicalID
	if arn == "" {
		ctx = cfnNativeComputeContext(ctx, r, true)
		rule, err := h.owned(ctx, r)
		if err != nil || rule == nil {
			return err
		}
		arn = cfnComputeValue(rule.RuleArn)
		r.PhysicalID = arn
		ctx = cfnNativeComputeContext(ctx, r, false)
	}
	_, err := h.get(ctx, arn)
	if cfnELBMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, arn); err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "elbv2", "DeleteRule", map[string]any{"RuleArn": arn})
	if cfnELBMissing(err) {
		return nil
	}
	return err
}
func (h cfnELBRule) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	rule, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(rule, nil)
	if err != nil {
		return nil, err
	}
	if n, err := strconv.Atoi(cfnComputeValue(rule.Priority)); err == nil {
		p["Priority"] = n
	}
	// arn:...:listener-rule/app/<lb>/<lb-id>/<listener-id>/<rule-id>
	listener := strings.Replace(r.PhysicalID, ":listener-rule/", ":listener/", 1)
	p["ListenerArn"] = listener[:strings.LastIndex(listener, "/")]
	if p["Tags"], err = cfnELBPublicTags(ctx, h.commands, r.PhysicalID); err != nil {
		return nil, err
	}
	return cfnCSKeep(p, "RuleArn", "ListenerArn", "Priority", "Actions", "Conditions", "Transforms", "IsDefault", "Tags"), nil
}
func (h cfnELBRule) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	listeners, err := cfnELBListener(h).List(ctx, r)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, listener := range listeners {
		input := map[string]any{"ListenerArn": listener.Identifier}
		for {
			out, err := cfnComputeCall[api.DescribeRulesOutput](ctx, h.commands, "elbv2", "DescribeRules", input)
			if cfnELBMissing(err) {
				break
			}
			if err != nil {
				return nil, err
			}
			for _, rule := range out.Rules {
				if rule.IsDefault != nil && bool(*rule.IsDefault) {
					continue
				}
				arn := cfnComputeValue(rule.RuleArn)
				rows = append(rows, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"RuleArn": arn, "ListenerArn": listener.Identifier}})
			}
			if cfnComputeValue(out.NextMarker) == "" {
				break
			}
			input["Marker"] = cfnComputeValue(out.NextMarker)
		}
	}
	return rows, nil
}
