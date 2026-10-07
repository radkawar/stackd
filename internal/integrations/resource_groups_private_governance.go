package integrations

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayv2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cloudtrail"
	"stackd/internal/services/cloudwatch"
	"stackd/internal/services/iam"
	"stackd/internal/services/xray"
)

// privateGovernanceOwners borrows the enclosing coordinated read context. Public
// tags and the candidate ledger select no ownership: only native private claims do.
func (r ResourceGroupsResources) privateGovernanceOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if err := r.privateGovernanceIAMOwners(ctx, scope, owners); err != nil {
		return err
	}
	if err := r.privateGovernanceOrganizationOwners(ctx, scope, owners); err != nil {
		return err
	}
	if err := r.privateGovernanceCloudWatchOwners(ctx, scope, owners); err != nil {
		return err
	}
	if err := r.privateGovernanceCloudTrailOwners(ctx, scope, owners); err != nil {
		return err
	}
	if err := r.privateGovernanceXRayOwners(ctx, scope, owners); err != nil {
		return err
	}
	if err := r.privateGovernanceRESTOwners(ctx, scope, owners); err != nil {
		return err
	}
	// The parent already preserves the native nested-stack identity relation;
	// CloudFormation stack membership needs no second repository read here.
	return r.privateGovernanceV2Owners(ctx, scope, owners)
}

func resourceGroupsGovernanceARN(scope cloudformation.Scope, value, service, region, account string) (arn.ARN, bool) {
	parsed, err := arn.Parse(value)
	return parsed, err == nil && parsed.Partition == scope.Partition && parsed.Service == service && parsed.Region == region && parsed.AccountID == account && parsed.Resource != ""
}

func resourceGroupsGovernanceOrganizationClaim(request cloudformation.ResourceRequest) string {
	return request.StackID + "/" + request.LogicalID + "/" + request.Token
}

func (r ResourceGroupsResources) privateGovernanceIAMOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::ServiceLinkedRole", "AWS::IAM::ManagedPolicy", "AWS::IAM::InstanceProfile", "AWS::IAM::VirtualMFADevice", "AWS::IAM::OpenIDConnectProvider", "AWS::IAM::SAMLProvider", "AWS::IAM::ServerCertificate") || r.Tagging.Backends.IAM == nil {
		return nil
	}
	return r.Tagging.Backends.IAM.View(ctx, func(tx iam.ReadTx) error {
		sc := iam.Scope{Partition: scope.Partition, AccountID: scope.Account}
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			parsed, ok := resourceGroupsGovernanceARN(scope, candidate, "iam", "", scope.Account)
			if !ok {
				continue
			}
			name := parsed.Resource[strings.LastIndexByte(parsed.Resource, '/')+1:]
			var actualARN, claim string
			var err error
			switch request.Type {
			case "AWS::IAM::User":
				if !strings.HasPrefix(parsed.Resource, "user/") {
					continue
				}
				var row iam.User
				row, err = tx.User(sc, name)
				actualARN, claim = row.Arn, row.CloudFormationOwner
			case "AWS::IAM::Role", "AWS::IAM::ServiceLinkedRole":
				if !strings.HasPrefix(parsed.Resource, "role/") {
					continue
				}
				var row iam.Role
				row, err = tx.Role(sc, name)
				if err == nil && request.Type == "AWS::IAM::ServiceLinkedRole" && !strings.HasPrefix(row.Path, "/aws-service-role/") {
					continue
				}
				actualARN, claim = row.Arn, row.CloudFormationOwner
			case "AWS::IAM::ManagedPolicy":
				if !strings.HasPrefix(parsed.Resource, "policy/") {
					continue
				}
				var row iam.ManagedPolicy
				row, err = tx.ManagedPolicy(sc, candidate)
				actualARN, claim = row.Arn, row.CloudFormationOwner
			case "AWS::IAM::InstanceProfile":
				if !strings.HasPrefix(parsed.Resource, "instance-profile/") {
					continue
				}
				var row iam.InstanceProfile
				row, err = tx.InstanceProfile(sc, name)
				actualARN, claim = row.Arn, row.CloudFormationOwner
			case "AWS::IAM::VirtualMFADevice":
				if !strings.HasPrefix(parsed.Resource, "mfa/") {
					continue
				}
				var row iam.MFADevice
				row, err = tx.MFADevice(sc, candidate)
				if err == nil && !row.RetiredAt.IsZero() {
					continue
				}
				actualARN, claim = row.SerialNumber, row.CloudFormationOwner
			case "AWS::IAM::OpenIDConnectProvider":
				if !strings.HasPrefix(parsed.Resource, "oidc-provider/") {
					continue
				}
				var row iam.OIDCProviderRecord
				row, err = tx.OIDCProvider(sc, candidate)
				actualARN, claim = row.ARN, row.CloudFormationOwner
			case "AWS::IAM::SAMLProvider":
				if !strings.HasPrefix(parsed.Resource, "saml-provider/") {
					continue
				}
				var row iam.SAMLProviderRecord
				row, err = tx.SAMLProvider(sc, candidate)
				actualARN, claim = row.ARN, row.CloudFormationOwner
			case "AWS::IAM::ServerCertificate":
				if !strings.HasPrefix(parsed.Resource, "server-certificate/") {
					continue
				}
				var row iam.ServerCertificateRecord
				row, err = tx.ServerCertificate(sc, name)
				actualARN, claim = row.ARN, row.CloudFormationOwner
			default:
				continue
			}
			if errors.Is(err, iam.ErrRecordNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			physicalID := candidate
			switch request.Type {
			case "AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::ServiceLinkedRole", "AWS::IAM::InstanceProfile", "AWS::IAM::ServerCertificate":
				physicalID = name
			}
			if request.PhysicalID != physicalID && request.PhysicalID != candidate {
				continue
			}
			if actualARN == candidate {
				owners.claim(candidate, claim, cfnIAMPolicyOwner)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateGovernanceOrganizationOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	// Native roots have no private claim and no claimable CFN resource adapter.
	if !owners.needs("AWS::Organizations::Account", "AWS::Organizations::OrganizationalUnit", "AWS::Organizations::Policy", "AWS::Organizations::ResourcePolicy") || r.Tagging.Backends.Organizations == nil {
		return nil
	}
	partition, _, err := r.Tagging.Backends.Organizations.Load(ctx, scope.Partition)
	if err != nil {
		return err
	}
	claim := func(value, id, actual, kind string) {
		request, ok := owners.requests[value]
		if !ok || request.Type != kind || request.Scope != scope || (request.PhysicalID != id && request.PhysicalID != value) {
			return
		}
		if _, ok := resourceGroupsGovernanceARN(scope, value, "organizations", "", scope.Account); ok {
			owners.claim(value, actual, resourceGroupsGovernanceOrganizationClaim)
		}
	}
	for _, organization := range partition.Organizations {
		if organization.Organization.MasterAccountID != scope.Account {
			continue
		}
		if owners.needs("AWS::Organizations::Account") {
			for _, row := range organization.Accounts {
				if row.CloudFormationRegion == scope.Region {
					claim(row.ARN, row.ID, row.CloudFormationOwner, "AWS::Organizations::Account")
				}
			}
		}
		if owners.needs("AWS::Organizations::OrganizationalUnit") {
			for _, row := range organization.Units {
				claim(row.ARN, row.ID, row.CloudFormationOwner, "AWS::Organizations::OrganizationalUnit")
			}
		}
		if owners.needs("AWS::Organizations::Policy") {
			for _, row := range organization.Policies {
				if !row.PolicySummary.AWSManaged {
					claim(row.PolicySummary.ARN, row.PolicySummary.ID, row.CloudFormationOwner, "AWS::Organizations::Policy")
				}
			}
		}
		if owners.needs("AWS::Organizations::ResourcePolicy") && organization.ResourcePolicy.ID != "" {
			claim(organization.ResourcePolicy.ARN, organization.ResourcePolicy.ID, organization.ResourcePolicy.CloudFormationOwner, "AWS::Organizations::ResourcePolicy")
		}
	}
	return nil
}

func (r ResourceGroupsResources) privateGovernanceCloudWatchOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::CloudWatch::Alarm", "AWS::CloudWatch::CompositeAlarm", "AWS::CloudWatch::Dashboard") || r.Tagging.Backends.CloudWatch == nil {
		return nil
	}
	return r.Tagging.Backends.CloudWatch.View(ctx, func(tx cloudwatch.Reader) error {
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			switch request.Type {
			case "AWS::CloudWatch::Alarm", "AWS::CloudWatch::CompositeAlarm":
				parsed, ok := resourceGroupsGovernanceARN(scope, candidate, "cloudwatch", scope.Region, scope.Account)
				if !ok || !strings.HasPrefix(parsed.Resource, "alarm:") {
					continue
				}
				key := cloudwatch.AlarmKey{Scope: cloudwatch.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}, Name: strings.TrimPrefix(parsed.Resource, "alarm:")}
				if request.PhysicalID != key.Name && request.PhysicalID != candidate {
					continue
				}
				row, err := tx.Alarm(key)
				if errors.Is(err, cloudwatch.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if row.Key == key && row.Key.ARN() == candidate && ((request.Type == "AWS::CloudWatch::Alarm" && row.Metric != nil && row.Composite == nil) || (request.Type == "AWS::CloudWatch::CompositeAlarm" && row.Composite != nil && row.Metric == nil)) {
					owners.claim(candidate, row.CFNOwner, cfnLogsMarker)
				}
			case "AWS::CloudWatch::Dashboard":
				parsed, ok := resourceGroupsGovernanceARN(scope, candidate, "cloudwatch", "", scope.Account)
				if !ok || !strings.HasPrefix(parsed.Resource, "dashboard/") {
					continue
				}
				key := cloudwatch.DashboardKey{Partition: scope.Partition, AccountID: scope.Account, Name: strings.TrimPrefix(parsed.Resource, "dashboard/")}
				if request.PhysicalID != key.Name && request.PhysicalID != candidate {
					continue
				}
				row, err := tx.Dashboard(key)
				if errors.Is(err, cloudwatch.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if row.Key == key && row.Key.ARN() == candidate {
					owners.claim(candidate, row.CFNOwner, cfnLogsMarker)
				}
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateGovernanceCloudTrailOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::CloudTrail::Trail") || r.Tagging.Backends.CloudTrail == nil {
		return nil
	}
	return r.Tagging.Backends.CloudTrail.View(ctx, func(tx cloudtrail.Reader) error {
		for candidate, request := range owners.requests {
			if request.Type != "AWS::CloudTrail::Trail" || request.Scope != scope {
				continue
			}
			parsed, ok := resourceGroupsGovernanceARN(scope, candidate, "cloudtrail", scope.Region, scope.Account)
			if !ok || !strings.HasPrefix(parsed.Resource, "trail/") {
				continue
			}
			key := cloudtrail.TrailKey{Scope: cloudtrail.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}, Name: strings.TrimPrefix(parsed.Resource, "trail/")}
			if request.PhysicalID != key.Name && request.PhysicalID != candidate {
				continue
			}
			row, err := tx.Trail(key)
			if errors.Is(err, cloudtrail.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if row.Key == key && row.Key.ARN() == candidate {
				owners.claim(candidate, row.CFNOwner, cfnLogsMarker)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateGovernanceXRayOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::XRay::Group", "AWS::XRay::SamplingRule") || r.Tagging.Backends.XRay == nil {
		return nil
	}
	return r.Tagging.Backends.XRay.View(ctx, func(tx xray.Reader) error {
		sc := xray.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			parsed, ok := resourceGroupsGovernanceARN(scope, candidate, "xray", scope.Region, scope.Account)
			if !ok {
				continue
			}
			switch request.Type {
			case "AWS::XRay::Group":
				if !strings.HasPrefix(parsed.Resource, "group/") {
					continue
				}
				name, id, _ := strings.Cut(strings.TrimPrefix(parsed.Resource, "group/"), "/")
				key := xray.GroupKey{Scope: sc, Name: name, ID: id}
				if request.PhysicalID != key.Name && request.PhysicalID != candidate {
					continue
				}
				row, err := tx.Group(key)
				if errors.Is(err, xray.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if row.Key == key && row.Key.ARN() == candidate {
					owners.claim(candidate, row.CFNOwner, cfnLogsMarker)
				}
			case "AWS::XRay::SamplingRule":
				if !strings.HasPrefix(parsed.Resource, "sampling-rule/") {
					continue
				}
				key := xray.SamplingRuleKey{Scope: sc, Name: strings.TrimPrefix(parsed.Resource, "sampling-rule/")}
				if request.PhysicalID != key.Name && request.PhysicalID != candidate {
					continue
				}
				row, err := tx.SamplingRule(key)
				if errors.Is(err, xray.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if row.Key == key && row.Key.ARN() == candidate {
					owners.claim(candidate, row.CFNOwner, cfnLogsMarker)
				}
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateGovernanceRESTOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::ApiGateway::RestApi", "AWS::ApiGateway::Stage", "AWS::ApiGateway::ApiKey", "AWS::ApiGateway::UsagePlan") || r.Tagging.Backends.APIGateway == nil {
		return nil
	}
	return r.Tagging.Backends.APIGateway.View(ctx, func(tx apigateway.Reader) error {
		sc := apigateway.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			parsed, ok := resourceGroupsGovernanceARN(scope, candidate, "apigateway", scope.Region, "")
			if !ok {
				continue
			}
			var claim apigateway.Ownership
			var actualPath, actualID string
			var err error
			switch request.Type {
			case "AWS::ApiGateway::RestApi":
				if !strings.HasPrefix(parsed.Resource, "/restapis/") {
					continue
				}
				key := apigateway.APIKey{Scope: sc, ID: strings.TrimPrefix(parsed.Resource, "/restapis/")}
				row, readErr := tx.API(key)
				err = readErr
				if row.Key == key {
					actualPath, actualID, claim = "/restapis/"+row.Key.ID, row.Key.ID, row.Ownership
				}
			case "AWS::ApiGateway::Stage":
				if !strings.HasPrefix(parsed.Resource, "/restapis/") {
					continue
				}
				apiID, name, ok := strings.Cut(strings.TrimPrefix(parsed.Resource, "/restapis/"), "/stages/")
				if !ok || apiID == "" || name == "" {
					continue
				}
				key := apigateway.StageKey{APIKey: apigateway.APIKey{Scope: sc, ID: apiID}, Name: name}
				row, readErr := tx.Stage(key)
				err = readErr
				if row.Key == key {
					actualPath, actualID, claim = "/restapis/"+row.Key.ID+"/stages/"+row.Key.Name, row.Key.ID+"/"+row.Key.Name, row.Ownership
				}
			case "AWS::ApiGateway::ApiKey":
				if !strings.HasPrefix(parsed.Resource, "/apikeys/") {
					continue
				}
				key := apigateway.ClientKey{Scope: sc, ID: strings.TrimPrefix(parsed.Resource, "/apikeys/")}
				row, readErr := tx.ClientKey(key)
				err = readErr
				if row.Key == key {
					actualPath, actualID, claim = "/apikeys/"+row.Key.ID, row.Key.ID, row.Ownership
				}
			case "AWS::ApiGateway::UsagePlan":
				if !strings.HasPrefix(parsed.Resource, "/usageplans/") {
					continue
				}
				key := apigateway.PlanKey{Scope: sc, ID: strings.TrimPrefix(parsed.Resource, "/usageplans/")}
				row, readErr := tx.UsagePlan(key)
				err = readErr
				if row.Key == key {
					actualPath, actualID, claim = "/usageplans/"+row.Key.ID, row.Key.ID, row.Ownership
				}
			default:
				continue
			}
			if errors.Is(err, apigateway.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if actualPath == parsed.Resource && (request.PhysicalID == actualID || request.PhysicalID == candidate) {
				owners.structured(candidate, claim.StackID, claim.LogicalID, claim.Incarnation)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateGovernanceV2Owners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::ApiGatewayV2::Api", "AWS::ApiGatewayV2::Stage") || r.Tagging.Backends.APIGatewayV2 == nil {
		return nil
	}
	return r.Tagging.Backends.APIGatewayV2.View(ctx, func(tx apigatewayv2.Reader) error {
		sc := apigatewayv2.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			parsed, ok := resourceGroupsGovernanceARN(scope, candidate, "apigateway", scope.Region, "")
			if !ok || !strings.HasPrefix(parsed.Resource, "/apis/") {
				continue
			}
			var claim apigatewayv2.ResourceOwner
			var actualPath, actualID string
			var err error
			switch request.Type {
			case "AWS::ApiGatewayV2::Api":
				key := apigatewayv2.APIKey{Scope: sc, ID: strings.TrimPrefix(parsed.Resource, "/apis/")}
				row, readErr := tx.API(key)
				err = readErr
				if row.Key == key {
					actualPath, actualID, claim = "/apis/"+row.Key.ID, row.Key.ID, row.Owner
				}
			case "AWS::ApiGatewayV2::Stage":
				apiID, name, ok := strings.Cut(strings.TrimPrefix(parsed.Resource, "/apis/"), "/stages/")
				if !ok || apiID == "" || name == "" {
					continue
				}
				key := apigatewayv2.ResourceKey{APIKey: apigatewayv2.APIKey{Scope: sc, ID: apiID}, ID: name}
				row, readErr := tx.Stage(key)
				err = readErr
				if row.Key == key {
					actualPath, actualID, claim = "/apis/"+row.Key.APIKey.ID+"/stages/"+row.Key.ID, row.Key.APIKey.ID+"|"+row.Key.ID, row.Owner
				}
			default:
				continue
			}
			if errors.Is(err, apigatewayv2.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if actualPath == parsed.Resource && (request.PhysicalID == actualID || request.PhysicalID == candidate) {
				owners.structured(candidate, claim.StackID, claim.LogicalID, claim.Token)
			}
		}
		return nil
	})
}
