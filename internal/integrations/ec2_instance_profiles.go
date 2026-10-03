package integrations

import (
	"context"
	"errors"
	"strings"
	"time"

	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
	"stackd/journal"
)

// EC2InstanceProfileAuthority reads the current IAM-owned profile association.
// It is internal admission authority, not a public GetInstanceProfile request.
type EC2InstanceProfileAuthority interface {
	InstanceProfileForUse(context.Context, string) (iam.InstanceProfileSnapshot, error)
}

// EC2InstanceProfiles uses IAM's shared session issuer and credential repository.
// EC2 retains only the delivered credential's ID. A live delivered session remains
// available until refresh even after profile membership/trust changes, matching
// the EC2 credential-rotation contract; association changes never revoke it.
type EC2InstanceProfiles struct {
	IAM   EC2InstanceProfileAuthority
	Roles ServiceRoles
}

var _ ec2.InstanceProfiles = (*EC2InstanceProfiles)(nil)

func (a *EC2InstanceProfiles) ResolveInstanceProfile(ctx context.Context, specification api.IamInstanceProfileSpecification) (iamapi.InstanceProfile, error) {
	var reference string
	if specification.Arn != nil {
		reference = string(*specification.Arn)
	} else if specification.Name != nil {
		reference = string(*specification.Name)
	}
	profile, err := a.resolve(ctx, reference)
	if err != nil {
		return iamapi.InstanceProfile{}, err
	}
	return profile.Profile, nil
}

// Native instance_profiles_{lifecycle,transitions}.json captures expire credentials
// 6h35m after iam/info's LastUpdated, independently of the role's one-hour maximum.
const ec2ProfileSessionDuration = 6*time.Hour + 35*time.Minute

// Keep profile membership refresh within AWS's documented one-hour window,
// independently of the lifetime of credentials already delivered to a guest.
// TODO: Comeback capture long-lived EC2 rotation timing; 55 minutes is the local
// publication policy, not a measured AWS rotation interval.
const ec2ProfileRefreshInterval = 55 * time.Minute

// InstanceProfileCredentials reuses a delivered IAM credential until the next
// profile refresh. Fresh association/start clears the reference and immediately
// rechecks profile incarnation, membership and trust. Previously delivered
// credentials remain valid until their own expiration.
func (a *EC2InstanceProfiles) InstanceProfileCredentials(ctx context.Context, origin ec2.InstanceCredentialOrigin, profile api.IamInstanceProfile, previousID string, imdsv2 bool) (ec2.InstanceProfileCredential, error) {
	metadata := awsctx.FromContext(ctx)
	prefix := "arn:" + metadata.Partition + ":ec2:" + metadata.Region + ":" + metadata.AccountID + ":instance/"
	instanceID, valid := strings.CutPrefix(origin.InstanceARN, prefix)
	if !valid || !strings.HasPrefix(instanceID, "i-") || strings.Contains(instanceID, "/") {
		return ec2.InstanceProfileCredential{}, ec2ProfileFailure("The instance must belong to the current account and region.")
	}
	if a.Roles.IAM == nil {
		return ec2.InstanceProfileCredential{}, &awswire.Error{Code: "InternalFailure", Message: "IAM session authority is not configured.", StatusCode: 500}
	}
	var delivered identity.Credential
	deliveryVersion := ec2RoleDelivery(imdsv2)
	if previousID != "" {
		err := a.Roles.IAM.WithSession(ctx, func(ctx context.Context, repository identity.Repository, now time.Time) error {
			return repository.View(ctx, func(reader identity.Reader) error {
				record, err := reader.Get(previousID)
				if errors.Is(err, identity.ErrNotFound) {
					return nil
				}
				if err != nil {
					return err
				}
				credential := record.Credential
				rolePrefix := "arn:" + metadata.Partition + ":iam::" + metadata.AccountID + ":role/"
				version := credential.SessionContext["ec2:roledelivery"]
				issuedTo := credential.SessionContext["ec2:sourceinstancearn"]
				if record.Status == identity.Active && credential.AccountID == metadata.AccountID && credential.SessionType == identity.SessionTypeAssumeRole && strings.HasPrefix(credential.IssuerARN, rolePrefix) && strings.HasSuffix(credential.PrincipalARN, "/"+instanceID) && now.Before(credential.CreateDate.Add(ec2ProfileRefreshInterval)) && len(version) == 1 && version[0] == deliveryVersion && len(issuedTo) == 1 && issuedTo[0] == origin.InstanceARN {
					delivered = credential
				}
				return nil
			})
		})
		if err != nil {
			return ec2.InstanceProfileCredential{}, err
		}
		if delivered.AccessKeyID != "" {
			return ec2ProfileCredential(delivered), nil
		}
	}
	source := awsctx.ServicePrincipal{Name: "ec2." + ec2SnapshotKMSSuffix(metadata.Partition), Type: "AWSService"}
	var result ec2.InstanceProfileCredential
	credential, rejected := a.Roles.assumeResolved(ctx, source,
		identity.RoleSessionSpec{SessionName: instanceID, Duration: ec2ProfileSessionDuration, RequestParentEventID: metadata.ParentEventID,
			InScopeOf: journal.APIIdentityScope{IssuerType: "AWS::EC2::Instance", CredentialsIssuedTo: origin.InstanceARN},
			SessionContext: map[string][]string{
				"ec2:roledelivery": {deliveryVersion}, "ec2:sourceinstancearn": {origin.InstanceARN},
				"aws:ec2instancesourcevpc": {origin.VPCID}, "aws:ec2instancesourceprivateipv4": {origin.PrivateIPv4},
			}}, "",
		func(ctx context.Context) (string, error) {
			current, err := a.resolve(ctx, profileARN(profile))
			if err != nil || current.ID != profileID(profile) {
				return "", &awswire.Error{Code: "InstanceProfileNotFound", Message: "Instance profile not found.", StatusCode: 400}
			}
			if len(current.Profile.Roles) != 0 && current.Profile.Roles[0].RoleName != nil {
				result.RoleName = string(*current.Profile.Roles[0].RoleName)
			}
			if current.RoleARN == "" {
				return "", &awswire.Error{Code: "InstanceProfileEmpty", Message: "Instance Profile does not contain a role.", StatusCode: 400}
			}
			return current.RoleARN, nil
		})
	if rejected != nil {
		if rejected.Code == "InstanceProfileEmpty" {
			return result, nil
		}
		return result, rejected
	}
	return ec2ProfileCredential(credential), nil
}

func ec2ProfileCredential(credential identity.Credential) ec2.InstanceProfileCredential {
	return ec2.InstanceProfileCredential{RoleName: credential.IssuerARN[strings.LastIndexByte(credential.IssuerARN, '/')+1:], Credentials: serviceAssumeRoleOutput(credential).Credentials, LastUpdated: credential.CreateDate}
}

func profileARN(profile api.IamInstanceProfile) string {
	if profile.Arn == nil {
		return ""
	}
	return string(*profile.Arn)
}

func profileID(profile api.IamInstanceProfile) string {
	if profile.Id == nil {
		return ""
	}
	return string(*profile.Id)
}

func (a *EC2InstanceProfiles) resolve(ctx context.Context, reference string) (iam.InstanceProfileSnapshot, error) {
	if a.IAM == nil {
		return iam.InstanceProfileSnapshot{}, &awswire.Error{Code: "InternalFailure", Message: "IAM instance-profile authority is not configured.", StatusCode: 500}
	}
	profile, err := a.IAM.InstanceProfileForUse(ctx, reference)
	if err != nil {
		return iam.InstanceProfileSnapshot{}, ec2ProfileFailure("Invalid IAM instance profile " + reference + ": " + err.Error())
	}
	return profile, nil
}

func ec2ProfileFailure(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidParameterValue", Message: message, StatusCode: 400}
}
