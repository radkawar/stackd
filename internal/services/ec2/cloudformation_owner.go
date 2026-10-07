package ec2

import (
	"context"
	"errors"
	"strings"
)

// CloudFormation ownership is a private native claim.
// It is admitted atomically with the resource it names, scoped by the exact
// partition/account/region key and never derived from public tags. A claim is
// deployment identity, not authority: every command still evaluates current IAM.

type cloudFormationOwnerKey struct{}
type cloudFormationIntent struct {
	owner  CloudFormationOwner
	create bool
	target string
}

// cloudFormationExternalOwner is implemented by the authoritative EBS owner.
type cloudFormationExternalOwner interface {
	CloudFormationCreation(context.Context, string, string) (string, error)
	CloudFormationOwned(context.Context, string, string, string) error
}

func cloudFormationExternalType(resourceType string) bool {
	return resourceType == "AWS::EC2::Volume" || resourceType == "AWS::EC2::VolumeDeletionSnapshot"
}

type cloudFormationOwnerType struct {
	describe string
	// primary is the exact resource family receiving the creation receipt;
	// children are dependent native rows that inherit the owner when created
	// under that owner's create or mutation context.
	primary  string
	children []string
}

var cloudFormationOwnerTypes = map[string]cloudFormationOwnerType{
	"AWS::EC2::Instance":             {describe: "DescribeInstances", primary: "i"},
	"AWS::EC2::LaunchTemplate":       {describe: "DescribeLaunchTemplates", primary: "lt"},
	"AWS::EC2::KeyPair":              {describe: "DescribeKeyPairs", primary: "key"},
	"AWS::EC2::VPC":                  {describe: "DescribeVpcs", primary: "vpc"},
	"AWS::EC2::Subnet":               {describe: "DescribeSubnets", primary: "subnet"},
	"AWS::EC2::InternetGateway":      {describe: "DescribeInternetGateways", primary: "igw"},
	"AWS::EC2::RouteTable":           {describe: "DescribeRouteTables", primary: "rtb"},
	"AWS::EC2::NatGateway":           {describe: "DescribeNatGateways", primary: "nat"},
	"AWS::EC2::VPCEndpoint":          {describe: "DescribeVpcEndpoints", primary: "vpce"},
	"AWS::EC2::SecurityGroup":        {describe: "DescribeSecurityGroups", primary: "sg", children: []string{"sgr"}},
	"AWS::EC2::SecurityGroupIngress": {describe: "DescribeSecurityGroupRules", primary: "sgr"},
	"AWS::EC2::SecurityGroupEgress":  {describe: "DescribeSecurityGroupRules", primary: "sgr"},
	"AWS::EC2::EIP":                  {describe: "DescribeAddresses", primary: "eipalloc"},
	"AWS::EC2::NetworkAcl":           {describe: "DescribeNetworkAcls", primary: "acl"},
	"AWS::EC2::DHCPOptions":          {describe: "DescribeDhcpOptions", primary: "dopt"},
	"AWS::EC2::NetworkInterface":     {describe: "DescribeNetworkInterfaces", primary: "eni"},
}

func WithCloudFormationCreation(ctx context.Context, resourceType, owner string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationIntent{owner: CloudFormationOwner{ResourceType: resourceType, Owner: owner}, create: true})
}

func WithCloudFormationMutation(ctx context.Context, resourceType, owner, id string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationIntent{owner: CloudFormationOwner{ResourceType: resourceType, Owner: owner}, target: id})
}

// CloudFormationIntent supplies the trusted native context to the separate EBS
// owner. This identity is never parsed from EC2 request properties or tags.
func CloudFormationIntent(ctx context.Context) (owner CloudFormationOwner, target string, create, present bool) {
	intent, present := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationIntent)
	return intent.owner, intent.target, intent.create, present
}

func cloudFormationReceiptKey(scope Scope, owner CloudFormationOwner) NetworkCreationKey {
	return NetworkCreationKey{Scope: scope, Action: "CloudFormationOwner/" + owner.ResourceType, Token: owner.Owner}
}

func ownedPrefix(id, prefix string) bool { return strings.HasPrefix(id, prefix+"-") }

// cloudFormationTransaction observes identifiers allocated by this native
// transaction. Only those are new rows; a replayed or preexisting row is never
// admitted (CloudFormation import or idempotent replay cannot adopt it).
type cloudFormationTransaction struct {
	Transaction
	created []ResourceKey
	intent  cloudFormationIntent
}

func (t *cloudFormationTransaction) NextID(scope Scope, prefix string) (string, error) {
	id, err := t.Transaction.NextID(scope, prefix)
	if err == nil {
		t.created = append(t.created, ResourceKey{Scope: scope, ID: id})
	}
	return id, err
}

// Compute mutations fence the row the command actually writes, not merely the
// identifier supplied by its trusted deployment context. IAM is evaluated by
// the native command before any of these writes.
func (t *cloudFormationTransaction) mutationTarget(k ResourceKey) error {
	if t.intent.create {
		return nil
	}
	if k != key(t.Context(), t.intent.target) {
		return failure("IncorrectState", "The native EC2 mutation targets another CloudFormation resource.")
	}
	current, err := t.Transaction.NetworkResourceOwner(k)
	if err != nil {
		return err
	}
	if current != t.intent.owner {
		return failure("IncorrectState", "The EC2 resource is not owned by this CloudFormation resource incarnation.")
	}
	return nil
}

func (t *cloudFormationTransaction) PutInstance(v InstanceRecord) error {
	if err := t.mutationTarget(v.Key); err != nil {
		return err
	}
	return t.Transaction.PutInstance(v)
}
func (t *cloudFormationTransaction) PutKeyPair(v KeyPairRecord) error {
	if err := t.mutationTarget(v.Key); err != nil {
		return err
	}
	return t.Transaction.PutKeyPair(v)
}
func (t *cloudFormationTransaction) DeleteKeyPair(k ResourceKey) error {
	if err := t.mutationTarget(k); err != nil {
		return err
	}
	return t.Transaction.DeleteKeyPair(k)
}
func (t *cloudFormationTransaction) PutLaunchTemplate(v LaunchTemplateRecord) error {
	if err := t.mutationTarget(v.Key); err != nil {
		return err
	}
	return t.Transaction.PutLaunchTemplate(v)
}
func (t *cloudFormationTransaction) DeleteLaunchTemplate(k ResourceKey) error {
	if err := t.mutationTarget(k); err != nil {
		return err
	}
	return t.Transaction.DeleteLaunchTemplate(k)
}
func (t *cloudFormationTransaction) PutLaunchTemplateVersion(v LaunchTemplateVersionRecord) error {
	if err := t.mutationTarget(v.Key.Template); err != nil {
		return err
	}
	return t.Transaction.PutLaunchTemplateVersion(v)
}
func (t *cloudFormationTransaction) DeleteLaunchTemplateVersion(k LaunchTemplateVersionKey) error {
	if err := t.mutationTarget(k.Template); err != nil {
		return err
	}
	return t.Transaction.DeleteLaunchTemplateVersion(k)
}

type cloudFormationAdmission struct {
	intent cloudFormationIntent
	kind   cloudFormationOwnerType
	tx     *cloudFormationTransaction
	fence  error
}

// beginCloudFormationOwner runs before the native command inside its
// transaction. A mutation fence is evaluated against pre-command state but only
// reported after the command itself has passed current IAM and validation.
func beginCloudFormationOwner(ctx context.Context, tx Transaction) (Transaction, *cloudFormationAdmission, error) {
	intent, marked := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationIntent)
	if !marked {
		return tx, nil, nil
	}
	if cloudFormationExternalType(intent.owner.ResourceType) {
		return tx, nil, nil // EBS admits and fences its own transaction.
	}
	kind, known := cloudFormationOwnerTypes[intent.owner.ResourceType]
	if !known || intent.owner.Owner == "" {
		return nil, nil, failure("InvalidParameterValue", "Unsupported EC2 CloudFormation owner.")
	}
	admission := &cloudFormationAdmission{intent: intent, kind: kind, tx: &cloudFormationTransaction{Transaction: tx, intent: intent}}
	if !intent.create {
		current, err := tx.NetworkResourceOwner(key(ctx, intent.target))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, nil, err
		}
		if err != nil || current != intent.owner {
			admission.fence = failure("IncorrectState", "The EC2 resource is not owned by this CloudFormation resource incarnation.")
		}
	}
	return admission.tx, admission, nil
}

func (a *cloudFormationAdmission) finish(ctx context.Context) error {
	if a == nil {
		return nil
	}
	if a.fence != nil {
		return a.fence
	}
	primary := []ResourceKey{}
	for _, created := range a.tx.created {
		if created.Scope != scopeFor(ctx) {
			continue
		}
		claim := false
		if a.intent.create && ownedPrefix(created.ID, a.kind.primary) {
			primary = append(primary, created)
			claim = true
		}
		for _, child := range a.kind.children {
			claim = claim || ownedPrefix(created.ID, child)
		}
		if !claim {
			continue
		}
		if err := a.tx.Transaction.PutNetworkResourceOwner(created, a.intent.owner); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue // allocated but not persisted by the command
			}
			return err
		}
	}
	if !a.intent.create {
		return nil
	}
	receiptKey := cloudFormationReceiptKey(scopeFor(ctx), a.intent.owner)
	previous, err := a.tx.NetworkOwnerCreation(receiptKey)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	persisted := []ResourceKey{}
	for _, k := range primary {
		if owner, e := a.tx.NetworkResourceOwner(k); e == nil && owner == a.intent.owner {
			persisted = append(persisted, k)
		}
	}
	switch {
	case len(persisted) > 1:
		return failure("InvalidParameterCombination", "A CloudFormation resource incarnation must create exactly one EC2 resource.")
	case len(persisted) == 1 && err == nil:
		return creationMismatch()
	case len(persisted) == 1:
		return a.tx.PutNetworkOwnerCreation(NetworkOwnerCreationRecord{Key: receiptKey, ResourceID: persisted[0].ID})
	case err == nil:
		// Idempotent native replay of this incarnation's own admitted creation.
		owner, e := a.tx.NetworkResourceOwner(key(ctx, previous.ResourceID))
		if e == nil && owner == a.intent.owner {
			return nil
		}
	}
	return failure("IncorrectState", "The native command did not create a new EC2 resource for this CloudFormation incarnation.")
}

// CloudFormationCreation returns the exact admitted resource of an incarnation.
// ErrNotFound certifies, under current IAM, that it never admitted a creation.
func (s *Service) CloudFormationCreation(ctx context.Context, resourceType, owner string) (string, error) {
	if cloudFormationExternalType(resourceType) {
		if ownerService, ok := s.volumes.(cloudFormationExternalOwner); ok {
			return ownerService.CloudFormationCreation(ctx, resourceType, owner)
		}
		return "", unsupported("The EBS private CloudFormation owner is not configured.")
	}
	kind, known := cloudFormationOwnerTypes[resourceType]
	if !known || owner == "" {
		return "", failure("InvalidParameterValue", "Unsupported EC2 CloudFormation owner.")
	}
	if err := s.authorize(ctx, kind.describe, "", "*", nil); err != nil {
		return "", err
	}
	claim := CloudFormationOwner{ResourceType: resourceType, Owner: owner}
	var id string
	err := s.repository.View(ctx, func(r Reader) error {
		ctx := r.Context()
		receipt, err := r.NetworkOwnerCreation(cloudFormationReceiptKey(scopeFor(ctx), claim))
		if err != nil {
			return err
		}
		id = receipt.ResourceID
		current, err := r.NetworkResourceOwner(key(ctx, id))
		if errors.Is(err, ErrNotFound) {
			return failure("IncorrectState", "The admitted EC2 resource of this CloudFormation incarnation no longer exists.")
		}
		if err != nil {
			return err
		}
		if current != claim {
			return failure("IncorrectState", "The admitted EC2 resource no longer carries this CloudFormation incarnation.")
		}
		if resourceType == "AWS::EC2::Instance" {
			instance, err := r.Instance(key(ctx, id))
			if err != nil {
				return err
			}
			if state := instanceState(instance); state == "terminated" || state == "shutting-down" {
				return failure("IncorrectState", "The admitted EC2 instance has been terminated.")
			}
		}
		if resourceType == "AWS::EC2::NatGateway" {
			gateway, err := r.NatGateway(key(ctx, id))
			if err != nil {
				return err
			}
			if state := str(gateway.Data.State); state == "deleted" || state == "deleting" {
				return failure("IncorrectState", "The admitted EC2 NAT gateway has been deleted.")
			}
		}
		if resourceType == "AWS::EC2::VPCEndpoint" {
			endpoint, err := r.VPCEndpoint(key(ctx, id))
			if err != nil {
				return err
			}
			if state := str(endpoint.Data.State); state == "deleted" || state == "deleting" {
				return failure("IncorrectState", "The admitted EC2 VPC endpoint has been deleted.")
			}
		}
		return nil
	})
	return id, err
}

// CloudFormationOwned observes the exact private claim under current IAM.
func (s *Service) CloudFormationOwned(ctx context.Context, resourceType, owner, id string) error {
	if cloudFormationExternalType(resourceType) {
		if ownerService, ok := s.volumes.(cloudFormationExternalOwner); ok {
			return ownerService.CloudFormationOwned(ctx, resourceType, owner, id)
		}
		return unsupported("The EBS private CloudFormation owner is not configured.")
	}
	kind, known := cloudFormationOwnerTypes[resourceType]
	if !known || owner == "" {
		return failure("InvalidParameterValue", "Unsupported EC2 CloudFormation owner.")
	}
	if err := s.authorize(ctx, kind.describe, "", "*", nil); err != nil {
		return err
	}
	claim := CloudFormationOwner{ResourceType: resourceType, Owner: owner}
	return s.repository.View(ctx, func(r Reader) error {
		current, err := r.NetworkResourceOwner(key(r.Context(), id))
		if errors.Is(err, ErrNotFound) {
			return failure("InvalidResourceID.NotFound", "The EC2 resource '"+id+"' does not exist.")
		}
		if err != nil {
			return err
		}
		if current != claim {
			return failure("IncorrectState", "The EC2 resource is not owned by this CloudFormation resource incarnation.")
		}
		return nil
	})
}

// CloudFormationKeyPairPrivateKey certifies that this exact privately owned
// native key committed generated material through its trusted transactional sink.
func (s *Service) CloudFormationKeyPairPrivateKey(ctx context.Context, id string) (bool, error) {
	if err := s.authorize(ctx, "DescribeKeyPairs", "", "*", nil); err != nil {
		return false, err
	}
	var managed bool
	err := s.repository.View(ctx, func(r Reader) error {
		k := key(r.Context(), id)
		pair, err := r.KeyPair(k)
		if err != nil {
			return err
		}
		if pair.CloudFormationOwner.ResourceType != "AWS::EC2::KeyPair" || pair.CloudFormationOwner.Owner == "" {
			return nil
		}
		receipt, err := r.NetworkOwnerCreation(NetworkCreationKey{Scope: k.Scope, Action: "CloudFormationKeyPairMaterial", Token: pair.CloudFormationOwner.Owner})
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		managed = receipt.ResourceID == id
		return nil
	})
	return managed, err
}
