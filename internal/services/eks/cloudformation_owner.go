package eks

import (
	"context"
	"errors"
	"strings"
)

// CloudFormationCreationKey identifies a trusted deployment incarnation in its
// exact native scope. Claims are not tags and never replace current IAM.
type CloudFormationCreationKey struct {
	Scope
	ResourceType, Owner string
}
type CloudFormationCreation struct {
	Key                                                CloudFormationCreationKey
	ClusterName, NativeName, NativeID, PhysicalID, ARN string
}
type cloudFormationIntent struct {
	ResourceType, Owner, Target string
	Create                      bool
}
type cloudFormationIntentKey struct{}
type cloudFormationTransactionKey struct{}

func WithCloudFormationCreation(ctx context.Context, resourceType, owner string) context.Context {
	return context.WithValue(ctx, cloudFormationIntentKey{}, cloudFormationIntent{ResourceType: resourceType, Owner: owner, Create: true})
}
func WithCloudFormationMutation(ctx context.Context, resourceType, owner, target string) context.Context {
	return context.WithValue(ctx, cloudFormationIntentKey{}, cloudFormationIntent{ResourceType: resourceType, Owner: owner, Target: target})
}
func cloudFormationKind(resourceType string) string {
	switch resourceType {
	case "AWS::EKS::Cluster", "AWS::EKS::Nodegroup", "AWS::EKS::Addon", "AWS::EKS::FargateProfile", "AWS::EKS::AccessEntry", "AWS::EKS::PodIdentityAssociation":
		return strings.TrimPrefix(resourceType, "AWS::EKS::")
	}
	return ""
}
func cloudFormationMismatch() error {
	return failure("InvalidRequestException", "The EKS resource is not owned by this CloudFormation resource incarnation.", 400)
}

// This hook runs only after the ordinary native IAM evaluation and before any
// dependency admission or state mutation. The receipt is read in that same tx.
func cloudFormationAuthorized(ctx context.Context, resource, action string) error {
	intent, marked := ctx.Value(cloudFormationIntentKey{}).(cloudFormationIntent)
	if !marked {
		return nil
	}
	tx, ok := ctx.Value(cloudFormationTransactionKey{}).(Transaction)
	if !ok || intent.Owner == "" || cloudFormationKind(intent.ResourceType) == "" {
		return cloudFormationMismatch()
	}
	key := CloudFormationCreationKey{Scope: scopeFor(ctx), ResourceType: intent.ResourceType, Owner: intent.Owner}
	receipt, err := tx.CloudFormationCreation(key)
	if intent.Create {
		if action != "Create"+cloudFormationKind(intent.ResourceType) {
			return cloudFormationMismatch()
		}
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return cloudFormationMismatch()
	}
	if errors.Is(err, ErrNotFound) {
		return cloudFormationMismatch()
	}
	if err != nil {
		return err
	}
	if receipt.PhysicalID != intent.Target {
		return cloudFormationMismatch()
	}
	_, _, err = cloudFormationLive(tx, receipt)
	if errors.Is(err, ErrNotFound) {
		if action == "Describe"+cloudFormationKind(intent.ResourceType) {
			return nil
		}
		return cloudFormationMismatch()
	}
	if err != nil {
		return err
	}
	// Update observation is scoped to a cluster, not a child ARN.
	if resource != receipt.ARN && !((action == "ListUpdates" || action == "DescribeUpdate") && resource == (Key{Scope: key.Scope, Name: receipt.ClusterName}).ARN()) {
		return cloudFormationMismatch()
	}
	return nil
}

func cloudFormationLive(r Reader, receipt CloudFormationCreation) (string, map[string]string, error) {
	key := Key{Scope: receipt.Key.Scope, Name: receipt.ClusterName}
	var id, arn string
	var tags map[string]string
	var err error
	switch cloudFormationKind(receipt.Key.ResourceType) {
	case "Cluster":
		var row Cluster
		row, err = r.Cluster(key)
		id, arn, tags = row.ID, row.Key.ARN(), row.Tags
	case "Nodegroup":
		var row Nodegroup
		row, err = r.Nodegroup(NodegroupKey{Cluster: key, Name: receipt.NativeName})
		id, arn, tags = row.ID, row.Key.ARN(row.ID), row.Tags
	case "Addon":
		var row Addon
		row, err = r.Addon(key, receipt.NativeName)
		id, arn, tags = row.ID, row.ARN(), row.Tags
	case "FargateProfile":
		var row FargateProfile
		row, err = r.FargateProfile(key, receipt.NativeName)
		id, arn, tags = row.ID, row.ARN(), row.Tags
	case "AccessEntry":
		var row AccessEntry
		row, err = r.AccessEntry(key, receipt.NativeName)
		id, arn, tags = row.ID, accessARN(row), row.Tags
	case "PodIdentityAssociation":
		var row PodIdentityAssociation
		row, err = r.PodIdentityAssociation(key, receipt.NativeName)
		id, arn, tags = row.ID, row.ARN(), row.Tags
	default:
		return "", nil, cloudFormationMismatch()
	}
	if err != nil {
		return "", nil, err
	}
	if id == "" || id != receipt.NativeID || arn != receipt.ARN {
		return "", nil, cloudFormationMismatch()
	}
	return arn, tags, nil
}

// Missing receipts are certified under current native Describe IAM, never by a
// public inventory. A deleted incarnation is a mismatch, not permission to adopt
// a replacement with the same customer-visible name.
func (s *Service) CloudFormationCreation(ctx context.Context, resourceType, owner string) (string, error) {
	kind := cloudFormationKind(resourceType)
	if kind == "" || owner == "" {
		return "", cloudFormationMismatch()
	}
	// Private observation is its own ordinary IAM evaluation, not a marked command.
	ctx = context.WithValue(ctx, cloudFormationIntentKey{}, nil)
	var result string
	err := s.repository.View(ctx, func(r Reader) error {
		ctx := r.Context()
		receipt, err := r.CloudFormationCreation(CloudFormationCreationKey{Scope: scopeFor(ctx), ResourceType: resourceType, Owner: owner})
		if errors.Is(err, ErrNotFound) {
			if denied := s.authorizeResource(ctx, "*", nil, "Describe"+kind, nil); denied != nil {
				return denied
			}
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		arn, tags, liveErr := cloudFormationLive(r, receipt)
		if liveErr != nil {
			arn = receipt.ARN
		}
		if denied := s.authorizeResource(ctx, arn, tags, "Describe"+kind, nil); denied != nil {
			return denied
		}
		if errors.Is(liveErr, ErrNotFound) {
			return cloudFormationMismatch()
		}
		if liveErr != nil {
			return liveErr
		}
		result = receipt.PhysicalID
		return nil
	})
	return result, err
}
func (s *Service) CloudFormationOwned(ctx context.Context, resourceType, owner, target string) error {
	id, err := s.CloudFormationCreation(ctx, resourceType, owner)
	if errors.Is(err, ErrNotFound) {
		return cloudFormationMismatch()
	}
	if err != nil {
		return err
	}
	if id != target {
		return cloudFormationMismatch()
	}
	return nil
}

// Only genuinely new native rows are admitted. Idempotent public native replay
// never imports an unclaimed resource. Auxiliary cluster writes are not claims.
type cloudFormationTransaction struct {
	Transaction
	intent  cloudFormationIntent
	created CloudFormationCreation
	count   int
}

func (tx *cloudFormationTransaction) remember(kind, cluster, name, id, physical, arn string, prior error) error {
	if !tx.intent.Create || cloudFormationKind(tx.intent.ResourceType) != kind {
		return nil
	}
	if prior != nil && !errors.Is(prior, ErrNotFound) {
		return prior
	}
	if prior == nil {
		return nil
	}
	tx.count++
	tx.created = CloudFormationCreation{Key: CloudFormationCreationKey{Scope: scopeFor(tx.Context()), ResourceType: tx.intent.ResourceType, Owner: tx.intent.Owner}, ClusterName: cluster, NativeName: name, NativeID: id, PhysicalID: physical, ARN: arn}
	return nil
}
func (tx *cloudFormationTransaction) PutCluster(v Cluster) error {
	if !tx.intent.Create || tx.intent.ResourceType != "AWS::EKS::Cluster" {
		return tx.Transaction.PutCluster(v)
	}
	_, prior := tx.Cluster(v.Key)
	if err := tx.remember("Cluster", v.Key.Name, v.Key.Name, v.ID, v.Key.Name, v.Key.ARN(), prior); err != nil {
		return err
	}
	return tx.Transaction.PutCluster(v)
}
func (tx *cloudFormationTransaction) PutNodegroup(v Nodegroup) error {
	if !tx.intent.Create || tx.intent.ResourceType != "AWS::EKS::Nodegroup" {
		return tx.Transaction.PutNodegroup(v)
	}
	_, prior := tx.Nodegroup(v.Key)
	if err := tx.remember("Nodegroup", v.Key.Cluster.Name, v.Key.Name, v.ID, v.Key.Cluster.Name+"/"+v.Key.Name, v.Key.ARN(v.ID), prior); err != nil {
		return err
	}
	return tx.Transaction.PutNodegroup(v)
}
func (tx *cloudFormationTransaction) PutAddon(v Addon) error {
	if !tx.intent.Create || tx.intent.ResourceType != "AWS::EKS::Addon" {
		return tx.Transaction.PutAddon(v)
	}
	_, prior := tx.Addon(v.Key, v.Name)
	if err := tx.remember("Addon", v.Key.Name, v.Name, v.ID, v.Key.Name+"|"+v.Name, v.ARN(), prior); err != nil {
		return err
	}
	return tx.Transaction.PutAddon(v)
}
func (tx *cloudFormationTransaction) PutFargateProfile(v FargateProfile) error {
	if !tx.intent.Create || tx.intent.ResourceType != "AWS::EKS::FargateProfile" {
		return tx.Transaction.PutFargateProfile(v)
	}
	_, prior := tx.FargateProfile(v.Key, v.Name)
	if err := tx.remember("FargateProfile", v.Key.Name, v.Name, v.ID, v.Key.Name+"|"+v.Name, v.ARN(), prior); err != nil {
		return err
	}
	return tx.Transaction.PutFargateProfile(v)
}
func (tx *cloudFormationTransaction) PutAccessEntry(v AccessEntry) error {
	if !tx.intent.Create || tx.intent.ResourceType != "AWS::EKS::AccessEntry" {
		return tx.Transaction.PutAccessEntry(v)
	}
	_, prior := tx.AccessEntry(v.Key, v.PrincipalARN)
	if err := tx.remember("AccessEntry", v.Key.Name, v.PrincipalARN, v.ID, v.PrincipalARN+"|"+v.Key.Name, accessARN(v), prior); err != nil {
		return err
	}
	return tx.Transaction.PutAccessEntry(v)
}
func (tx *cloudFormationTransaction) PutPodIdentityAssociation(v PodIdentityAssociation) error {
	if !tx.intent.Create || tx.intent.ResourceType != "AWS::EKS::PodIdentityAssociation" {
		return tx.Transaction.PutPodIdentityAssociation(v)
	}
	_, prior := tx.PodIdentityAssociation(v.Key, v.ID)
	if err := tx.remember("PodIdentityAssociation", v.Key.Name, v.ID, v.ID, v.ARN(), v.ARN(), prior); err != nil {
		return err
	}
	return tx.Transaction.PutPodIdentityAssociation(v)
}
func (tx *cloudFormationTransaction) finish() error {
	if !tx.intent.Create {
		return nil
	}
	if tx.count != 1 || tx.created.NativeID == "" {
		return cloudFormationMismatch()
	}
	return tx.Transaction.PutCloudFormationCreation(tx.created)
}
