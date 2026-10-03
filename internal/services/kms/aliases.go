package kms

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"stackd/internal/apievents"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

var aliasNamePattern = regexp.MustCompile(`^alias/[a-zA-Z0-9/_-]+$`)

type aliasOwnerContextKey struct{}

// WithAliasOwner constrains trusted in-process alias commands to one owner.
// It does not authorize the caller or change any native KMS request fields.
// HTTP inputs cannot set this constraint; incomplete owners fail closed.
func WithAliasOwner(ctx context.Context, owner AliasOwner) context.Context {
	return context.WithValue(ctx, aliasOwnerContextKey{}, owner)
}

func aliasOwnerFor(ctx context.Context) (AliasOwner, *awswire.Error) {
	owner, present := ctx.Value(aliasOwnerContextKey{}).(AliasOwner)
	if present && (owner.StackID == "" || owner.LogicalID == "" || owner.Token == "") {
		return AliasOwner{}, failure("AccessDeniedException", "The alias owner identity is incomplete.")
	}
	return owner, nil
}

func (s *Service) registerAliases() {
	register(s, "CreateAlias", s.createAlias)
	register(s, "UpdateAlias", s.updateAlias)
	register(s, "DeleteAlias", s.deleteAlias)
	register(s, "ListAliases", s.listAliases)
}

func validateAlias(name string) *awswire.Error {
	if len(name) > 256 || !aliasNamePattern.MatchString(name) {
		return failure("InvalidAliasNameException", "AliasName must start with alias/ and contain only letters, numbers, /, _, and -.")
	}
	if strings.HasPrefix(name, "alias/aws/") {
		return failure("NotAuthorizedException", "The alias/aws/ namespace is reserved for AWS managed aliases.")
	}
	return nil
}

func (s *Service) aliasTarget(ctx context.Context, keyID string) (*key, *awswire.Error) {
	k, err := s.resolveAuthorized(ctx, keyID, false)
	if err != nil {
		return nil, err
	}
	if err := customerKey(k); err != nil {
		return nil, err
	}
	if k.state == "PendingDeletion" || k.state == "PendingReplicaDeletion" {
		return nil, failure("KMSInvalidStateException", "An alias cannot target a key pending deletion.")
	}
	return k, nil
}

func (s *Service) createAlias(ctx context.Context, in *kmsapi.CreateAliasInput) (*kmsapi.CreateAliasOutput, *awswire.Error) {
	name := value(in.AliasName)
	if err := validateAlias(name); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, scopeFor(ctx).arn(name), "", false, nil); err != nil {
		return nil, err
	}
	owner, ownerErr := aliasOwnerFor(ctx)
	if ownerErr != nil {
		return nil, ownerErr
	}
	k, err := s.aliasTarget(ctx, value(in.TargetKeyId))
	if err != nil {
		return nil, err
	}
	st := s.store(ctx)
	if existing := st.aliases[name]; existing != nil {
		if owner != (AliasOwner{}) && existing.owner == owner {
			return &kmsapi.CreateAliasOutput{}, nil
		}
		return nil, failure("AlreadyExistsException", "An alias with this name already exists.")
	}
	now := s.currentTime().UTC()
	st.aliases[name] = &alias{name: name, keyID: k.ID, created: now, updated: now, owner: owner}
	return &kmsapi.CreateAliasOutput{}, nil
}

func (s *Service) updateAlias(ctx context.Context, in *kmsapi.UpdateAliasInput) (*kmsapi.UpdateAliasOutput, *awswire.Error) {
	name := value(in.AliasName)
	if err := validateAlias(name); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, scopeFor(ctx).arn(name), "", false, nil); err != nil {
		return nil, err
	}
	owner, ownerErr := aliasOwnerFor(ctx)
	if ownerErr != nil {
		return nil, ownerErr
	}
	st := s.store(ctx)
	a := st.aliases[name]
	if a == nil {
		return nil, failure("NotFoundException", "Alias does not exist.")
	}
	if owner != (AliasOwner{}) && a.owner != owner {
		return nil, failure("AccessDeniedException", "The alias belongs to a different owner.")
	}
	old, err := s.resolveAuthorized(ctx, a.keyID, false)
	if err != nil {
		return nil, err
	}
	k, err := s.aliasTarget(ctx, value(in.TargetKeyId))
	if err != nil {
		return nil, err
	}
	if old.Spec != k.Spec || old.Usage != k.Usage {
		return nil, failure("ValidationException", "The new target must have the same key type and usage.")
	}
	a.keyID, a.updated = k.ID, s.currentTime().UTC()
	return &kmsapi.UpdateAliasOutput{}, nil
}

func (s *Service) deleteAlias(ctx context.Context, in *kmsapi.DeleteAliasInput) (*kmsapi.DeleteAliasOutput, *awswire.Error) {
	name := value(in.AliasName)
	if err := validateAlias(name); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, scopeFor(ctx).arn(name), "", false, nil); err != nil {
		return nil, err
	}
	owner, ownerErr := aliasOwnerFor(ctx)
	if ownerErr != nil {
		return nil, ownerErr
	}
	st := s.store(ctx)
	a := st.aliases[name]
	if a == nil {
		return nil, failure("NotFoundException", "Alias does not exist.")
	}
	if owner != (AliasOwner{}) && a.owner != owner {
		return nil, failure("AccessDeniedException", "The alias belongs to a different owner.")
	}
	if _, err := s.resolveAuthorized(ctx, a.keyID, false); err != nil {
		return nil, err
	}
	delete(st.aliases, name)
	return &kmsapi.DeleteAliasOutput{}, nil
}

func (s *Service) listAliases(ctx context.Context, in *kmsapi.ListAliasesInput) (*kmsapi.ListAliasesOutput, *awswire.Error) {
	st := s.store(ctx)
	keyID := ""
	if in.KeyId != nil {
		k, err := s.resolve(ctx, value(in.KeyId), false)
		if err != nil {
			return nil, err
		}
		keyID = k.ID
	}
	names := make([]string, 0, len(st.aliases))
	for name, a := range st.aliases {
		if keyID == "" || a.keyID == keyID {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	page, next, err := s.page(ctx, "ListAliases", keyID, names, in.Limit, in.Marker)
	if err != nil {
		return nil, err
	}
	out := &kmsapi.ListAliasesOutput{Aliases: make(kmsapi.AliasList, 0, len(page)), Truncated: ptr(kmsapi.BooleanType(next != ""))}
	if next != "" {
		out.NextMarker = ptr(kmsapi.MarkerType(next))
	}
	for _, name := range page {
		a := st.aliases[name]
		out.Aliases = append(out.Aliases, kmsapi.AliasListEntry{AliasName: ptr(kmsapi.AliasNameType(name)), AliasArn: ptr(kmsapi.ArnType(scopeFor(ctx).arn(name))), TargetKeyId: ptr(kmsapi.KeyIdType(a.keyID)), CreationDate: ptr(a.created), LastUpdatedDate: ptr(a.updated)})
	}
	return out, nil
}

// EnsureServiceKey lazily provisions an AWS managed regional key and its alias.
// Service callers remain responsible for authorizing their use of this key.
func (s *Service) EnsureServiceKey(ctx context.Context, service string) (string, *awswire.Error) {
	input := &kmsapi.CreateKeyInput{
		Description: ptr(kmsapi.DescriptionType("Default key that protects my " + service + " data")),
		KeySpec:     ptr(kmsapi.KeySpec("SYMMETRIC_DEFAULT")), KeyUsage: ptr(kmsapi.KeyUsageType("ENCRYPT_DECRYPT")),
		Origin: ptr(kmsapi.OriginType("AWS_KMS")),
	}
	reject := func(err *awswire.Error) (string, *awswire.Error) {
		if recordErr := s.recordOutcome(ctx, "CreateKey", input, nil, err, nil); recordErr != nil {
			return "", failure("KMSInternalException", "Unable to record KMS API outcome.")
		}
		return "", err
	}
	if service == "" || strings.ContainsAny(service, "/: ") {
		return reject(failure("ValidationException", "Invalid AWS service key name."))
	}
	if scopeFor(ctx).partition == "aws-cn" {
		return reject(failure("UnsupportedOperationException", "SM4 keys for China regions are not implemented."))
	}
	var arn string
	a := &auditContext{}
	ctx = context.WithValue(ctx, auditContextKey{}, a)
	var aliasInput *kmsapi.CreateAliasInput
	attemptContext, outcomes := apievents.RetainChildOutcomes(ctx)
	err := s.transact(attemptContext, func(ctx context.Context) *awswire.Error {
		st := s.store(ctx)
		name := "alias/aws/" + service
		if alias := st.aliases[name]; alias != nil {
			arn = st.keys[alias.keyID].arn
			return nil
		}
		k, err := s.newKey(ctx, value(input.Description), "AWS", KeySetRecord{Spec: "SYMMETRIC_DEFAULT", Usage: "ENCRYPT_DECRYPT", Origin: "AWS_KMS"}, make(map[string]string))
		if err != nil {
			return err
		}
		k.policy = servicePolicy(ctx, service)
		if err := s.recordOutcome(ctx, "CreateKey", input, &kmsapi.CreateKeyOutput{KeyMetadata: metadata(ctx, k)}, nil, a); err != nil {
			return failure("KMSInternalException", "Unable to record KMS API outcome.")
		}
		aliasInput = &kmsapi.CreateAliasInput{AliasName: ptr(kmsapi.AliasNameType(name)), TargetKeyId: ptr(kmsapi.KeyIdType(k.ID))}
		st.aliases[name] = &alias{name: name, keyID: k.ID, created: k.created, updated: k.created}
		arn = k.arn
		if err := s.recordOutcome(ctx, "CreateAlias", aliasInput, &kmsapi.CreateAliasOutput{}, nil, a); err != nil {
			return failure("KMSInternalException", "Unable to record KMS API outcome.")
		}
		return nil
	})
	if err != nil {
		if aliasInput != nil {
			if recordErr := s.recordOutcome(ctx, "CreateAlias", aliasInput, nil, err, a); recordErr != nil {
				return "", failure("KMSInternalException", "Unable to record KMS API outcome.")
			}
		}
		return reject(err)
	}
	outcomes.Accept()
	return arn, nil
}
