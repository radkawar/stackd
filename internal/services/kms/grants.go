package kms

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"stackd/iam/policy"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/iam"
)

type grant struct {
	id, name, grantee, granteeID, retiring, retiringID, issuer string
	created                                                    time.Time
	operations                                                 []string
	tokens                                                     []string
	equals, subset                                             map[string]string
}

func (s *Service) registerGrants() {
	register(s, "CreateGrant", s.createGrant)
	register(s, "ListGrants", s.listGrants)
	register(s, "ListRetirableGrants", s.listRetirableGrants)
	register(s, "RevokeGrant", s.revokeGrant)
	register(s, "RetireGrant", s.retireGrant)
}

func grantConstraints(in *kmsapi.GrantConstraints) (map[string]string, map[string]string, *awswire.Error) {
	if in == nil {
		return nil, nil, nil
	}
	if in.SourceArn != nil {
		return nil, nil, failure("UnsupportedOperationException", "SourceArn grant constraints are not implemented.")
	}
	if in.EncryptionContextEquals != nil && in.EncryptionContextSubset != nil {
		return nil, nil, failure("ValidationException", "Specify only one encryption context grant constraint.")
	}
	for _, pairs := range []kmsapi.EncryptionContextType{in.EncryptionContextEquals, in.EncryptionContextSubset} {
		if pairs == nil {
			continue
		}
		if len(pairs) < 1 || len(pairs) > 8 {
			return nil, nil, failure("ValidationException", "Grant constraints require between 1 and 8 context pairs.")
		}
		for k, v := range pairs {
			if value := string(v); string(k) == "" || utf8.RuneCountInString(value) > 384 {
				return nil, nil, failure("ValidationException", "Grant encryption context is invalid.")
			}
		}
	}
	var equals, subset map[string]string
	if in.EncryptionContextEquals != nil {
		equals = encryptionContext(in.EncryptionContextEquals)
	}
	if in.EncryptionContextSubset != nil {
		subset = encryptionContext(in.EncryptionContextSubset)
	}
	return equals, subset, nil
}

func (s *Service) createGrant(ctx context.Context, in *kmsapi.CreateGrantInput) (*kmsapi.CreateGrantOutput, *awswire.Error) {
	// TODO: Comeback implement the separate service-principal fields and trusted SourceArn constraints; complete grant propagation and quota conformance.
	if in.GranteeServicePrincipal != nil || in.RetiringServicePrincipal != nil {
		return nil, failure("UnsupportedOperationException", "The service-principal grant fields are not implemented.")
	}
	grantee, granteeID, err := s.bindGrantPrincipal(ctx, value(in.GranteePrincipal))
	if err != nil {
		return nil, err
	}
	retiring, retiringID := "", ""
	if in.RetiringPrincipal != nil {
		retiring, retiringID, err = s.bindGrantPrincipal(ctx, value(in.RetiringPrincipal))
		if err != nil {
			return nil, err
		}
	}
	equals, subset, err := grantConstraints(in.Constraints)
	if err != nil {
		return nil, err
	}
	ops := make([]string, 0, len(in.Operations))
	for _, op := range in.Operations {
		ops = append(ops, string(op))
	}
	slices.Sort(ops)
	ops = slices.Compact(ops)
	if len(ops) == 0 {
		return nil, failure("ValidationException", "At least one grant operation is required.")
	}
	g := &grant{name: value(in.Name), grantee: grantee, granteeID: granteeID, retiring: retiring, retiringID: retiringID, issuer: scopeFor(ctx).account, operations: ops, equals: equals, subset: subset}
	ctx = withGrantTokens(ctx, in.GrantTokens)
	action, _ := ctx.Value(actionContextKey{}).(actionContext)
	action.proposedGrant = g
	ctx = context.WithValue(ctx, actionContextKey{}, action)
	awsResourceGrant, _ := ctx.Value(awsResourceGrantContextKey{}).(bool)
	conditions := map[string][]string{"kms:GranteePrincipal": {grantee}, "kms:GrantOperations": ops, "kms:GrantIsForAWSResource": {strconv.FormatBool(awsResourceGrant)}}
	if retiring != "" {
		conditions["kms:RetiringPrincipal"] = []string{retiring}
	}
	if equals != nil {
		conditions["kms:GrantConstraintType"] = []string{"EncryptionContextEquals"}
	}
	if subset != nil {
		conditions["kms:GrantConstraintType"] = []string{"EncryptionContextSubset"}
	}
	k, err := s.resolveAuthorized(withConditions(ctx, conditions), value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	if err := usable(k); err != nil {
		return nil, err
	}
	viaService, _ := ctx.Value(viaServiceContextKey{}).(string)
	scope := scopeFor(ctx)
	ec2Resource := awsResourceGrant && regionalEC2GrantPrincipal(viaService, scope.partition) &&
		(grantee == viaService || iam.IsEC2InfrastructurePrincipal(scope.partition, scope.account, grantee, granteeID))
	ecrResource := awsResourceGrant && regionalECRGrantPrincipal(viaService, scope.partition) && grantee == viaService
	if !ec2Resource && !ecrResource {
		if err := customerKey(k); err != nil {
			return nil, err
		}
	}
	allowed := []string{"CreateGrant", "RetireGrant", "DescribeKey"}
	if k.Spec != "SYMMETRIC_DEFAULT" && in.Constraints != nil {
		return nil, failure("ValidationException", "EncryptionContext is supported only when creating a grant for a symmetric encryption KMS key.")
	}
	if asymmetricSpec(k.Spec) {
		allowed = append(allowed, "GetPublicKey")
	}
	if k.Usage == "GENERATE_VERIFY_MAC" {
		allowed = append(allowed, "GenerateMac", "VerifyMac")
	} else if k.Usage == "SIGN_VERIFY" {
		allowed = append(allowed, "Sign", "Verify")
	} else if k.Usage == "KEY_AGREEMENT" {
		allowed = append(allowed, "DeriveSharedSecret")
	} else {
		allowed = append(allowed, "Encrypt", "Decrypt", "ReEncryptFrom", "ReEncryptTo")
		if k.Spec == "SYMMETRIC_DEFAULT" {
			allowed = append(allowed, "GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext")
		}
	}
	for _, op := range ops {
		if !slices.Contains(allowed, op) {
			family := "a symmetric"
			if asymmetricSpec(k.Spec) {
				family = "an asymmetric"
			}
			return nil, failure("ValidationException", fmt.Sprintf("Operations [%s] are not supported when creating a grant for %s KMS key with key usage %s. Valid operations are [%s]", op, family, k.Usage, strings.Join(allowed, ", ")))
		}
	}
	if isTrue(in.DryRun) {
		return nil, dryRun()
	}
	var token [32]byte
	_, _ = rand.Read(token[:])
	freshToken := base64.RawURLEncoding.EncodeToString([]byte(k.arn + "\n" + hex.EncodeToString(token[:])))
	if g.name != "" {
		for _, old := range k.grants {
			if old.name != g.name {
				continue
			}
			if sameGrantPrincipal(old.grantee, old.granteeID, grantee, granteeID) && sameGrantPrincipal(old.retiring, old.retiringID, retiring, retiringID) && slices.Equal(old.operations, ops) && maps.Equal(old.equals, equals) && maps.Equal(old.subset, subset) {
				old.tokens = append(old.tokens, freshToken)
				return &kmsapi.CreateGrantOutput{GrantId: ptr(kmsapi.GrantIdType(old.id)), GrantToken: ptr(kmsapi.GrantTokenType(freshToken))}, nil
			}
		}
	}
	var id [32]byte
	_, _ = rand.Read(id[:])
	g.id, g.created, g.tokens = hex.EncodeToString(id[:]), s.currentTime().UTC(), []string{freshToken}
	if k.grants == nil {
		k.grants = make(map[string]*grant)
	}
	k.grants[g.id] = g
	return &kmsapi.CreateGrantOutput{GrantId: ptr(kmsapi.GrantIdType(g.id)), GrantToken: ptr(kmsapi.GrantTokenType(freshToken))}, nil
}

func grantPrincipalMatches(ctx context.Context, principal, id string) policy.PrincipalBinding {
	m := awsctx.FromContext(ctx)
	if regionalEC2GrantPrincipal(principal, m.Partition) || regionalECRGrantPrincipal(principal, m.Partition) {
		return policy.PrincipalBinding{Direct: id == "" && principal == m.ServicePrincipal.Name}
	}
	if m.ServicePrincipal.Name != "" {
		return policy.PrincipalBinding{}
	}
	if id != "" {
		caller := id == m.PrincipalID
		return policy.PrincipalBinding{Direct: caller || id == m.IssuerID, SessionDirect: caller && strings.HasPrefix(principal, "arn:"+m.Partition+":sts:")}
	}
	if principal == m.PrincipalARN {
		return policy.PrincipalBinding{Direct: true}
	}
	return policy.PrincipalBinding{Delegated: principal == "arn:"+m.Partition+":iam::"+m.AccountID+":root"}
}

func includesContext(have, want map[string]string) bool {
	for k, v := range want {
		actual, ok := have[k]
		if !ok || actual != v {
			return false
		}
	}
	return true
}

func grantPermits(g *grant, action actionContext) bool {
	if !slices.Contains(g.operations, action.name) {
		return false
	}
	if action.name == "DescribeKey" || action.name == "RetireGrant" {
		return true
	}
	if action.name == "CreateGrant" {
		next := action.proposedGrant
		if next == nil {
			return false
		}
		for _, op := range next.operations {
			if !slices.Contains(g.operations, op) {
				return false
			}
		}
		if g.equals != nil {
			return next.equals != nil && maps.Equal(next.equals, g.equals)
		}
		if g.subset != nil {
			return includesContext(next.equals, g.subset) || includesContext(next.subset, g.subset)
		}
		return true
	}
	return (g.equals == nil || maps.Equal(action.encryptionContext, g.equals)) && includesContext(action.encryptionContext, g.subset)
}
