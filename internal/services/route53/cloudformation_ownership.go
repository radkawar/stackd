package route53

import "context"

type cfnOwnershipKey struct{}
type cfnOwnership struct {
	claim   string
	enforce bool
	rows    map[string]string
}

// WithCloudFormationOwnership binds ChangeResourceRecordSets to one internal
// CloudFormation incarnation claim. CREATE and UPSERT stamp the claim; CREATE of
// a record already stamped with the same claim converges it (recovery) and never
// adopts another record. Enforced bindings reject UPSERT and DELETE of records
// stamped with another claim; DELETE then matches by record identity only.
// rows receives retained claims observed by authorized ListResourceRecordSets.
// The claim is internal metadata and never appears in the public API.
func WithCloudFormationOwnership(ctx context.Context, claim string, enforce bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cfnOwnershipKey{}, &cfnOwnership{claim, enforce, rows})
}

// CloudFormationRecordKey names a record set in observed ownership rows. Name is
// the canonical lower-case, dot-terminated owner name.
func CloudFormationRecordKey(name, kind, identifier string) string {
	return recordKey(RecordSet{Name: name, Type: kind, Identifier: identifier})
}

func cloudFormationOwnership(ctx context.Context) *cfnOwnership {
	v, _ := ctx.Value(cfnOwnershipKey{}).(*cfnOwnership)
	if v == nil || v.claim == "" && v.rows == nil {
		return nil
	}
	return v
}

func (b *cfnOwnership) observe(z Zone) {
	if b == nil || b.rows == nil {
		return
	}
	for _, r := range z.Records {
		b.rows[recordKey(r)] = r.Owner
	}
}
