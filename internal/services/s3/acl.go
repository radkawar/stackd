package s3

import (
	"context"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const allUsers = "http://acs.amazonaws.com/groups/global/AllUsers"
const authenticatedUsers = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
const logDelivery = "http://acs.amazonaws.com/groups/s3/LogDelivery"
const logDeliveryService = "logging.s3.amazonaws.com"

var accountNumber = regexp.MustCompile(`^[0-9]{12}$`)

// DefaultACL initializes ownership for legacy records and trusted internal writes.
func DefaultACL(partition, account string) *AccessControlList {
	id := canonicalID(partition, account)
	return &AccessControlList{OwnerAccountID: account, OwnerID: id, Grants: []ACLGrant{{Type: "CanonicalUser", ID: id, Permission: "FULL_CONTROL"}}}
}

func originalACL(b BucketRecord, acl *AccessControlList) *AccessControlList {
	if acl == nil {
		return DefaultACL(b.Key.Partition, b.AccountID)
	}
	return acl
}

func equalACL(left, right *AccessControlList) bool {
	return left.OwnerID == right.OwnerID && slices.Equal(left.Grants, right.Grants)
}

func effectiveACL(b BucketRecord, acl *AccessControlList, ignorePublic bool) *AccessControlList {
	if b.Ownership == "BucketOwnerEnforced" {
		return DefaultACL(b.Key.Partition, b.AccountID)
	}
	acl = originalACL(b, acl)
	if !ignorePublic {
		return acl
	}
	out := &AccessControlList{OwnerAccountID: acl.OwnerAccountID, OwnerID: acl.OwnerID}
	for _, grant := range acl.Grants {
		if !publicGrant(grant) {
			out.Grants = append(out.Grants, grant)
		}
	}
	return out
}

func aclOutput(acl *AccessControlList) (*api.Owner, api.Grants) {
	grants := make(api.Grants, 0, len(acl.Grants))
	for _, g := range acl.Grants {
		grantee := &api.Grantee{Type: new(api.Type(g.Type))}
		if g.ID != "" {
			grantee.ID = new(api.ID(g.ID))
		}
		if g.URI != "" {
			grantee.URI = new(api.URI(g.URI))
		}
		grants = append(grants, api.Grant{Grantee: grantee, Permission: new(api.Permission(g.Permission))})
	}
	return &api.Owner{ID: new(api.ID(acl.OwnerID))}, grants
}

func objectOwner(b BucketRecord, record ObjectRecord) *api.Owner {
	id := canonicalID(b.Key.Partition, b.AccountID)
	if b.Ownership != "BucketOwnerEnforced" && record.ACL != nil {
		id = record.ACL.OwnerID
	}
	return &api.Owner{ID: new(api.ID(id))}
}

func publicGrant(g ACLGrant) bool {
	return g.Type == "Group" && (g.URI == allUsers || g.URI == authenticatedUsers)
}
func publicACL(acl *AccessControlList) bool {
	for _, g := range acl.Grants {
		if publicGrant(g) {
			return true
		}
	}
	return false
}
func ownerFullControlOnly(acl *AccessControlList, id string) bool {
	return len(acl.Grants) == 1 && acl.Grants[0] == (ACLGrant{Type: "CanonicalUser", ID: id, Permission: "FULL_CONTROL"})
}
func aclDisabled() *awswire.Error {
	return failure("AccessControlListNotSupported", "The bucket does not allow ACLs", 400)
}
func malformedACL() *awswire.Error {
	return failure("MalformedACLError", "The XML you provided was not well-formed or did not validate against our published schema", 400)
}
func emailACL() *awswire.Error {
	wire := failure("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)
	wire.Method, wire.ResourceType = "PUT", "ACL"
	return wire
}

type aclHeaders struct{ full, read, readACP, write, writeACP string }

func (h aclHeaders) supplied() bool {
	return h.full != "" || h.read != "" || h.readACP != "" || h.write != "" || h.writeACP != ""
}

func validateGrant(g ACLGrant) *awswire.Error {
	switch g.Permission {
	case "FULL_CONTROL", "READ", "WRITE", "READ_ACP", "WRITE_ACP":
	default:
		return malformedACL()
	}
	switch g.Type {
	case "CanonicalUser":
		var decoded [32]byte
		if len(g.ID) != 64 {
			return argumentError("CanonicalUser/ID", g.ID, "Invalid id")
		}
		if _, err := hex.Decode(decoded[:], []byte(g.ID)); err != nil {
			return argumentError("CanonicalUser/ID", g.ID, "Invalid id")
		}
	case "Group":
		if g.URI != allUsers && g.URI != authenticatedUsers && g.URI != logDelivery {
			return argumentError("Group/URI", g.URI, "Invalid group uri")
		}
	case "AmazonCustomerByEmail":
		return emailACL()
	default:
		return malformedACL()
	}
	return nil
}

func parseACL(b BucketRecord, original *AccessControlList, canned string, headers aclHeaders, policy *api.AccessControlPolicy, required bool) (*AccessControlList, *awswire.Error) {
	if canned != "" && headers.supplied() {
		return nil, failure("InvalidRequest", "Specifying both Canned ACLs and Header Grants is not allowed", 400)
	}
	if policy != nil && (canned != "" || headers.supplied()) {
		return nil, failure("UnexpectedContent", "This request does not support content", 400)
	}
	out := &AccessControlList{OwnerAccountID: original.OwnerAccountID, OwnerID: original.OwnerID}
	if policy != nil {
		if policy.Owner == nil || value(policy.Owner.ID) == "" {
			return nil, malformedACL()
		}
		if value(policy.Owner.ID) != original.OwnerID {
			return nil, argumentError("CanonicalUser/ID", value(policy.Owner.ID), "Invalid id")
		}
		for _, grant := range policy.Grants {
			if grant.Grantee == nil {
				return nil, malformedACL()
			}
			g := ACLGrant{Type: value(grant.Grantee.Type), ID: value(grant.Grantee.ID), URI: value(grant.Grantee.URI), Permission: value(grant.Permission)}
			if wire := validateGrant(g); wire != nil {
				return nil, wire
			}
			out.Grants = append(out.Grants, g)
		}
		return out, nil
	}
	if headers.supplied() {
		for _, header := range []struct{ permission, name, text string }{{"FULL_CONTROL", "x-amz-grant-full-control", headers.full}, {"READ", "x-amz-grant-read", headers.read}, {"READ_ACP", "x-amz-grant-read-acp", headers.readACP}, {"WRITE", "x-amz-grant-write", headers.write}, {"WRITE_ACP", "x-amz-grant-write-acp", headers.writeACP}} {
			if header.text == "" {
				continue
			}
			for _, part := range strings.Split(header.text, ",") {
				name, text, found := strings.Cut(strings.TrimSpace(part), "=")
				name, text = strings.TrimSpace(name), strings.TrimSpace(text)
				if !found || len(text) < 2 || text[0] != '"' || text[len(text)-1] != '"' || strings.Contains(text[1:len(text)-1], "\"") {
					return nil, argumentError(header.name, header.text, "Argument format not recognized")
				}
				text = text[1 : len(text)-1]
				g := ACLGrant{Permission: header.permission}
				switch name {
				case "id":
					g.Type, g.ID = "CanonicalUser", text
				case "uri":
					g.Type, g.URI = "Group", text
				case "emailAddress":
					return nil, emailACL()
				default:
					return nil, argumentError(header.name, header.text, "Argument format not recognized")
				}
				if wire := validateGrant(g); wire != nil {
					return nil, wire
				}
				out.Grants = append(out.Grants, g)
			}
		}
		return out, nil
	}
	if canned == "" && required {
		wire := failure("MissingSecurityHeader", "Your request was missing a required header", 400)
		wire.MissingHeaderName = "x-amz-acl"
		return nil, wire
	}
	out.Grants = []ACLGrant{{Type: "CanonicalUser", ID: out.OwnerID, Permission: "FULL_CONTROL"}}
	group := func(uri, permission string) {
		out.Grants = append(out.Grants, ACLGrant{Type: "Group", URI: uri, Permission: permission})
	}
	switch canned {
	case "", "private":
	case "public-read":
		group(allUsers, "READ")
	case "public-read-write":
		group(allUsers, "READ")
		group(allUsers, "WRITE")
	case "authenticated-read":
		group(authenticatedUsers, "READ")
	case "log-delivery-write":
		group(logDelivery, "WRITE")
		group(logDelivery, "READ_ACP")
	case "bucket-owner-read", "bucket-owner-full-control":
		bucketID := canonicalID(b.Key.Partition, b.AccountID)
		if bucketID != out.OwnerID {
			permission := "READ"
			if canned == "bucket-owner-full-control" {
				permission = "FULL_CONTROL"
			}
			out.Grants = append(out.Grants, ACLGrant{Type: "CanonicalUser", ID: bucketID, Permission: permission})
		}
	default:
		return nil, argumentError("x-amz-acl", canned, "")
	}
	return out, nil
}

func (s *Service) objectCreationACL(ctx context.Context, c *apiCall, b BucketRecord, key, canned string, headers aclHeaders, conditions map[string][]string) (*AccessControlList, *awswire.Error) {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for _, header := range []struct{ name, text string }{{"full-control", headers.full}, {"read", headers.read}, {"read-acp", headers.readACP}, {"write", headers.write}, {"write-acp", headers.writeACP}} {
		if header.text != "" {
			conditions["s3:x-amz-grant-"+header.name] = []string{header.text}
		}
	}
	if wire := s.objectWrite(ctx, c, b, key, canned, conditions); wire != nil {
		return nil, wire
	}
	account := awsctx.FromContext(ctx).AccountID
	// Service producers have no canonical IAM identity and create bucket-owned data.
	if account == "" || awsctx.FromContext(ctx).ServicePrincipal.Name != "" {
		account = b.AccountID
	}
	acl, wire := parseACL(b, DefaultACL(b.Key.Partition, account), canned, headers, nil, false)
	if wire != nil {
		return nil, wire
	}
	bucketID := canonicalID(b.Key.Partition, b.AccountID)
	if b.Ownership == "BucketOwnerEnforced" {
		allowed := canned == "" && !headers.supplied()
		if account == b.AccountID {
			allowed = ownerFullControlOnly(acl, bucketID)
		} else if !allowed {
			allowed = true
			ownerGrant := false
			seen := map[string]bool{}
			for _, g := range acl.Grants {
				if g.Type != "CanonicalUser" || g.Permission != "FULL_CONTROL" || (g.ID != bucketID && g.ID != acl.OwnerID) || seen[g.ID] {
					allowed = false
					break
				}
				seen[g.ID] = true
				ownerGrant = ownerGrant || g.ID == bucketID
			}
			allowed = allowed && ownerGrant
		}
		if !allowed {
			return nil, aclDisabled()
		}
		return DefaultACL(b.Key.Partition, b.AccountID), nil
	}
	if c.publicAccess.BlockPublicACLs && publicACL(acl) {
		return nil, denied()
	}
	if headers.supplied() || (canned != "" && canned != "private" && canned != "bucket-owner-full-control") {
		if wire := s.authorize(ctx, c, b, "PutObjectAcl", key, conditions); wire != nil {
			return nil, wire
		}
	}
	if b.Ownership == "BucketOwnerPreferred" && canned == "bucket-owner-full-control" {
		return DefaultACL(b.Key.Partition, b.AccountID), nil
	}
	return acl, nil
}

func (s *Service) accessLogObjectACL(ctx context.Context, c *apiCall, b BucketRecord, key string, grants []ACLGrant, conditions map[string][]string) (*AccessControlList, *awswire.Error) {
	if wire := s.objectWrite(ctx, c, b, key, "", conditions); wire != nil {
		return nil, wire
	}
	if b.Ownership == "BucketOwnerEnforced" {
		if len(grants) != 0 {
			return nil, aclDisabled()
		}
		return DefaultACL(b.Key.Partition, b.AccountID), nil
	}
	// Legacy access logs belong to the S3 log-delivery account. Its opaque
	// service owner token is not an AWS account number; keeping it distinct
	// from the bucket account preserves foreign-object ACL authorization.
	owner := canonicalID(b.Key.Partition, logDeliveryService)
	acl := &AccessControlList{OwnerAccountID: logDeliveryService, OwnerID: owner, Grants: make([]ACLGrant, 0, 2+len(grants))}
	acl.Grants = append(acl.Grants,
		ACLGrant{Type: "CanonicalUser", ID: owner, Permission: "FULL_CONTROL"},
		ACLGrant{Type: "CanonicalUser", ID: canonicalID(b.Key.Partition, b.AccountID), Permission: "FULL_CONTROL"})
	acl.Grants = append(acl.Grants, grants...)
	if c.publicAccess.BlockPublicACLs && publicACL(acl) {
		return nil, denied()
	}
	return acl, nil
}

// ACL permissions map to S3 actions, not arbitrary object operations.
func aclPermission(action string, bucket bool) string {
	if bucket {
		switch action {
		case "ListBucket", "ListBucketVersions", "ListBucketMultipartUploads":
			return "READ"
		case "PutObject", "DeleteObject":
			return "WRITE"
		case "GetBucketAcl":
			return "READ_ACP"
		case "PutBucketAcl":
			return "WRITE_ACP"
		}
	} else {
		switch action {
		case "GetObject", "GetObjectVersion", "GetObjectAttributes", "GetObjectVersionAttributes":
			return "READ"
		case "GetObjectAcl", "GetObjectVersionAcl":
			return "READ_ACP"
		case "PutObjectAcl", "PutObjectVersionAcl":
			return "WRITE_ACP"
		}
	}
	return ""
}

func aclGrants(ctx context.Context, b BucketRecord, acl *AccessControlList, permission string, object bool) (bool, bool) {
	if permission == "" {
		return false, false
	}
	m := awsctx.FromContext(ctx)
	if m.ServicePrincipal.Name == logDeliveryService && !object {
		// ACL-based delivery needs both grants. A bucket-policy permission is
		// independent and is still evaluated, including explicit denials.
		write, readACP := false, false
		for _, grant := range acl.Grants {
			if grant.Type != "Group" || grant.URI != logDelivery {
				continue
			}
			write = write || grant.Permission == "WRITE" || grant.Permission == "FULL_CONTROL"
			readACP = readACP || grant.Permission == "READ_ACP" || grant.Permission == "FULL_CONTROL"
		}
		// The direct ACL result grants this verified service group membership,
		// not public access; resource-policy explicit denials still win.
		switch permission {
		case "WRITE":
			return false, write && readACP
		case "READ_ACP":
			return false, readACP
		default:
			return false, false
		}
	}
	accountID := ""
	if m.ServicePrincipal.Name == logDeliveryService {
		accountID = canonicalID(b.Key.Partition, logDeliveryService)
	} else if m.AccountID != "" && (m.PrincipalARN != "" || m.ServicePrincipal.Name != "") {
		accountID = canonicalID(b.Key.Partition, m.AccountID)
	}
	account, public := false, false
	// Object owners retain ACP access even when their ACL omits owner grants.
	if object && (permission == "READ_ACP" || permission == "WRITE_ACP") && accountID == acl.OwnerID {
		account = true
	}
	for _, grant := range acl.Grants {
		if grant.Permission != permission && grant.Permission != "FULL_CONTROL" {
			continue
		}
		if grant.Type == "CanonicalUser" && accountID != "" && grant.ID == accountID {
			account = true
		}
		if grant.Type == "Group" && (grant.URI == allUsers || (grant.URI == authenticatedUsers && accountID != "")) {
			public = true
		}
	}
	if m.ServicePrincipal.Name == logDeliveryService {
		// A service's ACL grant is direct, not delegated to its source account.
		// The direct/group-grant path retains resource-policy deny precedence.
		return false, account || public
	}
	return account, public
}
