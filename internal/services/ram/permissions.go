package ram

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"stackd/iam/policy"
	api "stackd/internal/awsapi/ram"
	"strconv"
	"strings"
	"time"
)

// managedPermissionData is an exact native ListPermissions/GetPermission capture.
//
//go:embed managed_permissions.json
var managedPermissionData []byte

func managedPermissions() []Permission {
	var rows []struct {
		ARN          string    `json:"arn"`
		Name         string    `json:"name"`
		ResourceType string    `json:"resourceType"`
		Version      string    `json:"version"`
		Document     string    `json:"permission"`
		Created      time.Time `json:"creationTime"`
		Updated      time.Time `json:"lastUpdatedTime"`
		Default      bool      `json:"isResourceTypeDefault"`
	}
	if json.Unmarshal(managedPermissionData, &rows) != nil {
		return nil
	}
	out := make([]Permission, 0, len(rows))
	for _, r := range rows {
		v, e := strconv.ParseInt(r.Version, 10, 32)
		if e != nil {
			continue
		}
		_, actions, e := parseTemplate(r.Document, nil)
		if e != nil {
			continue
		}
		out = append(out, Permission{ARN: r.ARN, Name: r.Name, ResourceType: r.ResourceType, Type: "AWS_MANAGED", FeatureSet: "STANDARD", Status: "ATTACHABLE", DefaultVersion: int32(v), ResourceTypeDefault: r.Default, Created: r.Created, Updated: r.Updated, Versions: []PermissionVersion{{Version: int32(v), Document: r.Document, Actions: actions, Created: r.Created, Updated: r.Updated}}})
	}
	return out
}
func (s *Service) permission(r Reader, arn string) (Permission, error) {
	sc := scopeFor(r.Context())
	for _, p := range s.managed {
		if strings.Replace(p.ARN, "arn:aws:", "arn:"+sc.Partition+":", 1) == arn {
			p.ARN = arn
			p.Partition = sc.Partition
			return p, nil
		}
	}
	p, e := r.Permission(arn)
	if e != nil {
		return p, e
	}
	if p.Scope != sc {
		return Permission{}, ErrNotFound
	}
	return p, nil
}
func (s *Service) defaultPermission(r Reader, kind string) (Permission, error) {
	for _, p := range s.managed {
		if p.ResourceType == kind && p.ResourceTypeDefault {
			return s.permission(r, strings.Replace(p.ARN, "arn:aws:", "arn:"+scopeFor(r.Context()).Partition+":", 1))
		}
	}
	return Permission{}, ErrUnsupportedResource
}
func versionOf(p Permission, v int32) (PermissionVersion, error) {
	if v == 0 {
		v = p.DefaultVersion
	}
	for _, pv := range p.Versions {
		if pv.Version == v {
			return pv, nil
		}
	}
	return PermissionVersion{}, ErrNotFound
}
func permissionSummary(p Permission, v int32, operation string) *api.ResourceSharePermissionSummary {
	pv, _ := versionOf(p, v)
	status := p.Status
	if pv.Deleted {
		status = "DELETED"
	}
	if status != "DELETED" {
		status = "UNATTACHABLE"
		if pv.Version == p.DefaultVersion {
			status = "ATTACHABLE"
		}
	}
	updated := pv.Updated
	if p.Status == "DELETED" {
		updated = p.Updated
	}
	out := &api.ResourceSharePermissionSummary{Arn: new(api.String(p.ARN)), Name: new(api.String(p.Name)), ResourceType: new(api.String(p.ResourceType)), Version: new(api.String(strconv.Itoa(int(pv.Version)))), DefaultVersion: new(api.Boolean(pv.Version == p.DefaultVersion)), IsResourceTypeDefault: new(api.Boolean(p.ResourceTypeDefault)), Status: new(api.String(status)), CreationTime: &pv.Created, LastUpdatedTime: &updated}
	// Native creation responses omit the read/list metadata. Only permission
	// creation, not version creation, returns the permission's tags.
	if operation != "CreatePermission" && operation != "CreatePermissionVersion" {
		out.PermissionType = new(api.PermissionType(p.Type))
		out.FeatureSet = new(api.PermissionFeatureSet(p.FeatureSet))
	}
	if operation != "CreatePermissionVersion" && len(p.Tags) != 0 {
		out.Tags = apiTags(p.Tags)
	}
	return out
}
func permissionDetail(p Permission, v int32, operation string) (*api.ResourceSharePermissionDetail, error) {
	pv, e := versionOf(p, v)
	if e != nil {
		return nil, e
	}
	a := permissionSummary(p, v, operation)
	return &api.ResourceSharePermissionDetail{Arn: a.Arn, Name: a.Name, ResourceType: a.ResourceType, Version: a.Version, DefaultVersion: a.DefaultVersion, IsResourceTypeDefault: a.IsResourceTypeDefault, PermissionType: a.PermissionType, FeatureSet: a.FeatureSet, Status: new(api.PermissionStatus(value(a.Status))), CreationTime: a.CreationTime, LastUpdatedTime: a.LastUpdatedTime, Tags: a.Tags, Permission: new(api.String(pv.Document))}, nil
}
func (s *Service) getPermission(tx Transaction, in *api.GetPermissionRequest) (*api.GetPermissionResponse, error) {
	if e := s.authorize(tx, "GetPermission", value(in.PermissionArn), nil); e != nil {
		return nil, e
	}
	p, e := s.permission(tx, value(in.PermissionArn))
	if e != nil {
		return nil, e
	}
	var v int32
	if in.PermissionVersion != nil {
		v = int32(*in.PermissionVersion)
	}
	out, e := permissionDetail(p, v, "GetPermission")
	return &api.GetPermissionResponse{Permission: out}, e
}

// templateStatements supports native single statements and multi-statement templates.
func templateStatements(raw string) ([]map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if e := json.Unmarshal([]byte(raw), &obj); e != nil {
		return nil, e
	}
	if st, ok := obj["Statement"]; ok {
		for k := range obj {
			if k != "Statement" && k != "Version" {
				return nil, fmt.Errorf("invalid template field %s", k)
			}
		}
		var rows []map[string]json.RawMessage
		if len(st) > 0 && st[0] == '[' {
			if e := json.Unmarshal(st, &rows); e != nil {
				return nil, e
			}
		} else {
			var row map[string]json.RawMessage
			if e := json.Unmarshal(st, &row); e != nil {
				return nil, e
			}
			rows = append(rows, row)
		}
		return rows, nil
	}
	return []map[string]json.RawMessage{obj}, nil
}
func parseTemplate(raw string, allowed []string) (string, []string, error) {
	rows, e := templateStatements(raw)
	if e != nil || len(rows) == 0 {
		return "", nil, failure("MalformedPolicyTemplateException", "The permission template is invalid JSON.")
	}
	all := []string{}
	for _, row := range rows {
		for k := range row {
			if k != "Effect" && k != "Action" && k != "Condition" && k != "Sid" {
				return "", nil, failure("InvalidPolicyException", "Permission templates cannot contain Principal, Resource, or unsupported elements.")
			}
		}
		var effect string
		_ = json.Unmarshal(row["Effect"], &effect)
		if effect != "Allow" {
			return "", nil, failure("InvalidPolicyException", "Only Allow statements are permitted.")
		}
		var actions []string
		if e = json.Unmarshal(row["Action"], &actions); e != nil {
			var a string
			if e = json.Unmarshal(row["Action"], &a); e != nil {
				return "", nil, failure("InvalidPolicyException", "A statement requires actions.")
			}
			actions = []string{a}
		}
		if len(actions) == 0 {
			return "", nil, failure("InvalidPolicyException", "A statement requires actions.")
		}
		for _, a := range actions {
			if allowed != nil && !actionAllowed(allowed, a) {
				return "", nil, failure("InvalidPolicyException", "Action is not supported by the resource type: "+a)
			}
			all = append(all, a)
		}
		row["Resource"] = json.RawMessage(`"*"`)
	}
	doc, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": rows})
	if _, e = policy.Parse(doc); e != nil {
		return "", nil, failure("InvalidPolicyException", e.Error())
	}
	slices.Sort(all)
	return raw, slices.Compact(all), nil
}
func (s *Service) customerTemplate(kind, raw string) (string, []string, error) {
	if !slices.Contains(s.resourceTypes, kind) {
		return "", nil, ErrUnsupportedResource
	}
	if kind == "ec2:Subnet" {
		return "", nil, failure("OperationNotPermittedException", "Subnets do not support customer managed permissions.")
	}
	actions := []string{}
	for _, p := range s.managed {
		if p.ResourceType == kind {
			for _, v := range p.Versions {
				actions = append(actions, v.Actions...)
			}
		}
	}
	return parseTemplate(raw, actions)
}

var permissionNamePattern = regexp.MustCompile(`^[\w.-]{1,36}$`)

func (s *Service) createPermission(tx Transaction, in *api.CreatePermissionRequest) (*api.CreatePermissionResponse, error) {
	if e := s.authorize(tx, "CreatePermission", "", nil); e != nil {
		return nil, e
	}
	rec, replay, e := receipt(tx, "CreatePermission", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if replay {
		p, e := tx.Permission(rec.ARN)
		if e != nil {
			return nil, e
		}
		return &api.CreatePermissionResponse{ClientToken: in.ClientToken, Permission: permissionSummary(p, rec.Version, "CreatePermission")}, nil
	}
	name := value(in.Name)
	if !permissionNamePattern.MatchString(name) {
		return nil, failure("InvalidParameterException", "Invalid permission name.")
	}
	sc := scopeFor(tx.Context())
	arn := arnFor(sc, "permission", name)
	old, e := tx.Permission(arn)
	if e == nil && old.Status != "DELETED" {
		return nil, failure("PermissionAlreadyExistsException", "The permission name already exists.")
	}
	if e != nil && !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	doc, actions, e := s.customerTemplate(value(in.ResourceType), value(in.PolicyTemplate))
	if e != nil {
		return nil, e
	}
	tags, e := readTags(in.Tags)
	if e != nil {
		return nil, e
	}
	now := s.clock.Now()
	p := Permission{Scope: sc, ARN: arn, Name: name, ResourceType: value(in.ResourceType), Type: "CUSTOMER_MANAGED", FeatureSet: "STANDARD", Status: "ATTACHABLE", DefaultVersion: 1, Created: now, Updated: now, Tags: tags, Versions: []PermissionVersion{{Version: 1, Document: doc, Actions: actions, Created: now, Updated: now}}}
	if e = tx.PutPermission(p); e != nil {
		return nil, e
	}
	rec.ARN = arn
	rec.Version = 1
	if e = saveReceipt(tx, rec); e != nil {
		return nil, e
	}
	return &api.CreatePermissionResponse{ClientToken: in.ClientToken, Permission: permissionSummary(p, 1, "CreatePermission")}, nil
}
func (s *Service) mutablePermission(tx Transaction, arn, op string) (Permission, error) {
	p, e := s.permission(tx, arn)
	if e != nil {
		return p, e
	}
	if e = s.authorize(tx, op, arn, p.Tags); e != nil {
		return p, e
	}
	if p.Type != "CUSTOMER_MANAGED" || p.FeatureSet != "STANDARD" || p.Status == "DELETED" {
		return p, failure("OperationNotPermittedException", "The permission cannot be modified.")
	}
	return p, nil
}
func (s *Service) createPermissionVersion(tx Transaction, in *api.CreatePermissionVersionRequest) (*api.CreatePermissionVersionResponse, error) {
	p, e := s.mutablePermission(tx, value(in.PermissionArn), "CreatePermissionVersion")
	if e != nil {
		return nil, e
	}
	rec, replay, e := receipt(tx, "CreatePermissionVersion", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if replay {
		out, e := permissionDetail(p, rec.Version, "CreatePermissionVersion")
		if e == nil {
			// Native creation receipts resolve the current numbered version but
			// expose its creation timestamp even after that version is deleted.
			out.LastUpdatedTime = out.CreationTime
		}
		return &api.CreatePermissionVersionResponse{ClientToken: in.ClientToken, Permission: out}, e
	}
	var version int32
	active := 0
	for _, v := range p.Versions {
		if !v.Deleted {
			active++
			version = max(version, v.Version)
		}
	}
	if active >= 5 {
		return nil, failure("PermissionVersionsLimitExceededException", "A customer managed permission supports at most five versions.")
	}
	doc, actions, e := s.customerTemplate(p.ResourceType, value(in.PolicyTemplate))
	if e != nil {
		return nil, e
	}
	for _, v := range p.Versions {
		if !v.Deleted && equalTemplate(v.Document, doc) {
			return nil, failure("InvalidParameterException", "Existing permission version: "+strconv.Itoa(int(v.Version))+" has same policy")
		}
	}
	version++
	now := s.clock.Now()
	for i := range p.Versions {
		if p.Versions[i].Version == p.DefaultVersion {
			p.Versions[i].Updated = now
		}
	}
	// AWS reuses the deleted highest version number. Its tombstone remains
	// readable until a new version replaces that same numbered identity.
	pv := PermissionVersion{Version: version, Document: doc, Actions: actions, Created: now, Updated: now}
	if i := slices.IndexFunc(p.Versions, func(v PermissionVersion) bool { return v.Version == version }); i >= 0 {
		p.Versions[i] = pv
	} else {
		p.Versions = append(p.Versions, pv)
	}
	p.DefaultVersion = version
	p.Updated = now
	if e = tx.PutPermission(p); e != nil {
		return nil, e
	}
	rec.ARN = p.ARN
	rec.Version = version
	if e = saveReceipt(tx, rec); e != nil {
		return nil, e
	}
	out, e := permissionDetail(p, version, "CreatePermissionVersion")
	return &api.CreatePermissionVersionResponse{ClientToken: in.ClientToken, Permission: out}, e
}
func (s *Service) setDefaultPermissionVersion(tx Transaction, in *api.SetDefaultPermissionVersionRequest) (*api.SetDefaultPermissionVersionResponse, error) {
	p, e := s.mutablePermission(tx, value(in.PermissionArn), "SetDefaultPermissionVersion")
	if e != nil {
		return nil, e
	}
	if in.PermissionVersion == nil {
		return nil, failure("InvalidParameterException", "PermissionVersion is required.")
	}
	v, e := versionOf(p, int32(*in.PermissionVersion))
	if e != nil {
		return nil, e
	}
	if v.Deleted {
		return nil, failure("OperationNotPermittedException", "A deleted permission version cannot be the default.")
	}
	rec, replay, e := receipt(tx, "SetDefaultPermissionVersion", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if !replay {
		now := s.clock.Now()
		for i := range p.Versions {
			if p.Versions[i].Version == p.DefaultVersion || p.Versions[i].Version == v.Version {
				p.Versions[i].Updated = now
			}
		}
		p.DefaultVersion = v.Version
		p.Updated = now
		if e = tx.PutPermission(p); e != nil {
			return nil, e
		}
		if e = saveReceipt(tx, rec); e != nil {
			return nil, e
		}
	}
	return &api.SetDefaultPermissionVersionResponse{ClientToken: in.ClientToken, ReturnValue: new(api.Boolean(true))}, nil
}
func permissionUsed(r Reader, arn string, version int32) (bool, error) {
	shares, e := r.Shares()
	if e != nil {
		return false, e
	}
	for _, sh := range shares {
		if sh.Status != "ACTIVE" {
			continue
		}
		for _, a := range sh.Permissions {
			if a.ARN == arn && (version == 0 || a.Version == version) {
				return true, nil
			}
		}
	}
	return false, nil
}
func (s *Service) deletePermission(tx Transaction, in *api.DeletePermissionRequest) (*api.DeletePermissionResponse, error) {
	rec, replay, e := receipt(tx, "DeletePermission", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	p, e := s.permission(tx, value(in.PermissionArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "DeletePermission", p.ARN, p.Tags); e != nil {
		return nil, e
	}
	if !replay {
		if p.Type != "CUSTOMER_MANAGED" || p.FeatureSet != "STANDARD" {
			return nil, failure("OperationNotPermittedException", "AWS managed or policy-created permissions cannot be deleted.")
		}
		used, e := permissionUsed(tx, p.ARN, 0)
		if e != nil {
			return nil, e
		}
		if used {
			return nil, failure("OperationNotPermittedException", "The permission is still associated with resource shares.")
		}
		p.Status = "DELETED"
		p.Updated = s.clock.Now()
		if e = tx.PutPermission(p); e != nil {
			return nil, e
		}
		if e = saveReceipt(tx, rec); e != nil {
			return nil, e
		}
	}
	return &api.DeletePermissionResponse{ClientToken: in.ClientToken, ReturnValue: new(api.Boolean(true)), PermissionStatus: new(api.PermissionStatusDELETING)}, nil
}
func (s *Service) deletePermissionVersion(tx Transaction, in *api.DeletePermissionVersionRequest) (*api.DeletePermissionVersionResponse, error) {
	p, e := s.mutablePermission(tx, value(in.PermissionArn), "DeletePermissionVersion")
	if e != nil {
		return nil, e
	}
	rec, replay, e := receipt(tx, "DeletePermissionVersion", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if !replay {
		if in.PermissionVersion == nil || *in.PermissionVersion <= 0 {
			return nil, failure("InvalidParameterException", "A positive PermissionVersion is required.")
		}
		v := int32(*in.PermissionVersion)
		if v == p.DefaultVersion {
			return nil, failure("OperationNotPermittedException", "The default version cannot be deleted.")
		}
		if _, e = versionOf(p, v); e != nil {
			return nil, e
		}
		used, e := permissionUsed(tx, p.ARN, v)
		if e != nil {
			return nil, e
		}
		if used {
			return nil, failure("OperationNotPermittedException", "The permission version is associated with a resource share.")
		}
		now := s.clock.Now()
		for i := range p.Versions {
			if p.Versions[i].Version == v {
				p.Versions[i].Deleted = true
				p.Versions[i].Updated = now
			}
		}
		p.Updated = now
		if e = tx.PutPermission(p); e != nil {
			return nil, e
		}
		if e = saveReceipt(tx, rec); e != nil {
			return nil, e
		}
	}
	return &api.DeletePermissionVersionResponse{ClientToken: in.ClientToken, ReturnValue: new(api.Boolean(true)), PermissionStatus: new(api.PermissionStatusDELETING)}, nil
}
func (s *Service) associateResourceSharePermission(tx Transaction, in *api.AssociateResourceSharePermissionRequest) (*api.AssociateResourceSharePermissionResponse, error) {
	v, e := s.ownedShare(tx, value(in.ResourceShareArn), "AssociateResourceSharePermission", true)
	if e != nil {
		return nil, e
	}
	p, e := s.permission(tx, value(in.PermissionArn))
	if e != nil {
		return nil, e
	}
	if p.Status == "DELETED" || p.FeatureSet != "STANDARD" {
		return nil, failure("InvalidParameterException", "The permission is not attachable.")
	}
	if in.PermissionVersion != nil && int32(*in.PermissionVersion) != p.DefaultVersion {
		return nil, failure("InvalidParameterException", "Only the default permission version can be associated.")
	}
	rec, replay, e := receipt(tx, "AssociateResourceSharePermission", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if !replay {
		idx := slices.IndexFunc(v.Permissions, func(a PermissionAssociation) bool { return a.ResourceType == p.ResourceType })
		if idx >= 0 && (in.Replace == nil || !bool(*in.Replace)) {
			return nil, failure("OperationNotPermittedException", "A permission already exists for this resource type; specify replace.")
		}
		for _, r := range v.Resources {
			if r.Status == "ASSOCIATED" && r.ResourceType == p.ResourceType {
				if e = s.authorizeResource(tx, r.ARN); e != nil {
					return nil, e
				}
			}
		}
		a := PermissionAssociation{p.ARN, p.ResourceType, p.DefaultVersion}
		if idx >= 0 {
			v.Permissions[idx] = a
		} else {
			v.Permissions = append(v.Permissions, a)
		}
		v.Updated = s.clock.Now()
		if e = tx.PutShare(v); e != nil {
			return nil, e
		}
		if e = saveReceipt(tx, rec); e != nil {
			return nil, e
		}
	}
	return &api.AssociateResourceSharePermissionResponse{ClientToken: in.ClientToken, ReturnValue: new(api.Boolean(true))}, nil
}
func (s *Service) disassociateResourceSharePermission(tx Transaction, in *api.DisassociateResourceSharePermissionRequest) (*api.DisassociateResourceSharePermissionResponse, error) {
	v, e := s.ownedShare(tx, value(in.ResourceShareArn), "DisassociateResourceSharePermission", true)
	if e != nil {
		return nil, e
	}
	rec, replay, e := receipt(tx, "DisassociateResourceSharePermission", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if !replay {
		for _, p := range v.Permissions {
			if p.ARN == value(in.PermissionArn) {
				for _, r := range v.Resources {
					if r.Status == "ASSOCIATED" && r.ResourceType == p.ResourceType {
						return nil, failure("OperationNotPermittedException", "Remove all resources of this type before removing its permission.")
					}
				}
			}
		}
		v.Permissions = slices.DeleteFunc(v.Permissions, func(p PermissionAssociation) bool { return p.ARN == value(in.PermissionArn) })
		v.Updated = s.clock.Now()
		if e = tx.PutShare(v); e != nil {
			return nil, e
		}
		if e = saveReceipt(tx, rec); e != nil {
			return nil, e
		}
	}
	return &api.DisassociateResourceSharePermissionResponse{ClientToken: in.ClientToken, ReturnValue: new(api.Boolean(true))}, nil
}
func equalTemplate(a, b string) bool {
	if _, _, e := parseTemplate(a, nil); e != nil {
		return false
	}
	if _, _, e := parseTemplate(b, nil); e != nil {
		return false
	}
	x, e := templateStatements(a)
	if e != nil {
		return false
	}
	y, e := templateStatements(b)
	if e != nil {
		return false
	}
	left, _ := json.Marshal(x)
	right, _ := json.Marshal(y)
	return bytes.Equal(left, right)
}

func actionAllowed(actions []string, action string) bool {
	for _, candidate := range actions {
		if strings.EqualFold(candidate, action) {
			return true
		}
	}
	return false
}
