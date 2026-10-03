package identitycenter

import (
	"slices"
	"stackd/iam/policy"
	api "stackd/internal/awsapi/ssoadmin"
	"strings"
)

func (s *Service) registerPermissions() {
	register(s, "ssoadmin", "PutInlinePolicyToPermissionSet", func(tx Transaction, in *api.PutInlinePolicyToPermissionSetInput) (*api.PutInlinePolicyToPermissionSetOutput, error) {
		_, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "PutInlinePolicyToPermissionSet")
		if e != nil {
			return nil, e
		}
		if _, e = policy.Parse([]byte(value(in.InlinePolicy))); e != nil {
			return nil, bad("The inline permission policy is invalid: " + e.Error())
		}
		p.InlinePolicy = value(in.InlinePolicy)
		return &api.PutInlinePolicyToPermissionSetOutput{}, tx.PutPermissionSet(p)
	})
	register(s, "ssoadmin", "GetInlinePolicyForPermissionSet", func(tx Transaction, in *api.GetInlinePolicyForPermissionSetInput) (*api.GetInlinePolicyForPermissionSetOutput, error) {
		_, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "GetInlinePolicyForPermissionSet")
		if e != nil {
			return nil, e
		}
		return &api.GetInlinePolicyForPermissionSetOutput{InlinePolicy: new(api.PermissionSetPolicyDocument(p.InlinePolicy))}, nil
	})
	register(s, "ssoadmin", "DeleteInlinePolicyFromPermissionSet", func(tx Transaction, in *api.DeleteInlinePolicyFromPermissionSetInput) (*api.DeleteInlinePolicyFromPermissionSetOutput, error) {
		_, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "DeleteInlinePolicyFromPermissionSet")
		if e != nil {
			return nil, e
		}
		p.InlinePolicy = ""
		return &api.DeleteInlinePolicyFromPermissionSetOutput{}, tx.PutPermissionSet(p)
	})
	register(s, "ssoadmin", "AttachManagedPolicyToPermissionSet", func(tx Transaction, in *api.AttachManagedPolicyToPermissionSetInput) (*api.AttachManagedPolicyToPermissionSetOutput, error) {
		i, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "AttachManagedPolicyToPermissionSet")
		if e != nil {
			return nil, e
		}
		arn := value(in.ManagedPolicyArn)
		if !strings.HasPrefix(arn, "arn:"+i.Partition+":iam::aws:policy/") {
			return nil, bad("Use an AWS managed policy ARN; customer managed policies require a name/path reference.")
		}
		if !slices.Contains(p.ManagedPolicies, arn) {
			p.ManagedPolicies = append(p.ManagedPolicies, arn)
			slices.Sort(p.ManagedPolicies)
		}
		return &api.AttachManagedPolicyToPermissionSetOutput{}, tx.PutPermissionSet(p)
	})
	register(s, "ssoadmin", "DetachManagedPolicyFromPermissionSet", func(tx Transaction, in *api.DetachManagedPolicyFromPermissionSetInput) (*api.DetachManagedPolicyFromPermissionSetOutput, error) {
		_, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "DetachManagedPolicyFromPermissionSet")
		if e != nil {
			return nil, e
		}
		index := slices.Index(p.ManagedPolicies, value(in.ManagedPolicyArn))
		if index < 0 {
			return nil, ErrNotFound
		}
		p.ManagedPolicies = slices.Delete(p.ManagedPolicies, index, index+1)
		return &api.DetachManagedPolicyFromPermissionSetOutput{}, tx.PutPermissionSet(p)
	})
	register(s, "ssoadmin", "ListManagedPoliciesInPermissionSet", func(tx Transaction, in *api.ListManagedPoliciesInPermissionSetInput) (*api.ListManagedPoliciesInPermissionSetOutput, error) {
		_, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "ListManagedPoliciesInPermissionSet")
		if e != nil {
			return nil, e
		}
		rows, next, e := pageSlice(p.ManagedPolicies, value(in.NextToken), "ListManagedPolicies/"+p.ARN, intValue(in.MaxResults), func(v string) string { return v })
		if e != nil {
			return nil, e
		}
		out := &api.ListManagedPoliciesInPermissionSetOutput{AttachedManagedPolicies: api.AttachedManagedPolicyList{}}
		for _, arn := range rows {
			out.AttachedManagedPolicies = append(out.AttachedManagedPolicies, api.AttachedManagedPolicy{Arn: new(api.ManagedPolicyArn(arn)), Name: new(api.Name(arn[strings.LastIndexByte(arn, '/')+1:]))})
		}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
	register(s, "ssoadmin", "AttachCustomerManagedPolicyReferenceToPermissionSet", func(tx Transaction, in *api.AttachCustomerManagedPolicyReferenceToPermissionSetInput) (*api.AttachCustomerManagedPolicyReferenceToPermissionSetOutput, error) {
		_, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "AttachCustomerManagedPolicyReferenceToPermissionSet")
		if e != nil {
			return nil, e
		}
		ref, e := policyReference(in.CustomerManagedPolicyReference)
		if e != nil {
			return nil, e
		}
		if !slices.Contains(p.CustomerManagedPolicies, ref) {
			p.CustomerManagedPolicies = append(p.CustomerManagedPolicies, ref)
			slices.SortFunc(p.CustomerManagedPolicies, func(a, b PolicyReference) int { return strings.Compare(a.Path+a.Name, b.Path+b.Name) })
		}
		return &api.AttachCustomerManagedPolicyReferenceToPermissionSetOutput{}, tx.PutPermissionSet(p)
	})
	register(s, "ssoadmin", "DetachCustomerManagedPolicyReferenceFromPermissionSet", func(tx Transaction, in *api.DetachCustomerManagedPolicyReferenceFromPermissionSetInput) (*api.DetachCustomerManagedPolicyReferenceFromPermissionSetOutput, error) {
		_, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "DetachCustomerManagedPolicyReferenceFromPermissionSet")
		if e != nil {
			return nil, e
		}
		ref, e := policyReference(in.CustomerManagedPolicyReference)
		if e != nil {
			return nil, e
		}
		index := slices.Index(p.CustomerManagedPolicies, ref)
		if index < 0 {
			return nil, ErrNotFound
		}
		p.CustomerManagedPolicies = slices.Delete(p.CustomerManagedPolicies, index, index+1)
		return &api.DetachCustomerManagedPolicyReferenceFromPermissionSetOutput{}, tx.PutPermissionSet(p)
	})
	register(s, "ssoadmin", "ListCustomerManagedPolicyReferencesInPermissionSet", func(tx Transaction, in *api.ListCustomerManagedPolicyReferencesInPermissionSetInput) (*api.ListCustomerManagedPolicyReferencesInPermissionSetOutput, error) {
		_, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "ListCustomerManagedPolicyReferencesInPermissionSet")
		if e != nil {
			return nil, e
		}
		rows, next, e := pageSlice(p.CustomerManagedPolicies, value(in.NextToken), "ListCustomerPolicies/"+p.ARN, intValue(in.MaxResults), func(v PolicyReference) string { return v.Path + v.Name })
		if e != nil {
			return nil, e
		}
		out := &api.ListCustomerManagedPolicyReferencesInPermissionSetOutput{CustomerManagedPolicyReferences: api.CustomerManagedPolicyReferenceList{}}
		for _, ref := range rows {
			out.CustomerManagedPolicyReferences = append(out.CustomerManagedPolicyReferences, *wireReference(ref))
		}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
	register(s, "ssoadmin", "PutPermissionsBoundaryToPermissionSet", func(tx Transaction, in *api.PutPermissionsBoundaryToPermissionSetInput) (*api.PutPermissionsBoundaryToPermissionSetOutput, error) {
		i, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "PutPermissionsBoundaryToPermissionSet")
		if e != nil {
			return nil, e
		}
		b := in.PermissionsBoundary
		if b == nil || (b.ManagedPolicyArn == nil) == (b.CustomerManagedPolicyReference == nil) {
			return nil, bad("Specify exactly one managed or customer-managed permissions boundary.")
		}
		p.BoundaryARN = ""
		p.Boundary = PolicyReference{}
		if b.ManagedPolicyArn != nil {
			p.BoundaryARN = value(b.ManagedPolicyArn)
			if !strings.HasPrefix(p.BoundaryARN, "arn:"+i.Partition+":iam::aws:policy/") {
				return nil, bad("An AWS managed boundary ARN is required.")
			}
		} else {
			p.Boundary, e = policyReference(b.CustomerManagedPolicyReference)
			if e != nil {
				return nil, e
			}
		}
		return &api.PutPermissionsBoundaryToPermissionSetOutput{}, tx.PutPermissionSet(p)
	})
	register(s, "ssoadmin", "GetPermissionsBoundaryForPermissionSet", func(tx Transaction, in *api.GetPermissionsBoundaryForPermissionSetInput) (*api.GetPermissionsBoundaryForPermissionSetOutput, error) {
		_, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "GetPermissionsBoundaryForPermissionSet")
		if e != nil {
			return nil, e
		}
		out := &api.GetPermissionsBoundaryForPermissionSetOutput{}
		if p.BoundaryARN != "" {
			out.PermissionsBoundary = &api.PermissionsBoundary{ManagedPolicyArn: new(api.ManagedPolicyArn(p.BoundaryARN))}
		} else if p.Boundary.Name != "" {
			out.PermissionsBoundary = &api.PermissionsBoundary{CustomerManagedPolicyReference: wireReference(p.Boundary)}
		}
		return out, nil
	})
	register(s, "ssoadmin", "DeletePermissionsBoundaryFromPermissionSet", func(tx Transaction, in *api.DeletePermissionsBoundaryFromPermissionSetInput) (*api.DeletePermissionsBoundaryFromPermissionSetOutput, error) {
		_, p, e := s.permission(tx, value(in.InstanceArn), value(in.PermissionSetArn), "DeletePermissionsBoundaryFromPermissionSet")
		if e != nil {
			return nil, e
		}
		p.BoundaryARN = ""
		p.Boundary = PolicyReference{}
		return &api.DeletePermissionsBoundaryFromPermissionSetOutput{}, tx.PutPermissionSet(p)
	})
}
func policyReference(v *api.CustomerManagedPolicyReference) (PolicyReference, error) {
	if v == nil || value(v.Name) == "" {
		return PolicyReference{}, bad("A customer managed policy name is required.")
	}
	path := value(v.Path)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") || !strings.HasSuffix(path, "/") {
		return PolicyReference{}, bad("The customer managed policy path must begin and end with a slash.")
	}
	return PolicyReference{Name: value(v.Name), Path: path}, nil
}
func wireReference(v PolicyReference) *api.CustomerManagedPolicyReference {
	return &api.CustomerManagedPolicyReference{Name: new(api.ManagedPolicyName(v.Name)), Path: new(api.ManagedPolicyPath(v.Path))}
}
