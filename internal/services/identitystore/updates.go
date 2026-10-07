package identitystore

import (
	"bytes"
	"encoding/json"
	"errors"
	api "stackd/internal/awsapi/identitystore"
	"strings"
	"unicode/utf8"
)

func patchString(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok || s == "" || utf8.RuneCountInString(s) > 1024 {
		return "", bad("AttributeValue must be a non-empty string of at most 1024 characters, or absent to remove it.")
	}
	return s, nil
}
func patchObject(v any, out any) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return bad("Invalid AttributeValue.")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(out); e != nil {
		return bad("Invalid AttributeValue.")
	}
	return nil
}
func (s *Service) updateUser(tx Transaction, in *api.UpdateUserInput) (*api.UpdateUserOutput, error) {
	store, id := value(in.IdentityStoreId), value(in.UserId)
	if e := s.admit(tx, "UpdateUser", store, id, "", ""); e != nil {
		return nil, e
	}
	u, e := tx.User(Key{store, id})
	if e != nil {
		return nil, e
	}
	for _, op := range in.Operations {
		path := strings.ToLower(value(op.AttributePath))
		var target *string
		switch path {
		case "username":
			target = &u.UserName
		case "displayname":
			target = &u.DisplayName
		case "nickname":
			target = &u.NickName
		case "profileurl":
			target = &u.ProfileURL
		case "title":
			target = &u.Title
		case "usertype":
			target = &u.UserType
		case "preferredlanguage":
			target = &u.PreferredLanguage
		case "locale":
			target = &u.Locale
		case "timezone":
			target = &u.Timezone
		case "birthdate":
			target = &u.Birthdate
		case "website":
			target = &u.Website
		case "name.formatted":
			target = &u.Name.Formatted
		case "name.familyname":
			target = &u.Name.FamilyName
		case "name.givenname":
			target = &u.Name.GivenName
		case "name.middlename":
			target = &u.Name.MiddleName
		case "name.honorificprefix":
			target = &u.Name.HonorificPrefix
		case "name.honorificsuffix":
			target = &u.Name.HonorificSuffix
		case "name":
			u.Name = Name{}
			if op.AttributeValue != nil {
				var name api.Name
				if e := patchObject(op.AttributeValue, &name); e != nil {
					return nil, e
				}
				u.Name = domainName(&name)
			}
		case "emails":
			u.Emails = nil
			if op.AttributeValue != nil {
				var emails api.Emails
				if e := patchObject(op.AttributeValue, &emails); e != nil {
					return nil, e
				}
				for _, v := range emails {
					u.Emails = append(u.Emails, Email{Value: value(v.Value), Type: value(v.Type), Primary: v.Primary != nil && bool(*v.Primary)})
				}
			}
		default:
			return nil, unsupported("Unsupported user attribute path: " + value(op.AttributePath))
		}
		if target != nil {
			v, e := patchString(op.AttributeValue)
			if e != nil {
				return nil, e
			}
			*target = v
		}
	}
	if e := validateUser(u); e != nil {
		return nil, e
	}
	if other, e := tx.UserByName(store, u.UserName); e == nil && other.ID != id {
		return nil, conflict("UserName already exists.")
	} else if e != nil && !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	return &api.UpdateUserOutput{}, tx.PutUser(u)
}
func (s *Service) updateGroup(tx Transaction, in *api.UpdateGroupInput) (*api.UpdateGroupOutput, error) {
	store, id := value(in.IdentityStoreId), value(in.GroupId)
	if e := s.admit(tx, "UpdateGroup", store, "", id, ""); e != nil {
		return nil, e
	}
	g, e := tx.Group(Key{store, id})
	if e != nil {
		return nil, e
	}
	if e := CheckCloudFormationOwner(tx.Context(), g.CloudFormationOwner); e != nil {
		return nil, e
	}
	for _, op := range in.Operations {
		v, e := patchString(op.AttributeValue)
		if e != nil {
			return nil, e
		}
		switch strings.ToLower(value(op.AttributePath)) {
		case "displayname":
			g.DisplayName = v
		case "description":
			g.Description = v
		default:
			return nil, unsupported("Unsupported group attribute path: " + value(op.AttributePath))
		}
	}
	if g.DisplayName == "" || reservedName(g.DisplayName) {
		return nil, bad("DisplayName is required and must not be reserved.")
	}
	if other, e := tx.GroupByName(store, g.DisplayName); e == nil && other.ID != id {
		return nil, conflict("DisplayName already exists.")
	} else if e != nil && !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	return &api.UpdateGroupOutput{}, tx.PutGroup(g)
}
