package identitystore

import (
	"context"
	"errors"
	"regexp"
)

var storeIDPattern = regexp.MustCompile(`^(d-[0-9a-f]{10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// EnsureStore is a trusted Identity Center provisioning boundary, not a public
// directory creation API. It joins the caller's transaction and never transfers
// an existing store to another owner.
func (s *Service) EnsureStore(ctx context.Context, scope Scope, id string) error {
	if !storeIDPattern.MatchString(id) || scope.Partition == "" || scope.AccountID == "" || scope.Region == "" {
		return bad("Invalid identity store scope or identifier.")
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		v, e := tx.Store(id)
		if e == nil {
			if v.Scope != scope {
				return ErrNotFound
			}
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		return tx.PutStore(Store{ID: id, Scope: scope})
	})
}
func ownedStore(r Reader, scope Scope, id string) error {
	v, e := r.Store(id)
	if e != nil {
		return e
	}
	if v.Scope != scope {
		return ErrNotFound
	}
	return nil
}

// FindUser reads current directory state under the explicitly supplied owner scope.
// Trusted consumers must pass their enclosing transaction context when using the
// result to admit a state transition. These lookups do not grant AWS authority.
func (s *Service) FindUser(ctx context.Context, scope Scope, storeID, userID string) (out User, err error) {
	err = s.repository.View(ctx, func(r Reader) error {
		if e := ownedStore(r, scope, storeID); e != nil {
			return e
		}
		var e error
		out, e = r.User(Key{storeID, userID})
		return e
	})
	return
}
func (s *Service) UserByName(ctx context.Context, scope Scope, storeID, username string) (out User, err error) {
	err = s.repository.View(ctx, func(r Reader) error {
		if e := ownedStore(r, scope, storeID); e != nil {
			return e
		}
		var e error
		out, e = r.UserByName(storeID, username)
		return e
	})
	return
}
func (s *Service) GroupExists(ctx context.Context, scope Scope, storeID, groupID string) (exists bool, err error) {
	err = s.repository.View(ctx, func(r Reader) error {
		if e := ownedStore(r, scope, storeID); e != nil {
			return e
		}
		_, e := r.Group(Key{storeID, groupID})
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		exists = e == nil
		return e
	})
	return
}
func (s *Service) IsMember(ctx context.Context, scope Scope, storeID, userID, groupID string) (exists bool, err error) {
	err = s.repository.View(ctx, func(r Reader) error {
		if e := ownedStore(r, scope, storeID); e != nil {
			return e
		}
		_, e := r.MembershipFor(storeID, userID, groupID)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		exists = e == nil
		return e
	})
	return
}

// DeleteStore retires an Identity Center directory and its users, groups and
// memberships in the caller's transaction. Public APIs cannot invoke this boundary.
func (s *Service) DeleteStore(ctx context.Context, scope Scope, storeID string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		if e := ownedStore(tx, scope, storeID); e != nil {
			return e
		}
		return tx.DeleteStore(storeID)
	})
}
