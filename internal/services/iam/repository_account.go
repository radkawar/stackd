package iam

import (
	"slices"
	"strings"
)

func (t *memoryTx) LoginProfile(scope Scope, userID string) (LoginProfileRecord, error) {
	if err := t.check(false); err != nil {
		return LoginProfileRecord{}, err
	}
	p, ok := t.state.loginProfiles[scope][userID]
	if !ok {
		return LoginProfileRecord{}, ErrRecordNotFound
	}
	return cloneLoginProfile(p), nil
}

func (t *memoryTx) LoginProfiles(scope Scope) ([]LoginProfileRecord, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	profiles := make([]LoginProfileRecord, 0, len(t.state.loginProfiles[scope]))
	for _, p := range t.state.loginProfiles[scope] {
		profiles = append(profiles, cloneLoginProfile(p))
	}
	slices.SortFunc(profiles, func(a, b LoginProfileRecord) int { return strings.Compare(a.UserID, b.UserID) })
	return profiles, nil
}

func (t *memoryTx) PutLoginProfile(scope Scope, p LoginProfileRecord) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.loginProfiles[scope] == nil {
		t.state.loginProfiles[scope] = make(map[string]LoginProfileRecord)
	}
	t.state.loginProfiles[scope][p.UserID] = cloneLoginProfile(p)
	return nil
}

func (t *memoryTx) DeleteLoginProfile(scope Scope, userID string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.loginProfiles[scope][userID]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.loginProfiles[scope], userID)
	return nil
}

// AccountSettings returns zero defaults for accounts without custom settings.
func (t *memoryTx) AccountSettings(scope Scope) (AccountSettingsRecord, error) {
	if err := t.check(false); err != nil {
		return AccountSettingsRecord{}, err
	}
	return cloneAccountSettings(t.state.accountSettings[scope]), nil
}

func (t *memoryTx) AccountAliasOwner(partition, alias string) (string, error) {
	if err := t.check(false); err != nil {
		return "", err
	}
	for scope, settings := range t.state.accountSettings {
		if scope.Partition == partition && settings.Alias != "" && settings.Alias == alias {
			return scope.AccountID, nil
		}
	}
	return "", ErrRecordNotFound
}

func (t *memoryTx) PutAccountSettings(scope Scope, settings AccountSettingsRecord) error {
	if err := t.check(true); err != nil {
		return err
	}
	t.state.accountSettings[scope] = cloneAccountSettings(settings)
	return nil
}
