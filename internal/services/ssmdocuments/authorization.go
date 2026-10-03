package ssmdocuments

import (
	"context"
	"maps"
	"regexp"
	"strings"

	"stackd/internal/authorization"
)

var documentNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,128}$`)

func documentARN(k Key) string {
	return "arn:" + k.Partition + ":ssm:" + k.Region + ":" + k.AccountID + ":document/" + k.Name
}
func documentKey(ctx context.Context, name string) (Key, error) {
	sc := scopeFor(ctx)
	isARN := strings.HasPrefix(name, "arn:")
	if isARN {
		parts := strings.SplitN(name, ":", 6)
		if len(parts) != 6 || parts[1] != sc.Partition || parts[2] != "ssm" || parts[3] != sc.Region || !strings.HasPrefix(parts[5], "document/") {
			return Key{}, failure("InvalidDocument", "Invalid document ARN.")
		}
		sc.AccountID = parts[4]
		name = strings.TrimPrefix(parts[5], "document/")
	}
	if !documentNamePattern.MatchString(name) {
		return Key{}, failure("ValidationException", "Invalid document name.")
	}
	if name == "AWS-RunShellScript" && !isARN {
		sc.AccountID = ""
	}
	return Key{Scope: sc, Name: name}, nil
}
func (s *Service) authorize(r Reader, action string, record Record, conditions map[string][]string) error {
	ctx := make(map[string][]string, len(conditions)+2*len(record.Tags))
	maps.Copy(ctx, conditions)
	for k, v := range record.Tags {
		ctx["aws:ResourceTag/"+k] = []string{v}
		ctx["ssm:resourceTag/"+k] = []string{v}
	}
	arn := "*"
	if record.Key.Name != "" {
		arn = documentARN(record.Key)
	}
	now := s.clock.Now()
	account := record.Key.AccountID
	builtin := record.Key.Name == "AWS-RunShellScript" && account == ""
	if builtin {
		account = BuiltinOwner(record.Key.Partition, record.Key.Region, record.Key.Name)
	}
	grant := builtin || sharedReadAction(action) && sharedSelector(record, scopeFor(r.Context()).AccountID) != ""
	if denied := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "ssm:" + action, ResourceARN: arn, ResourceAccountID: account, ResourceAccountGrant: grant, Context: ctx, EvaluationTime: &now}); denied != nil {
		return wireError(denied)
	}
	return nil
}
func (s *Service) load(r Reader, action, name string) (Record, error) {
	k, err := documentKey(r.Context(), name)
	if err != nil {
		return Record{}, err
	}
	if k.AccountID != "" && k.AccountID != scopeFor(r.Context()).AccountID && !sharedReadAction(action) {
		return Record{}, failure("InvalidDocument", "Only the document owner can perform this operation.")
	}
	record, err := loadRecord(r, k)
	if err != nil {
		record = Record{Key: k}
	}
	if rejected := s.authorize(r, action, record, nil); rejected != nil {
		return Record{}, rejected
	}
	return record, err
}
func loadRecord(r Reader, k Key) (Record, error) {
	if k.Name == "AWS-RunShellScript" && k.AccountID == "" {
		return builtinRecord(k), nil
	}
	record, err := r.Document(k)
	if err != nil {
		return Record{}, err
	}
	if k.AccountID != scopeFor(r.Context()).AccountID && sharedSelector(record, scopeFor(r.Context()).AccountID) == "" {
		return Record{}, failure("InvalidDocument", "The document does not exist or is not shared with you.")
	}
	return record, nil
}
