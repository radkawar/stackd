package stepfunctions

import (
	"errors"
	"maps"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awswire"
)

func (k MachineKey) ARN() string {
	return "arn:" + k.Partition + ":states:" + k.Region + ":" + k.AccountID + ":stateMachine:" + k.Name
}

func (k ActivityKey) ARN() string {
	return "arn:" + k.Partition + ":states:" + k.Region + ":" + k.AccountID + ":activity:" + k.Name
}

func (k VersionKey) ARN() string { return k.Machine.ARN() + ":" + strconv.FormatInt(k.Number, 10) }
func (k AliasKey) ARN() string   { return k.Machine.ARN() + ":" + k.Name }

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
var aliasNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

func validResourceName(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > 80 || !utf8.ValidString(name) {
		return false
	}
	for _, c := range name {
		if unicode.IsSpace(c) || unicode.IsControl(c) || strings.ContainsRune(`<>[]{ }?*"#%\^|~`+"`$&,;:/", c) || c >= 0xD800 && c <= 0xDFFF || c >= 0xFDD0 && c <= 0xFDEF || c&0xFFFF >= 0xFFFE {
			return false
		}
	}
	return true
}

func validAliasName(name string) bool {
	return len(name) >= 1 && len(name) <= 80 && aliasNamePattern.MatchString(name) && strings.IndexFunc(name, func(c rune) bool { return c < '0' || c > '9' }) >= 0
}

// parseResourceARN validates syntax without turning a foreign account or region
// into a local resource. Callers enforce endpoint scope before repository reads.
func parseResourceARN(raw string) (Scope, string, string, string, error) {
	parts := strings.SplitN(raw, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "states" || parts[3] == "" || !accountPattern.MatchString(parts[4]) {
		return Scope{}, "", "", "", failure("InvalidArn", "Invalid Arn: '"+raw+"'", 400)
	}
	resource := strings.Split(parts[5], ":")
	if len(resource) < 2 || len(resource) > 3 || !validResourceName(resource[1]) || resource[0] != "stateMachine" && resource[0] != "activity" || resource[0] == "activity" && len(resource) != 2 {
		return Scope{}, "", "", "", failure("InvalidArn", "Invalid Arn: '"+raw+"'", 400)
	}
	qualifier := ""
	if len(resource) == 3 {
		qualifier = resource[2]
		if _, ok := versionNumber(qualifier); !ok && !validAliasName(qualifier) {
			return Scope{}, "", "", "", failure("InvalidArn", "Invalid Arn: '"+raw+"'", 400)
		}
	}
	return Scope{Partition: parts[1], Region: parts[3], AccountID: parts[4]}, resource[0], resource[1], qualifier, nil
}

func machineReference(raw string) (MachineKey, string, error) {
	scope, kind, name, qualifier, err := parseResourceARN(raw)
	if err != nil {
		return MachineKey{}, "", err
	}
	if kind != "stateMachine" {
		return MachineKey{}, "", failure("InvalidArn", "Invalid State Machine Arn: '"+raw+"'", 400)
	}
	return MachineKey{Scope: scope, Name: name}, qualifier, nil
}

// describeMachineReference accepts Map labels only for DescribeStateMachine.
// Repository lookup, IAM authorization, and encryption still use the parent.
func describeMachineReference(raw string) (string, string, error) {
	parent, label, labelled := strings.Cut(raw, "/")
	if !labelled {
		return raw, "", nil
	}
	_, qualifier, err := machineReference(parent)
	if err != nil || qualifier != "" || label == "" || strings.ContainsRune(label, ':') {
		return "", "", failure("InvalidArn", "Invalid Arn: '"+raw+"'", 400)
	}
	return parent, label, nil
}

func activityReference(raw string) (ActivityKey, error) {
	scope, kind, name, _, err := parseResourceARN(raw)
	if err != nil {
		return ActivityKey{}, err
	}
	if kind != "activity" {
		return ActivityKey{}, failure("InvalidArn", "Invalid Activity Arn: '"+raw+"'", 400)
	}
	return ActivityKey{Scope: scope, Name: name}, nil
}

func versionNumber(qualifier string) (int64, bool) {
	n, err := strconv.ParseInt(qualifier, 10, 64)
	return n, err == nil && n > 0 && strconv.FormatInt(n, 10) == qualifier
}

func machineMissing(raw string) *awswire.Error {
	return failure("StateMachineDoesNotExist", "State Machine Does Not Exist: '"+raw+"'", 400)
}

func resourceMissing(raw string) *awswire.Error {
	return failure("ResourceNotFound", "Resource not found: '"+raw+"'", 400)
}

func lookupMachine(r Reader, raw string) (MachineRecord, string, error) {
	key, qualifier, err := machineReference(raw)
	if err != nil {
		return MachineRecord{}, "", err
	}
	missing := MachineRecord{Key: key}
	if key.Scope != scopeFor(r.Context()) {
		return missing, qualifier, machineMissing(raw)
	}
	machine, err := r.Machine(key)
	if errors.Is(err, ErrNotFound) {
		return missing, qualifier, machineMissing(raw)
	}
	return machine, qualifier, err
}

func (s *Service) authorize(r Reader, action, resource string, tags map[string]string, conditions map[string][]string) *awswire.Error {
	conditions = maps.Clone(conditions)
	if conditions == nil {
		conditions = make(map[string][]string)
	}
	for key, val := range tags {
		conditions["aws:ResourceTag/"+key] = []string{val}
	}
	account := scopeFor(r.Context()).AccountID
	if parts := strings.SplitN(resource, ":", 6); len(parts) == 6 {
		account = parts[4]
	}
	if !strings.Contains(action, ":") {
		action = "states:" + action
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(r.Context(), authorization.Request{Action: action, ResourceARN: resource, ResourceAccountID: account, Context: conditions, EvaluationTime: &now}); rejected != nil {
		if rejected.Code == "AccessDenied" {
			return failure("AccessDeniedException", rejected.Message, 400)
		}
		return rejected
	}
	return nil
}

func (s *Service) controlMachine(r Reader, raw, action string, unqualified, active bool) (MachineRecord, string, error) {
	machine, qualifier, err := lookupMachine(r, raw)
	if machine.Key.Name != "" {
		if denied := s.authorize(r, action, raw, machine.Tags, nil); denied != nil {
			return MachineRecord{}, "", denied
		}
	}
	if err != nil {
		return machine, qualifier, err
	}
	if err := cloudFormationCheck(r.Context(), "StateMachine", machine.CFNOwner); err != nil {
		return machine, qualifier, err
	}
	if unqualified && qualifier != "" {
		return machine, qualifier, machineMissing(raw)
	}
	if active && machine.Status == "DELETING" {
		return machine, qualifier, failure("StateMachineDeleting", "State Machine is being deleted: '"+raw+"'", 400)
	}
	return machine, qualifier, nil
}

func (s *Service) passRole(r Reader, role string, machine MachineKey) error {
	parts := strings.SplitN(role, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != machine.Partition || parts[2] != "iam" || parts[3] != "" || !accountPattern.MatchString(parts[4]) || !strings.HasPrefix(parts[5], "role/") || len(parts[5]) <= 5 {
		return failure("InvalidArn", "Invalid Role Arn: '"+role+"'", 400)
	}
	if parts[4] != machine.AccountID {
		return failure("AccessDeniedException", "Cross-account pass role is not allowed.", 400)
	}
	if rejected := s.authorize(r, "iam:PassRole", role, nil, map[string][]string{"iam:PassedToService": {"states.amazonaws.com"}, "iam:AssociatedResourceArn": {machine.ARN()}}); rejected != nil {
		return rejected
	}
	return nil
}

func controlTimestamp(t time.Time) *api.Timestamp { return new(api.Timestamp(t)) }

func publicRevisionID(revision RevisionRecord) *api.RevisionId {
	if revision.Initial {
		return nil
	}
	return new(api.RevisionId(revision.Key.ID))
}
