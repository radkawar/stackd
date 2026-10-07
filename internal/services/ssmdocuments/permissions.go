package ssmdocuments

import (
	"maps"
	"regexp"
	"strings"

	api "stackd/internal/awsapi/ssm"
)

var shareAccountPattern = regexp.MustCompile(`^[0-9]{12}$`)

func sharedReadAction(action string) bool {
	switch action {
	case "GetDocument", "DescribeDocument", "ListDocumentVersions", "ListDocuments", "SendCommand":
		return true
	}
	return false
}

func sharedSelector(record Record, account string) string {
	if selector := record.Shares["all"]; selector != "" {
		return selector
	}
	return record.Shares[account]
}

func sharedVersionAllowed(r Reader, record Record, version int64) bool {
	if record.Key.AccountID == "" || record.Key.AccountID == scopeFor(r.Context()).AccountID {
		return true
	}
	switch sharedSelector(record, scopeFor(r.Context()).AccountID) {
	case "$ALL":
		return true
	case "$DEFAULT":
		return version == record.DefaultVersion
	case "$LATEST":
		return version == record.LatestVersion
	}
	return false
}

func permissionAccounts(input api.AccountIdList) ([]string, error) {
	if len(input) > 20 {
		return nil, failure("DocumentPermissionLimit", "At most 20 accounts may be specified in one operation.")
	}
	accounts := make([]string, 0, len(input))
	public := false
	for _, raw := range input {
		account := string(raw)
		if strings.EqualFold(account, "all") {
			account, public = "all", true
		} else if !shareAccountPattern.MatchString(account) {
			return nil, failure("ValidationException", "Account IDs must contain twelve digits or be All.")
		}
		accounts = append(accounts, account)
	}
	if public && len(accounts) != 1 {
		return nil, failure("DocumentPermissionLimit", "Accounts can either be All or a group of AWS accounts.")
	}
	return accounts, nil
}

func (s *Service) permissionDocument(r Reader, action, name, permission string) (Record, error) {
	if permission != "Share" {
		return Record{}, failure("InvalidPermissionType", "Share is the only supported permission type.")
	}
	if !documentNamePattern.MatchString(name) {
		return Record{}, failure("ValidationException", "Specify the owned document name.")
	}
	record, err := s.loadClaimed(r, action, name)
	if err != nil {
		return Record{}, err
	}
	if record.Key.AccountID != scopeFor(r.Context()).AccountID {
		return Record{}, failure("InvalidDocument", "Only the document owner can manage its permissions.")
	}
	return record, nil
}

func (s *Service) modifyDocumentPermission(tx Transaction, in *api.ModifyDocumentPermissionRequest) (*api.ModifyDocumentPermissionResponse, error) {
	record, err := s.permissionDocument(tx, "ModifyDocumentPermission", value(in.Name), value(in.PermissionType))
	if err != nil {
		return nil, err
	}
	add, err := permissionAccounts(in.AccountIdsToAdd)
	if err != nil {
		return nil, err
	}
	remove, err := permissionAccounts(in.AccountIdsToRemove)
	if err != nil {
		return nil, err
	}
	if len(add)+len(remove) == 0 {
		return nil, failure("ValidationException", "Specify accounts to add or remove.")
	}
	selector := value(in.SharedDocumentVersion)
	if selector == "" {
		selector = "$DEFAULT"
	}
	if selector != "$DEFAULT" && selector != "$LATEST" && selector != "$ALL" {
		return nil, failure("ValidationException", "SharedDocumentVersion must be $DEFAULT, $LATEST, or $ALL.")
	}
	shares := maps.Clone(record.Shares)
	if shares == nil {
		shares = map[string]string{}
	}
	for _, account := range add {
		if account == "all" {
			shares[account] = "$ALL"
		} else {
			shares[account] = selector
		}
	}
	// Removal wins over an addition of the same account; All removes public
	// sharing only, not private grants (native document_sharing.json).
	for _, account := range remove {
		delete(shares, account)
	}
	if shares["all"] != "" && len(shares) != 1 {
		return nil, failure("DocumentPermissionLimit", "A document cannot be shared publicly and privately at the same time.")
	}
	if len(shares) > 1000 {
		return nil, failure("DocumentPermissionLimit", "A document can be shared with at most 1000 accounts.")
	}
	if shares["all"] != "" && record.Shares["all"] == "" {
		if s.publicSharing == nil {
			return nil, failure("InternalServerError", "The document public-sharing setting authority is unavailable.")
		}
		allowed, err := s.publicSharing.DocumentPublicSharingAllowed(tx.Context())
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, failure("InvalidDocumentOperation", "Public sharing is blocked for this account and Region.")
		}
		documents, err := tx.Documents(record.Key.Scope)
		if err != nil {
			return nil, err
		}
		count := 0
		for _, document := range documents {
			if document.Shares["all"] != "" {
				count++
			}
		}
		if count >= 5 {
			return nil, failure("DocumentPermissionLimit", "At most five documents may be shared publicly.")
		}
	}
	record.Shares = shares
	return &api.ModifyDocumentPermissionResponse{}, tx.PutDocument(record)
}

func (s *Service) describeDocumentPermission(tx Transaction, in *api.DescribeDocumentPermissionRequest) (*api.DescribeDocumentPermissionResponse, error) {
	record, err := s.permissionDocument(tx, "DescribeDocumentPermission", value(in.Name), value(in.PermissionType))
	if err != nil {
		return nil, err
	}
	accounts := make([]string, 0, len(record.Shares))
	for account := range record.Shares {
		accounts = append(accounts, account)
	}
	size := 200
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	rows, next, err := documentPageLimit(s, tx, "DescribeDocumentPermission", record.DocumentID, accounts, func(account string) string { return account }, size, 200, in.NextToken)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeDocumentPermissionResponse{AccountIds: api.AccountIdList{}, AccountSharingInfoList: api.AccountSharingInfoList{}, NextToken: next}
	for _, account := range rows {
		out.AccountIds = append(out.AccountIds, api.AccountId(account))
		out.AccountSharingInfoList = append(out.AccountSharingInfoList, api.AccountSharingInfo{AccountId: new(api.AccountId(account)), SharedDocumentVersion: new(api.SharedDocumentVersion(record.Shares[account]))})
	}
	return out, nil
}
