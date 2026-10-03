package ssmdocuments

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/ssm"
)

func contentHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}
func (s *Service) createDocument(tx Transaction, in *api.CreateDocumentRequest) (*api.CreateDocumentResult, error) {
	k, err := documentKey(tx.Context(), value(in.Name))
	if err != nil {
		return nil, err
	}
	tags, err := validateTags(in.Tags)
	if err != nil {
		return nil, err
	}
	kind := value(in.DocumentType)
	if kind == "" {
		kind = "Command"
	}
	conditions := tagConditions(tags)
	conditions["ssm:DocumentType"] = []string{kind}
	record := Record{Key: k, Type: kind, DocumentID: uuid.NewString(), DefaultVersion: 1, LatestVersion: 1, NextVersion: 2, Tags: tags}
	if err = s.authorize(tx, "CreateDocument", record, conditions); err != nil {
		return nil, err
	}
	name := strings.ToLower(k.Name)
	if strings.HasPrefix(name, "aws") || strings.HasPrefix(name, "amazon") || strings.HasPrefix(name, "amzn") {
		return nil, failure("ValidationException", "Document name prefixes aws, amazon and amzn are reserved.")
	}
	if _, err = tx.Document(k); err == nil {
		return nil, failure("DocumentAlreadyExists", "A document with this name already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if kind != "Command" && kind != "ApplicationConfiguration" && kind != "ApplicationConfigurationSchema" && kind != "DeploymentStrategy" {
		// TODO: Comeback: Automation, Session, Package and other document engines require their own execution owners.
		return nil, failure("InvalidDocumentContent", "The document type is not supported.")
	}
	if len(in.Attachments) > 0 {
		// TODO: Comeback: document attachments require their actual storage owner.
		return nil, failure("InvalidDocumentContent", "Document attachments are not supported.")
	}
	if kind == "ApplicationConfiguration" {
		if err = s.bindSchema(tx, &record, in.Requires); err != nil {
			return nil, err
		}
	} else if kind == "Command" && len(in.Requires) > 0 {
		return nil, failure("InvalidDocumentContent", "Command document dependencies are not supported.")
	}
	format := value(in.DocumentFormat)
	if format == "" {
		format = "JSON"
	}
	if err = validateDocumentContent(tx, record, value(in.Content), format); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	v := Version{Key: VersionKey{k, 1}, Content: value(in.Content), Format: format, Hash: contentHash(value(in.Content)), VersionName: value(in.VersionName), DisplayName: value(in.DisplayName), TargetType: value(in.TargetType), Created: now, Status: "Creating", ReadyAt: now}
	if err = tx.PutDocument(record); err != nil {
		return nil, err
	}
	if err = tx.InsertVersion(v); err != nil {
		return nil, err
	}
	desc, err := description(record, v)
	return &api.CreateDocumentResult{DocumentDescription: desc}, err
}
func (s *Service) updateDocument(tx Transaction, in *api.UpdateDocumentRequest) (*api.UpdateDocumentResult, error) {
	record, err := s.load(tx, "UpdateDocument", value(in.Name))
	if err != nil {
		return nil, err
	}
	if record.Key.AccountID == "" {
		return nil, failure("InvalidDocumentOperation", "AWS-owned documents cannot be updated.")
	}
	selector := value(in.DocumentVersion)
	if selector == "" || selector == "$DEFAULT" {
		return nil, failure("InvalidDocumentVersion", "UpdateDocument requires the latest number or $LATEST.")
	}
	old, err := selectVersion(tx, record, selector, "")
	if err != nil {
		return nil, err
	}
	if old.Key.Version != record.LatestVersion {
		return nil, failure("InvalidDocumentVersion", "Only the latest document version can be updated.")
	}
	if len(in.Attachments) > 0 {
		return nil, failure("InvalidDocumentContent", "Document attachments are not supported.")
	}
	format := value(in.DocumentFormat)
	if format == "" {
		format = "JSON"
	}
	if record.Type == "Command" {
		previous, err := decodeContent(old.Content, old.Format)
		if err != nil {
			return nil, err
		}
		next, err := decodeContent(value(in.Content), format)
		if err != nil {
			return nil, err
		}
		if previous.SchemaVersion == "1.2" || next.SchemaVersion == "1.2" {
			return nil, failure("InvalidDocumentSchemaVersion", "Update is not allowed for Command schema version 1.2.")
		}
	}
	if err = validateDocumentContent(tx, record, value(in.Content), format); err != nil {
		return nil, err
	}
	versions, err := tx.Versions(record.Key)
	if err != nil {
		return nil, err
	}
	if len(versions) >= 1000 {
		return nil, failure("DocumentVersionLimitExceeded", "Delete an older document version before updating.")
	}
	hash := contentHash(value(in.Content))
	versionName := value(in.VersionName)
	if old.Hash == hash {
		return nil, failure("DuplicateDocumentContent", "The content matches the latest document version.")
	}
	for _, v := range versions {
		if versionName != "" && v.VersionName == versionName {
			return nil, failure("DuplicateDocumentVersionName", "The version name already exists.")
		}
	}
	now := s.clock.Now()
	v := Version{Key: VersionKey{record.Key, record.NextVersion}, Content: value(in.Content), Format: format, Hash: hash, VersionName: versionName, DisplayName: old.DisplayName, TargetType: old.TargetType, Created: now, Status: "Updating", ReadyAt: now}
	if in.DisplayName != nil {
		v.DisplayName = value(in.DisplayName)
	}
	if in.TargetType != nil {
		v.TargetType = value(in.TargetType)
	}
	if err = tx.InsertVersion(v); err != nil {
		return nil, err
	}
	record.LatestVersion = v.Key.Version
	record.NextVersion++
	if err = tx.PutDocument(record); err != nil {
		return nil, err
	}
	desc, err := description(record, v)
	return &api.UpdateDocumentResult{DocumentDescription: desc}, err
}
func (s *Service) updateDefault(tx Transaction, in *api.UpdateDocumentDefaultVersionRequest) (*api.UpdateDocumentDefaultVersionResult, error) {
	record, err := s.load(tx, "UpdateDocumentDefaultVersion", value(in.Name))
	if err != nil {
		return nil, err
	}
	if record.Key.AccountID == "" {
		return nil, failure("InvalidDocumentOperation", "AWS-owned document defaults cannot be changed.")
	}
	v, err := selectVersion(tx, record, value(in.DocumentVersion), "")
	if err != nil {
		return nil, err
	}
	record.DefaultVersion = v.Key.Version
	if err = tx.PutDocument(record); err != nil {
		return nil, err
	}
	return &api.UpdateDocumentDefaultVersionResult{Description: &api.DocumentDefaultVersionDescription{Name: new(api.DocumentName(record.Key.Name)), DefaultVersion: new(api.DocumentVersion(strconv.FormatInt(v.Key.Version, 10))), DefaultVersionName: optional[api.DocumentVersionName](v.VersionName)}}, nil
}
func (s *Service) deleteDocument(tx Transaction, in *api.DeleteDocumentRequest) (*api.DeleteDocumentResult, error) {
	record, err := s.load(tx, "DeleteDocument", value(in.Name))
	if err != nil {
		return nil, err
	}
	if record.Key.AccountID == "" {
		return nil, failure("InvalidDocumentOperation", "AWS-owned documents cannot be deleted.")
	}
	if record.Type == "ApplicationConfigurationSchema" && (in.Force == nil || !bool(*in.Force)) {
		return nil, failure("InvalidDocument", "ApplicationConfigurationSchema documents require Force to delete.")
	}
	selector, versionName := value(in.DocumentVersion), value(in.VersionName)
	if selector == "" && versionName == "" {
		if len(record.Shares) != 0 {
			return nil, failure("InvalidDocumentOperation", "Stop sharing the document before deleting it.")
		}
		return &api.DeleteDocumentResult{}, tx.DeleteDocument(record.Key)
	}
	v, err := selectVersion(tx, record, selector, versionName)
	if err != nil {
		return nil, err
	}
	if v.Key.Version == record.DefaultVersion {
		return nil, failure("InvalidDocumentOperation", "The default document version cannot be deleted.")
	}
	if err = tx.DeleteVersion(v.Key); err != nil {
		return nil, err
	}
	if v.Key.Version == record.LatestVersion {
		versions, err := tx.Versions(record.Key)
		if err != nil {
			return nil, err
		}
		record.LatestVersion = versions[len(versions)-1].Key.Version
		if err = tx.PutDocument(record); err != nil {
			return nil, err
		}
	}
	return &api.DeleteDocumentResult{}, nil
}
func optional[T ~string](v string) *T {
	if v == "" {
		return nil
	}
	return new(T(v))
}
