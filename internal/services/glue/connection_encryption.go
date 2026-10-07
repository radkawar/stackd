package glue

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/glue"
)

type ConnectionEncryptionRecord struct {
	CFNOwner        string
	Scope           Scope
	KeyID           string
	ReturnEncrypted bool
}

func registerConnectionEncryption(s *Service) {
	registerControl(s, "GetDataCatalogEncryptionSettings", s.getConnectionEncryption)
	registerControl(s, "PutDataCatalogEncryptionSettings", s.putConnectionEncryption)
}
func connectionEncryption(r Reader, scope Scope) (ConnectionEncryptionRecord, error) {
	row, err := r.ConnectionEncryption(scope)
	if errors.Is(err, ErrNotFound) {
		return ConnectionEncryptionRecord{Scope: scope}, nil
	}
	return row, err
}
func (s *Service) getConnectionEncryption(ctx context.Context, tx Transaction, in *api.GetDataCatalogEncryptionSettingsInput) (*api.GetDataCatalogEncryptionSettingsOutput, error) {
	scope, err := connectionScope(ctx, in.CatalogId)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, tx, "GetDataCatalogEncryptionSettings", scope, "*", nil); err != nil {
		return nil, err
	}
	row, err := connectionEncryption(tx, scope)
	if err != nil {
		return nil, err
	}
	password := &api.ConnectionPasswordEncryption{ReturnConnectionPasswordEncrypted: new(api.Boolean(row.ReturnEncrypted))}
	if row.KeyID != "" {
		password.AwsKmsKeyId = new(api.NameString(row.KeyID))
	}
	return &api.GetDataCatalogEncryptionSettingsOutput{DataCatalogEncryptionSettings: &api.DataCatalogEncryptionSettings{ConnectionPasswordEncryption: password, EncryptionAtRest: &api.EncryptionAtRest{CatalogEncryptionMode: new(api.CatalogEncryptionMode("DISABLED"))}}}, nil
}
func (s *Service) putConnectionEncryption(ctx context.Context, tx Transaction, in *api.PutDataCatalogEncryptionSettingsInput) (*api.PutDataCatalogEncryptionSettingsOutput, error) {
	scope, err := connectionScope(ctx, in.CatalogId)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, tx, "PutDataCatalogEncryptionSettings", scope, "*", nil); err != nil {
		return nil, err
	}
	if in.DataCatalogEncryptionSettings == nil {
		return nil, failure("InvalidInputException", "Data catalog encryption settings are required.")
	}
	settings := in.DataCatalogEncryptionSettings
	// TODO: Comeback implement whole-catalog KMS encryption; do not report it enabled while only passwords are encrypted.
	if settings.EncryptionAtRest != nil && value(settings.EncryptionAtRest.CatalogEncryptionMode) != "DISABLED" {
		return nil, unsupported("Whole-catalog encryption is not implemented.")
	}
	row, err := connectionEncryption(tx, scope)
	if err != nil {
		return nil, err
	}
	if password := settings.ConnectionPasswordEncryption; password != nil {
		if password.ReturnConnectionPasswordEncrypted == nil {
			return nil, failure("InvalidInputException", "ReturnConnectionPasswordEncrypted is required.")
		}
		row.ReturnEncrypted = bool(*password.ReturnConnectionPasswordEncrypted)
		row.KeyID = value(password.AwsKmsKeyId)
		if row.ReturnEncrypted && row.KeyID == "" {
			return nil, unsupported("Password encryption requires an explicit customer-managed KMS key.")
		}
	}
	if err := tx.PutConnectionEncryption(row); err != nil {
		return nil, err
	}
	return &api.PutDataCatalogEncryptionSettingsOutput{}, nil
}
func (s *Service) protectConnectionPassword(ctx context.Context, tx Transaction, row *ConnectionRecord) error {
	settings, err := connectionEncryption(tx, row.Key.Scope)
	if err != nil {
		return err
	}
	if row.Password == "" || !settings.ReturnEncrypted {
		return nil
	}
	if s.connectionCrypto == nil {
		return unsupported("Connection password KMS adapter is not configured.")
	}
	cipher, _, rejected := s.connectionCrypto.Encrypt(ctx, settings.KeyID, []byte(row.Password), connectionEncryptionContext(row.Key))
	if rejected != nil {
		return rejected
	}
	row.PasswordCipher = cipher
	row.Password = ""
	return nil
}
func (r memoryReader) ConnectionEncryption(scope Scope) (ConnectionEncryptionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ConnectionEncryptionRecord{}, err
	}
	v, ok := r.s.connectionEncryption[scope]
	if !ok {
		return ConnectionEncryptionRecord{}, ErrNotFound
	}
	return v, nil
}
func (w memoryWriter) PutConnectionEncryption(v ConnectionEncryptionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.connectionEncryption[v.Scope] = v
	return nil
}
func (w memoryWriter) DeleteConnectionEncryption(scope Scope) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.connectionEncryption, scope)
	return nil
}
