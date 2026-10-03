package integrations

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	ssmapi "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/services/appconfig"
)

var _ appconfig.StrategyDocuments = (*AppConfigEffects)(nil)

func appConfigStrategyContent(strategy appconfig.Strategy) (ssmapi.DocumentContent, error) {
	growth := strconv.FormatFloat(float64(float32(strategy.GrowthFactor)), 'f', -1, 64)
	if !strings.Contains(growth, ".") {
		growth += ".0"
	}
	document := struct {
		SchemaVersion string      `json:"schemaVersion"`
		Description   string      `json:"description,omitempty"`
		Duration      int32       `json:"deploymentDurationInMinutes"`
		GrowthFactor  json.Number `json:"growthFactor"`
		Bake          int32       `json:"finalBakeTimeInMinutes"`
		GrowthType    string      `json:"growthType"`
	}{"1.0", strategy.Description, strategy.DurationMinutes, json.Number(growth), strategy.FinalBakeMinutes, strategy.GrowthType}
	content, err := json.Marshal(document)
	return ssmapi.DocumentContent(content), err
}
func appConfigStrategyContext(ctx context.Context, scope appconfig.Scope) context.Context {
	ctx = appConfigScopeContext(ctx, scope)
	m := awsctx.FromContext(ctx)
	m.InvokedBy = "appconfig.amazonaws.com"
	return awsctx.WithViaService(awsctx.WithMetadata(ctx, m), "appconfig.amazonaws.com")
}

// Strategy replication is a state-only SSM operation. It intentionally borrows
// the AppConfig transaction and current caller, so denied/colliding documents
// roll back the strategy rather than creating an untracked external resource.
func (a *AppConfigEffects) CreateStrategyDocument(ctx context.Context, strategy appconfig.Strategy) error {
	content, err := appConfigStrategyContent(strategy)
	if err != nil {
		return err
	}
	_, err = appConfigCommand(appConfigStrategyContext(ctx, strategy.Scope), a.Documents, "ssm", "CreateDocument", &ssmapi.CreateDocumentRequest{Name: new(ssmapi.DocumentName(strategy.Name)), Content: &content, DocumentType: new(ssmapi.DocumentType("DeploymentStrategy")), DocumentFormat: new(ssmapi.DocumentFormat("JSON"))})
	return err
}
func (a *AppConfigEffects) UpdateStrategyDocument(ctx context.Context, strategy appconfig.Strategy) error {
	content, err := appConfigStrategyContent(strategy)
	if err != nil {
		return err
	}
	_, err = appConfigCommand(appConfigStrategyContext(ctx, strategy.Scope), a.Documents, "ssm", "UpdateDocument", &ssmapi.UpdateDocumentRequest{Name: new(ssmapi.DocumentName(strategy.Name)), Content: &content, DocumentVersion: new(ssmapi.DocumentVersion("$LATEST")), DocumentFormat: new(ssmapi.DocumentFormat("JSON"))})
	return err
}
func (a *AppConfigEffects) DeleteStrategyDocument(ctx context.Context, strategy appconfig.Strategy) error {
	_, err := appConfigCommand(appConfigStrategyContext(ctx, strategy.Scope), a.Documents, "ssm", "DeleteDocument", &ssmapi.DeleteDocumentRequest{Name: new(ssmapi.DocumentName(strategy.Name))})
	return err
}
