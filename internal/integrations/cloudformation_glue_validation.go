package integrations

import (
	"fmt"
	"stackd/internal/services/cloudformation"
	"strings"
)

func cfnGlueNestedName(p cloudformation.Properties, top, nested string) string {
	if name := cfnComputeString(p, top); name != "" {
		return strings.ToLower(name)
	}
	v, _ := cfnComputeObject(p[nested])
	return strings.ToLower(cfnComputeString(v, "Name"))
}
func cfnGlueCatalogAdmission(p cloudformation.Properties) error {
	if v := cfnComputeString(p, "OverwriteChildResourcePermissionsWithDefault"); v != "" && v != "Deny" {
		return fmt.Errorf("overwriting child Lake Formation permissions requires its permission owner")
	}
	return nil
}
func cfnGlueTableAdmission(p cloudformation.Properties) error {
	if p["OpenTableFormatInput"] != nil {
		return fmt.Errorf("open table format creation requires its native table format owner")
	}
	return cfnGlueNameAdmission(p, "Name", "TableInput")
}
func cfnGlueNameAdmission(p cloudformation.Properties, top, nested string) error {
	a := cfnComputeString(p, top)
	v, _ := cfnComputeObject(p[nested])
	b := cfnComputeString(v, "Name")
	if a != "" && b != "" && !strings.EqualFold(a, b) {
		return fmt.Errorf("%s and %s.Name must identify the same resource", top, nested)
	}
	return nil
}
func (h cfnGlueDatabase) ReplacementInScope(scope cloudformation.Scope, a, b cloudformation.Properties) (bool, error) {
	ac, bc := cfnComputeString(a, "CatalogId"), cfnComputeString(b, "CatalogId")
	if ac == "" {
		ac = scope.Account
	}
	if bc == "" {
		bc = scope.Account
	}
	return ac != bc || cfnGlueNestedName(a, "DatabaseName", "DatabaseInput") != cfnGlueNestedName(b, "DatabaseName", "DatabaseInput"), h.Validate(b)
}
func (h cfnGlueTable) ReplacementInScope(scope cloudformation.Scope, a, b cloudformation.Properties) (bool, error) {
	ac, bc := cfnComputeString(a, "CatalogId"), cfnComputeString(b, "CatalogId")
	if ac == "" {
		ac = scope.Account
	}
	if bc == "" {
		bc = scope.Account
	}
	return ac != bc || !strings.EqualFold(cfnComputeString(a, "DatabaseName"), cfnComputeString(b, "DatabaseName")) || cfnGlueNestedName(a, "Name", "TableInput") != cfnGlueNestedName(b, "Name", "TableInput"), h.Validate(b)
}
func cfnGlueEncryptionInput(value any) map[string]any {
	p, _ := cfnComputeObject(value)
	out := cfnComputeCopy(p, "CloudWatchEncryption", "JobBookmarksEncryption")
	if v, ok := p["S3Encryptions"]; ok {
		out["S3Encryption"] = v
	}
	return out
}
func cfnGlueDatabaseCatalogAdmission(p cloudformation.Properties) error {
	if id := cfnComputeString(p, "CatalogId"); id != "" {
		if len(id) != 12 {
			return fmt.Errorf("glue Database CatalogId must be a 12-digit AWS account ID")
		}
		for _, c := range id {
			if c < '0' || c > '9' {
				return fmt.Errorf("glue Database CatalogId must be a 12-digit AWS account ID")
			}
		}
	}
	return nil
}
func cfnGlueTriggerAdmission(p cloudformation.Properties) error {
	active, _ := p["StartOnCreation"].(bool)
	if active && cfnComputeString(p, "Type") == "ON_DEMAND" {
		return fmt.Errorf("StartOnCreation cannot activate an ON_DEMAND trigger")
	}
	return nil
}
func cfnGlueDatabaseCatalogID(r cloudformation.ResourceRequest) string {
	if r.CloudControl {
		return r.Scope.Account
	}
	return cfnGlueCatalogID(r)
}
