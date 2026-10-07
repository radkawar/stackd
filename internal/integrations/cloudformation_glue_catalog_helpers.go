package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
	"strings"
)

func cfnGlueCatalogID(r cloudformation.ResourceRequest) string {
	if id := cfnComputeString(r.Properties, "CatalogId"); id != "" {
		return id
	}
	return r.Scope.Account
}
func cfnGlueCatalogPath(r cloudformation.ResourceRequest, id string) string {
	return strings.TrimPrefix(strings.ReplaceAll(strings.TrimPrefix(id, r.Scope.Account), ":", "/"), "/")
}
func cfnGlueCatalogARN(r cloudformation.ResourceRequest, id string) string {
	arn := "arn:" + r.Scope.Partition + ":glue:" + r.Scope.Region + ":" + r.Scope.Account + ":catalog"
	if path := cfnGlueCatalogPath(r, id); path != "" {
		arn += "/" + path
	}
	return arn
}
func cfnGlueCatalogFromARN(r cloudformation.ResourceRequest, arn string) (string, error) {
	prefix := cfnGlueCatalogARN(r, r.Scope.Account)
	if arn == prefix {
		return r.Scope.Account, nil
	}
	if !strings.HasPrefix(arn, prefix+"/") {
		return "", fmt.Errorf("catalog ARN must identify the current account and region")
	}
	return r.Scope.Account + ":" + strings.ReplaceAll(strings.TrimPrefix(arn, prefix+"/"), "/", ":"), nil
}
func cfnGlueCatalogIDs(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest) ([]string, error) {
	ids := []string{r.Scope.Account}
	for i := 0; i < len(ids); i++ {
		input := map[string]any{"ParentCatalogId": ids[i]}
		for {
			out, err := cfnComputeCall[api.GetCatalogsOutput](ctx, c, "glue", "GetCatalogs", input)
			if err != nil {
				return nil, err
			}
			for _, v := range out.CatalogList {
				ids = append(ids, cfnComputeValue(v.CatalogId))
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["NextToken"] = out.NextToken
		}
	}
	return ids, nil
}
func cfnGlueDatabases(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest) ([]cloudformation.Properties, error) {
	ids, err := cfnGlueCatalogIDs(ctx, c, r)
	if err != nil {
		return nil, err
	}
	rows := []cloudformation.Properties{}
	for _, id := range ids {
		input := map[string]any{"CatalogId": id}
		for {
			out, err := cfnComputeCall[api.GetDatabasesOutput](ctx, c, "glue", "GetDatabases", input)
			if err != nil {
				return nil, err
			}
			for _, v := range out.DatabaseList {
				rows = append(rows, cloudformation.Properties{"CatalogId": id, "DatabaseName": cfnComputeValue(v.Name)})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["NextToken"] = out.NextToken
		}
	}
	return rows, nil
}
func cfnGlueTables(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest) ([]cloudformation.Properties, error) {
	dbs, err := cfnGlueDatabases(ctx, c, r)
	if err != nil {
		return nil, err
	}
	rows := []cloudformation.Properties{}
	for _, db := range dbs {
		input := map[string]any{"CatalogId": db["CatalogId"], "DatabaseName": db["DatabaseName"]}
		for {
			out, err := cfnComputeCall[api.GetTablesOutput](ctx, c, "glue", "GetTables", input)
			if err != nil {
				return nil, err
			}
			for _, v := range out.TableList {
				rows = append(rows, cloudformation.Properties{"CatalogId": db["CatalogId"], "DatabaseName": db["DatabaseName"], "Name": cfnComputeValue(v.Name)})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["NextToken"] = out.NextToken
		}
	}
	return rows, nil
}
func cfnGluePartitionValues(v any) (string, error) {
	body, err := json.Marshal(v)
	return string(body), err
}
func cfnGlueCompound(id string, count int) ([]string, error) {
	parts := strings.Split(id, "|")
	if len(parts) != count {
		return nil, fmt.Errorf("invalid compound Glue identifier")
	}
	for _, v := range parts {
		if v == "" {
			return nil, fmt.Errorf("empty Glue identifier component")
		}
	}
	return parts, nil
}
