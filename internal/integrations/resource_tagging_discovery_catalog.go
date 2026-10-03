package integrations

import (
	"context"

	"stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayv2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/glue"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
)

func (r ResourceTaggingResources) listTaggingGlue(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.Glue.View(ctx, func(tx glue.Reader) error {
		sc := glue.Scope(scope)
		appendDatabases := func(key glue.CatalogKey) error {
			rows, err := tx.Databases(key)
			if err != nil {
				return err
			}
			for _, row := range rows {
				out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "glue:database", Tags: row.Tags})
			}
			return nil
		}
		// The default catalog is implicit, but its databases are real resources.
		if err := appendDatabases(glue.CatalogKey{Scope: sc, CatalogID: scope.AccountID}); err != nil {
			return err
		}
		catalogs, err := tx.Catalogs(sc)
		if err != nil {
			return err
		}
		for _, row := range catalogs {
			if row.Key.CatalogID == scope.AccountID {
				continue
			}
			out = append(out, tagging.Resource{ARN: row.Key.ARN(), ResourceType: "glue:catalog", Tags: row.Tags})
			if err := appendDatabases(row.Key); err != nil {
				return err
			}
		}
		jobs, err := tx.ListJobs(sc)
		if err != nil {
			return err
		}
		for _, row := range jobs {
			out = append(out, tagging.Resource{ARN: row.Key.ARN("job"), ResourceType: "glue:job", Tags: row.Tags})
		}
		crawlers, err := tx.Crawlers(sc)
		if err != nil {
			return err
		}
		for _, row := range crawlers {
			out = append(out, tagging.Resource{ARN: row.Key.ARN("crawler"), ResourceType: "glue:crawler", Tags: row.Tags})
		}
		connections, err := tx.Connections(sc)
		if err != nil {
			return err
		}
		for _, row := range connections {
			out = append(out, tagging.Resource{ARN: row.Key.ARN("connection"), ResourceType: "glue:connection", Tags: row.Tags})
		}
		registries, err := tx.Registries(sc)
		if err != nil {
			return err
		}
		for _, row := range registries {
			out = append(out, tagging.Resource{ARN: row.Key.ARN("registry"), ResourceType: "glue:registry", Tags: row.Tags})
			schemas, err := tx.Schemas(sc, row.Key.Name)
			if err != nil {
				return err
			}
			for _, schema := range schemas {
				out = append(out, tagging.Resource{ARN: schema.Key.ARN(), ResourceType: "glue:schema", Tags: schema.Tags})
			}
		}
		workflows, err := tx.Workflows(sc)
		if err != nil {
			return err
		}
		for _, row := range workflows {
			out = append(out, tagging.Resource{ARN: row.Key.ARN("workflow"), ResourceType: "glue:workflow", Tags: row.Tags})
		}
		triggers, err := tx.Triggers(sc)
		if err != nil {
			return err
		}
		for _, row := range triggers {
			out = append(out, tagging.Resource{ARN: row.Key.ARN("trigger"), ResourceType: "glue:trigger", Tags: row.Tags})
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingAPIGateway(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	owner := scope
	owner.AccountID = ""
	appendResource := func(path, kind string, tags map[string]string) {
		out = append(out, tagging.Resource{ARN: resourceTaggingARN(owner, "apigateway", path), ResourceType: "apigateway:" + kind, Tags: tags})
	}
	err = r.Backends.APIGateway.View(ctx, func(tx apigateway.Reader) error {
		apis, err := tx.APIs(apigateway.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range apis {
			path := "/restapis/" + row.Key.ID
			appendResource(path, "restapis", row.Tags)
			stages, err := tx.Stages(row.Key)
			if err != nil {
				return err
			}
			for _, stage := range stages {
				appendResource(path+"/stages/"+stage.Key.Name, "restapis/stages", stage.Tags)
			}
		}
		keys, err := tx.ClientKeys(apigateway.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range keys {
			appendResource("/apikeys/"+row.Key.ID, "apikeys", row.Tags)
		}
		plans, err := tx.UsagePlans(apigateway.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range plans {
			appendResource("/usageplans/"+row.Key.ID, "usageplans", row.Tags)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = r.Backends.APIGatewayV2.View(ctx, func(tx apigatewayv2.Reader) error {
		apis, err := tx.APIs(apigatewayv2.Scope(scope))
		if err != nil {
			return err
		}
		for _, row := range apis {
			path := "/apis/" + row.Key.ID
			appendResource(path, "apis", row.Tags)
			stages, err := tx.Stages(row.Key)
			if err != nil {
				return err
			}
			for _, stage := range stages {
				appendResource(path+"/stages/"+stage.Key.ID, "apis/stages", stage.Tags)
			}
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingCloudFormation(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	err = r.Backends.CloudFormation.View(ctx, func(tx cloudformation.Reader) error {
		rows, err := tx.Stacks(cloudformation.Scope{Partition: scope.Partition, Account: scope.AccountID, Region: scope.Region})
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Deleted != nil || row.Status == "DELETE_COMPLETE" {
				continue
			}
			out = append(out, tagging.Resource{ARN: row.ID, ResourceType: "cloudformation:stack", Tags: row.Tags})
		}
		return nil
	})
	return
}
