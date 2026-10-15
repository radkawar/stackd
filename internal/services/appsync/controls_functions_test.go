package appsync

import (
	"testing"

	api "stackd/internal/awsapi/appsync"
)

func TestJavaScriptFunctionEmptyTemplateVersion(t *testing.T) {
	repository := NewMemoryRepository(nil)
	owner := APIRecord{Key: Key{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", ID: "api"}}
	function := api.FunctionConfiguration{Name: new(api.ResourceName("proof")), FunctionId: new(api.String("fn")), DataSourceName: new(api.ResourceName("none")), FunctionVersion: new(api.String("")), Runtime: &api.AppSyncRuntime{Name: new(api.RuntimeNameAPPSYNC_JS), RuntimeVersion: new(api.String("1.0.0"))}, Code: new(api.Code(`export function request(ctx){return {payload:ctx.args.input}} export function response(ctx){return ctx.result}`))}
	if err := repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutAPI(owner); err != nil {
			return err
		}
		if err := tx.PutDataSource(DataSourceRecord{API: owner.Key, DataSource: api.DataSource{Name: function.DataSourceName, Type: new(api.DataSourceTypeNONE)}}); err != nil {
			return err
		}
		if err := validateFunction(tx, owner, &function); err != nil {
			return err
		}
		if function.FunctionVersion != nil {
			t.Fatal("empty VTL version retained for a JavaScript function")
		}
		function.FunctionVersion = new(api.String("2018-05-29"))
		if err := validateFunction(tx, owner, &function); err == nil {
			t.Fatal("unsupported VTL configuration accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
