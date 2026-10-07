package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-classifier.html
type cfnGlueClassifier struct{ commands StepFunctionsCommands }

func (h cfnGlueClassifier) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "XMLClassifier", "CsvClassifier", "GrokClassifier", "JsonClassifier"); err != nil {
		return err
	}
	count := 0
	for _, key := range []string{"XMLClassifier", "CsvClassifier", "GrokClassifier", "JsonClassifier"} {
		if _, ok := cfnComputeObject(p[key]); ok {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("exactly one classifier definition is required")
	}
	return cloudformation.ValidateResourceProperties("AWS::Glue::Classifier", p)
}
func cfnGlueClassifierName(p map[string]any) string {
	for _, key := range []string{"XMLClassifier", "CsvClassifier", "GrokClassifier", "JsonClassifier"} {
		if v, ok := cfnComputeObject(p[key]); ok {
			return cfnComputeString(v, "Name")
		}
	}
	return ""
}
func (h cfnGlueClassifier) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnGlueClassifierName(a) != cfnGlueClassifierName(b), h.Validate(b)
}
func (h cfnGlueClassifier) input(r cloudformation.ResourceRequest) (map[string]any, string) {
	name := r.PhysicalID
	if name == "" {
		name = cfnGlueClassifierName(r.Properties)
	}
	if name == "" {
		name = cfnComputeName(r, "Name", 255)
	}
	input := map[string]any{}
	for _, key := range []string{"XMLClassifier", "CsvClassifier", "GrokClassifier", "JsonClassifier"} {
		if v, ok := cfnComputeObject(r.Properties[key]); ok {
			body := map[string]any{}
			for k, v := range v {
				body[k] = v
			}
			body["Name"] = name
			if key == "CsvClassifier" {
				if datatypes, ok := body["ContainsCustomDatatype"]; ok {
					body["CustomDatatypes"] = datatypes
					delete(body, "ContainsCustomDatatype")
				}
			}
			input[key] = body
		}
	}
	return input, name
}
func (h cfnGlueClassifier) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input, name := h.input(r)
	r.PhysicalID = name
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Classifier")
	_, err := h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(name, name, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreateClassifier", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(name, name, nil), nil
}
func (h cfnGlueClassifier) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Classifier")
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input, name := h.input(r)
	return cfnAnalyticsResult(name, name, nil), cfnComputeRun(ctx, h.commands, "glue", "UpdateClassifier", input)
}
func (h cfnGlueClassifier) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Classifier")
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteClassifier", map[string]any{"Name": r.PhysicalID}))
}
func (h cfnGlueClassifier) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Classifier")
	out, err := cfnComputeCall[api.GetClassifierOutput](ctx, h.commands, "glue", "GetClassifier", map[string]any{"Name": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	p, err := cfnAnalyticsMap(out.Classifier)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"XMLClassifier", "CsvClassifier", "GrokClassifier", "JsonClassifier"} {
		if v, ok := cfnComputeObject(p[key]); ok {
			delete(v, "Version")
			delete(v, "CreationTime")
			delete(v, "LastUpdated")
			if key == "CsvClassifier" {
				if datatypes, ok := v["CustomDatatypes"]; ok {
					v["ContainsCustomDatatype"] = datatypes
					delete(v, "CustomDatatypes")
				}
				delete(v, "Serde")
			}
		}
	}
	p["Name"] = r.PhysicalID
	return p, nil
}
func (h cfnGlueClassifier) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.GetClassifiersOutput](ctx, h.commands, "glue", "GetClassifiers", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Classifiers {
			p, err := cfnAnalyticsMap(v)
			if err != nil {
				return nil, err
			}
			r.PhysicalID = cfnGlueClassifierName(p)
			p, err = h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			break
		}
		input["NextToken"] = out.NextToken
	}
	return cfnAnalyticsSort(rows), nil
}
