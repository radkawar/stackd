package appconfig

import (
	"fmt"
	"math"

	api "stackd/internal/awsapi/appconfig"
)

func experimentTreatmentInputs(in api.TreatmentInputList) ([]ExperimentTreatment, error) {
	if len(in) < 1 || len(in) > 5 {
		return nil, failure("BadRequestException", "An experiment must define between one and five treatments.")
	}
	out := make([]ExperimentTreatment, len(in))
	for i := range in {
		t, e := experimentTreatmentInput(&in[i], fmt.Sprintf("t%d", i+1))
		if e != nil {
			return nil, e
		}
		out[i] = t
	}
	return out, nil
}
func experimentTreatmentInput(in *api.TreatmentInput, key string) (ExperimentTreatment, error) {
	out := ExperimentTreatment{Key: key, Attributes: map[string]ExperimentAttribute{}}
	if in == nil || in.FlagValue == nil || in.FlagValue.Enabled == nil || in.Weight == nil {
		return out, failure("BadRequestException", "Treatments require FlagValue.Enabled and Weight.")
	}
	out.Description = value(in.Description)
	out.Weight = float64(*in.Weight)
	out.Enabled = boolean(in.FlagValue.Enabled)
	if math.IsNaN(out.Weight) || math.IsInf(out.Weight, 0) || out.Weight < 0 || out.Weight > 100 {
		return out, failure("BadRequestException", "Treatment weight must be between 0 and 100.")
	}
	for k, v := range in.FlagValue.AttributeValues {
		a := ExperimentAttribute{}
		count := 0
		if v.BooleanValue != nil {
			count++
			a.Kind = "boolean"
			a.Boolean = boolean(v.BooleanValue)
		}
		if v.NumberValue != nil {
			count++
			a.Kind = "number"
			a.Number = float64(*v.NumberValue)
			if math.IsNaN(a.Number) || math.IsInf(a.Number, 0) {
				return out, failure("BadRequestException", "Attribute numbers must be finite.")
			}
		}
		if v.StringValue != nil {
			count++
			a.Kind = "string"
			a.String = value(v.StringValue)
		}
		if v.NumberArray != nil {
			count++
			a.Kind = "numbers"
			a.Numbers = make([]float64, len(v.NumberArray))
			for i, n := range v.NumberArray {
				a.Numbers[i] = float64(n)
				if math.IsNaN(float64(n)) || math.IsInf(float64(n), 0) {
					return out, failure("BadRequestException", "Attribute numbers must be finite.")
				}
			}
		}
		if v.StringArray != nil {
			count++
			a.Kind = "strings"
			a.Strings = make([]string, len(v.StringArray))
			for i, s := range v.StringArray {
				a.Strings[i] = string(s)
			}
		}
		if count != 1 {
			return out, failure("BadRequestException", "AttributeValue must contain exactly one union member.")
		}
		out.Attributes[string(k)] = a
	}
	return out, nil
}
func experimentTreatmentOutput(t ExperimentTreatment) api.Treatment {
	out := api.Treatment{Key: new(api.TreatmentKey(t.Key)), Description: deployOptional[api.Description](t.Description), Weight: new(api.Weight(t.Weight)), FlagValue: &api.FlagValue{Enabled: new(api.Boolean(t.Enabled))}}
	if len(t.Attributes) > 0 {
		out.FlagValue.AttributeValues = api.AttributeValueMap{}
	}
	for k, a := range t.Attributes {
		v := api.AttributeValue{}
		switch a.Kind {
		case "boolean":
			v.BooleanValue = new(api.Boolean(a.Boolean))
		case "number":
			v.NumberValue = new(api.Double(a.Number))
		case "string":
			v.StringValue = new(api.AttributeString(a.String))
		case "numbers":
			v.NumberArray = make(api.NumberList, len(a.Numbers))
			for i, n := range a.Numbers {
				v.NumberArray[i] = api.Double(n)
			}
		case "strings":
			v.StringArray = make(api.StringList, len(a.Strings))
			for i, s := range a.Strings {
				v.StringArray[i] = api.AttributeString(s)
			}
		}
		out.FlagValue.AttributeValues[api.AttributeKey(k)] = v
	}
	return out
}
func experimentDefinitionOutput(d ExperimentDefinition) api.ExperimentDefinition {
	control := experimentTreatmentOutput(d.Control)
	out := api.ExperimentDefinition{ApplicationId: new(api.Id(d.ApplicationID)), Id: new(api.Id(d.ID)), Name: new(api.Name(d.Name)), EnvironmentId: new(api.Id(d.EnvironmentID)), ConfigurationProfileId: new(api.Id(d.ProfileID)), FlagKey: new(api.FlagKey(d.FlagKey)), AudienceRule: new(api.Rule(d.AudienceRule)), AudienceDescription: deployOptional[api.Description](d.AudienceDescription), Hypothesis: deployOptional[api.Description](d.Hypothesis), LaunchCriteria: deployOptional[api.Description](d.LaunchCriteria), KmsKeyIdentifier: deployOptional[api.KmsKeyIdentifier](d.KMSKeyIdentifier), Status: new(api.ExperimentDefinitionStatus(d.Status)), CreatedAt: new(d.CreatedAt), UpdatedAt: new(d.UpdatedAt), Control: &control, Treatments: api.TreatmentList{}}
	for _, t := range d.Treatments {
		out.Treatments = append(out.Treatments, experimentTreatmentOutput(t))
	}
	return out
}
func experimentOverridesOutput(in map[string]string) *api.TreatmentOverrides {
	if in == nil {
		return nil
	}
	out := &api.TreatmentOverrides{Inline: api.TreatmentOverrideMap{}}
	for k, v := range in {
		out.Inline[api.EntityId(k)] = api.TreatmentKey(v)
	}
	return out
}
func experimentRunOutput(r ExperimentRun) api.ExperimentRun {
	d := experimentDefinitionOutput(r.Snapshot)
	out := api.ExperimentRun{ApplicationId: new(api.Id(r.ApplicationID)), ExperimentDefinitionId: new(api.Id(r.DefinitionID)), Run: new(api.Integer(r.Number)), Description: deployOptional[api.Description](r.Description), Status: new(api.ExperimentRunStatus(r.Status)), ExposurePercentage: new(api.NullablePercentage(r.Exposure)), StartedAt: new(r.StartedAt), UpdatedAt: new(r.UpdatedAt), TreatmentOverrides: experimentOverridesOutput(r.Overrides), ExperimentDefinitionSnapshot: &api.ExperimentDefinitionSnapshot{ApplicationId: d.ApplicationId, AudienceDescription: d.AudienceDescription, AudienceRule: d.AudienceRule, ConfigurationProfileId: d.ConfigurationProfileId, Control: d.Control, EnvironmentId: d.EnvironmentId, FlagKey: d.FlagKey, Hypothesis: d.Hypothesis, Id: d.Id, LaunchCriteria: d.LaunchCriteria, Name: d.Name, Treatments: d.Treatments}}
	if !r.EndedAt.IsZero() {
		out.EndedAt = new(r.EndedAt)
	}
	if r.Result != nil {
		out.Result = &api.ExperimentRunResult{ExecutiveSummary: deployOptional[api.Description](r.Result.ExecutiveSummary), ReasonsToLaunch: deployOptional[api.Description](r.Result.ReasonsToLaunch), ReasonsNotToLaunch: deployOptional[api.Description](r.Result.ReasonsNotToLaunch)}
	}
	return out
}
func experimentOverridesInput(in *api.TreatmentOverrides, d ExperimentDefinition) (map[string]string, error) {
	if in == nil {
		return nil, nil
	}
	if in.Inline == nil {
		return nil, failure("BadRequestException", "TreatmentOverrides requires Inline.")
	}
	out := make(map[string]string, len(in.Inline))
	for id, key := range in.Inline {
		valid := string(key) == d.Control.Key
		for _, t := range d.Treatments {
			valid = valid || string(key) == t.Key
		}
		if !valid {
			return nil, failure("BadRequestException", "Treatment override refers to an unknown treatment: "+string(key))
		}
		out[string(id)] = string(key)
	}
	return out, nil
}
