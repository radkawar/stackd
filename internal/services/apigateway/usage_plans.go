package apigateway

import (
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/apigateway"
)

func usageThrottleOutput(throttle UsageThrottle) api.ThrottleSettings {
	return api.ThrottleSettings{BurstLimit: new(api.Integer(throttle.Burst)), RateLimit: new(api.Double(throttle.Rate))}
}

func usagePlanOutput(row UsagePlanRecord) *api.UsagePlan {
	out := &api.UsagePlan{Id: ptr(row.Key.ID), Name: ptr(row.Name), Description: (*api.String)(row.Description), ApiStages: make(api.ListOfApiStage, 0, len(row.Stages)), Tags: mapOut(row.Tags)}
	if row.Throttle != nil {
		out.Throttle = new(usageThrottleOutput(*row.Throttle))
	}
	if row.Quota != nil {
		out.Quota = &api.QuotaSettings{Limit: new(api.Integer(row.Quota.Limit)), Offset: new(api.Integer(row.Quota.Offset)), Period: new(api.QuotaPeriodType(row.Quota.Period))}
	}
	for _, stage := range row.Stages {
		outStage := api.ApiStage{ApiId: ptr(stage.Key.ID), Stage: ptr(stage.Key.Name)}
		if stage.Throttle != nil {
			outStage.Throttle = make(api.MapOfApiStageThrottleSettings, len(stage.Throttle))
			for method, throttle := range stage.Throttle {
				outStage.Throttle[api.String(method)] = usageThrottleOutput(throttle)
			}
		}
		out.ApiStages = append(out.ApiStages, outStage)
	}
	return out
}

func (s *Service) usagePlan(r Reader, id, verb, suffix string) (UsagePlanRecord, error) {
	row, err := r.UsagePlan(PlanKey{Scope: scopeFor(r.Context()), ID: id})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return row, err
	}
	if rejected := s.authorize(r, verb, "/usageplans/"+id+suffix, row.Tags); rejected != nil {
		return UsagePlanRecord{}, rejected
	}
	return row, err
}

func (s *Service) createUsagePlan(tx Transaction, in *api.CreateUsagePlanRequest) (*api.UsagePlan, error) {
	if err := s.authorize(tx, "POST", "/usageplans", nil); err != nil {
		return nil, err
	}
	if value(in.Name) == "" {
		return nil, bad("Usage plan name is required")
	}
	row := UsagePlanRecord{Key: PlanKey{Scope: scopeFor(tx.Context())}, Name: value(in.Name), Description: (*string)(optional(value(in.Description))), Tags: mapIn(in.Tags), Stages: make([]UsagePlanStage, 0, len(in.ApiStages))}
	if err := validateTags(row.Tags); err != nil {
		return nil, err
	}
	if in.Throttle != nil {
		throttle, err := usageThrottleIn(*in.Throttle)
		if err != nil {
			return nil, err
		}
		row.Throttle = &throttle
	}
	if in.Quota != nil {
		period := UsagePeriod(value(in.Quota.Period))
		limit := in.Quota.Limit
		// The published model defaults limit to zero, but native creation
		// requires it on the wire. Keep presence separate from that default.
		if request, ok := awsapi.FromContext(tx.Context()); ok && len(request.Body) != 0 {
			var body struct {
				Quota struct {
					Limit *api.Integer `json:"limit"`
				} `json:"quota"`
			}
			if err := json.Unmarshal(request.Body, &body); err != nil {
				return nil, err
			}
			limit = body.Quota.Limit
		}
		if limit == nil {
			return nil, bad("Usage Plan quota limit must be a non-negative numeric")
		}
		row.Quota = &UsageQuota{Limit: int32(*limit), Period: period}
		if in.Quota.Offset != nil {
			row.Quota.Offset = int32(*in.Quota.Offset)
		}
	}
	for _, inStage := range in.ApiStages {
		stage := UsagePlanStage{Key: StageKey{APIKey: APIKey{Scope: row.Key.Scope, ID: value(inStage.ApiId)}, Name: value(inStage.Stage)}}
		if _, err := tx.Stage(stage.Key); err != nil {
			return nil, err
		}
		if slices.ContainsFunc(row.Stages, func(v UsagePlanStage) bool { return v.Key == stage.Key }) {
			return nil, conflict("API stage is already associated with this usage plan")
		}
		var err error
		stage.Throttle, err = usageStageThrottleIn(tx, stage.Key, inStage.Throttle)
		if err != nil {
			return nil, err
		}
		row.Stages = append(row.Stages, stage)
	}
	if err := validUsagePlanSettings(row); err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	row.Key.ID = id
	if _, err := tx.UsagePlan(row.Key); err == nil {
		return nil, conflict("Usage plan identifier already exists")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err := tx.PutUsagePlan(row); err != nil {
		return nil, err
	}
	return usagePlanOutput(row), nil
}

func (s *Service) getUsagePlan(tx Transaction, in *api.GetUsagePlanRequest) (*api.UsagePlan, error) {
	row, err := s.usagePlan(tx, value(in.UsagePlanId), "GET", "")
	if err != nil {
		return nil, err
	}
	out := usagePlanOutput(row)
	if out.Tags == nil {
		out.Tags = api.MapOfStringToString{}
	}
	return out, nil
}

func (s *Service) getUsagePlans(tx Transaction, in *api.GetUsagePlansRequest) (*api.UsagePlans, error) {
	if err := s.authorize(tx, "GET", "/usageplans", nil); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	var rows []UsagePlanRecord
	var err error
	collection := "usageplans"
	if in.KeyId != nil {
		rows, err = tx.UsagePlansForKey(ClientKey{Scope: scope, ID: value(in.KeyId)})
		collection += "?key=" + value(in.KeyId)
	} else {
		rows, err = tx.UsagePlans(scope)
	}
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, scope, collection, in.Limit, in.Position, func(row UsagePlanRecord) string { return row.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.UsagePlans{Items: make(api.ListOfUsagePlan, 0, len(rows)), Position: next}
	for _, row := range rows {
		out.Items = append(out.Items, *usagePlanOutput(row))
	}
	return out, nil
}

func (s *Service) deleteUsagePlan(tx Transaction, in *api.DeleteUsagePlanRequest) (*api.Unit, error) {
	row, err := s.usagePlan(tx, value(in.UsagePlanId), "DELETE", "")
	if err != nil {
		return nil, err
	}
	if len(row.Stages) != 0 {
		return nil, bad("Cannot delete a usage plan with associated API stages")
	}
	if err := tx.DeleteUsagePlan(row.Key); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}

func (s *Service) updateUsagePlan(tx Transaction, in *api.UpdateUsagePlanRequest) (*api.UsagePlan, error) {
	row, err := s.usagePlan(tx, value(in.UsagePlanId), "PATCH", "")
	if err != nil {
		return nil, err
	}
	stagesChanged := false
	// Repositories return detached rows. No write occurs until every patch and
	// the final cross-field and membership constraints have been admitted.
	for _, patch := range in.PatchOperations {
		path := value(patch.Path)
		if patch.From != nil {
			return nil, bad("Invalid patch operation for " + path)
		}
		switch path {
		case "/name":
			if err := replace(patch, &row.Name); err != nil {
				return nil, err
			}
			if row.Name == "" {
				return nil, bad("Usage plan name is required")
			}
		case "/description":
			var description string
			if err := replace(patch, &description); err != nil {
				return nil, err
			}
			row.Description = (*string)(optional(description))
		case "/throttle":
			if value(patch.Op) != "remove" {
				return nil, bad("Invalid patch operation for " + path)
			}
			row.Throttle = nil
		case "/throttle/rateLimit", "/throttle/burstLimit":
			if row.Throttle == nil {
				row.Throttle = &UsageThrottle{}
			}
			if err := patchUsageThrottle(patch, strings.TrimPrefix(path, "/throttle/"), row.Throttle); err != nil {
				return nil, err
			}
		case "/quota":
			if value(patch.Op) != "remove" {
				return nil, bad("Invalid patch operation for " + path)
			}
			row.Quota = nil
		case "/quota/limit", "/quota/offset", "/quota/period":
			if row.Quota == nil {
				row.Quota = &UsageQuota{Limit: -1}
			}
			if err := patchUsageQuota(patch, strings.TrimPrefix(path, "/quota/"), row.Quota); err != nil {
				return nil, err
			}
		case "/apiStages":
			if err := patchUsageStages(tx, patch, &row); err != nil {
				return nil, err
			}
			stagesChanged = true
		case "/productCode":
			// TODO: Comeback implement Marketplace product associations with
			// their subscription authority, not an unattached product-code field.
			return nil, unsupported("AWS Marketplace usage plans")
		default:
			if !strings.HasPrefix(path, "/apiStages/") {
				return nil, bad("Invalid usage plan patch path " + path)
			}
			if err := patchUsageStageThrottle(tx, patch, &row); err != nil {
				return nil, err
			}
		}
	}
	if err := validUsagePlanSettings(row); err != nil {
		return nil, err
	}
	if stagesChanged {
		keys, err := tx.UsagePlanKeys(row.Key)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			if err := usagePlanStageConflict(tx, row, key.Key); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.PutUsagePlan(row); err != nil {
		return nil, err
	}
	out := usagePlanOutput(row)
	if out.Tags == nil {
		out.Tags = api.MapOfStringToString{}
	}
	return out, nil
}

func usageThrottleIn(in api.ThrottleSettings) (UsageThrottle, error) {
	var throttle UsageThrottle
	if in.BurstLimit != nil {
		throttle.Burst = int32(*in.BurstLimit)
	}
	if in.RateLimit != nil {
		throttle.Rate = float64(*in.RateLimit)
	}
	return throttle, validUsageThrottle(throttle)
}

func validUsageThrottle(throttle UsageThrottle) error {
	if throttle.Burst < 0 || throttle.Rate < 0 || math.IsNaN(throttle.Rate) || math.IsInf(throttle.Rate, 0) {
		return bad("Usage plan throttle limits must be non-negative numbers")
	}
	return nil
}

func validUsagePlanSettings(row UsagePlanRecord) error {
	if quota := row.Quota; quota != nil {
		if quota.Limit < 0 || quota.Offset < 0 {
			return bad("Usage plan quota limit and offset must be non-negative integers")
		}
		if quota.Period != UsageDay && quota.Period != UsageWeek && quota.Period != UsageMonth {
			return bad("Invalid Usage Plan quota period specified. Must be one of [DAY, WEEK, MONTH]")
		}
		if quota.Period == UsageDay && quota.Offset != 0 {
			return bad("Usage Plan quota offset must be zero in the DAY period")
		}
	}
	for _, stage := range row.Stages {
		if stage.Throttle != nil && row.Throttle == nil {
			return bad("Usage plan throttle settings are required for method throttles")
		}
	}
	return nil
}

func patchUsageThrottle(patch api.PatchOperation, field string, throttle *UsageThrottle) error {
	var text string
	if err := patchString(patch, &text, "add", "replace"); err != nil {
		return err
	}
	switch field {
	case "burstLimit":
		value, err := strconv.ParseInt(text, 10, 32)
		if err != nil {
			return bad("Usage plan burst limit must be a non-negative integer")
		}
		throttle.Burst = int32(value)
	case "rateLimit":
		value, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return bad("Usage plan rate limit must be a non-negative number")
		}
		throttle.Rate = value
	default:
		return bad("Invalid usage plan throttle setting")
	}
	return validUsageThrottle(*throttle)
}

func patchUsageQuota(patch api.PatchOperation, field string, quota *UsageQuota) error {
	var text string
	if err := patchString(patch, &text, "add", "replace"); err != nil {
		return err
	}
	if field == "period" {
		quota.Period = UsagePeriod(text)
		return nil
	}
	value, err := strconv.ParseInt(text, 10, 32)
	if err != nil {
		return bad("Usage plan quota limit and offset must be non-negative integers")
	}
	if field == "limit" {
		quota.Limit = int32(value)
	} else {
		quota.Offset = int32(value)
	}
	return nil
}

func usageStageKey(scope Scope, text string) (StageKey, error) {
	id, name, ok := strings.Cut(text, ":")
	if !ok || id == "" || name == "" || strings.Contains(name, ":") {
		return StageKey{}, bad("API stage must have the form apiId:stageName")
	}
	return StageKey{APIKey: APIKey{Scope: scope, ID: id}, Name: name}, nil
}

func patchUsageStages(tx Transaction, patch api.PatchOperation, row *UsagePlanRecord) error {
	var text string
	if err := patchString(patch, &text, "add", "remove"); err != nil {
		return err
	}
	// Unlike scalar removals, stage removals identify their member in value.
	key, err := usageStageKey(row.Key.Scope, value(patch.Value))
	if err != nil {
		return err
	}
	index := slices.IndexFunc(row.Stages, func(stage UsagePlanStage) bool { return stage.Key == key })
	if value(patch.Op) == "remove" {
		if index < 0 {
			return ErrNotFound
		}
		row.Stages = slices.Delete(row.Stages, index, index+1)
		return nil
	}
	if _, err := tx.Stage(key); err != nil {
		return err
	}
	if index >= 0 {
		return conflict("API stage is already associated with this usage plan")
	}
	row.Stages = append(row.Stages, UsagePlanStage{Key: key})
	return nil
}

func usageStageThrottleIn(r Reader, key StageKey, in api.MapOfApiStageThrottleSettings) (map[string]UsageThrottle, error) {
	if in == nil {
		return nil, nil
	}
	out := make(map[string]UsageThrottle, len(in))
	for method, settings := range in {
		if err := validUsageMethod(r, key, string(method)); err != nil {
			return nil, err
		}
		throttle, err := usageThrottleIn(settings)
		if err != nil {
			return nil, err
		}
		out[string(method)] = throttle
	}
	return out, nil
}

func validUsageMethod(r Reader, stage StageKey, method string) error {
	separator := strings.LastIndexByte(method, '/')
	if separator < 1 || !strings.HasPrefix(method, "/") || separator == len(method)-1 {
		return bad("Method throttle must identify a resource path and HTTP method")
	}
	path, verb := method[:separator], method[separator+1:]
	resources, err := r.Resources(stage.APIKey)
	if err != nil {
		return err
	}
	for _, resource := range resources {
		if resource.Path == path {
			_, err := r.Method(MethodKey{ResourceKey: resource.Key, HTTPMethod: verb})
			return err
		}
	}
	return ErrNotFound
}

func patchUsageStageThrottle(tx Transaction, patch api.PatchOperation, row *UsagePlanRecord) error {
	path := strings.TrimPrefix(value(patch.Path), "/apiStages/")
	stageText, tail, ok := strings.Cut(path, "/")
	if !ok || (tail != "throttle" && !strings.HasPrefix(tail, "throttle/")) {
		return bad("Invalid API stage throttle patch path")
	}
	key, err := usageStageKey(row.Key.Scope, stageText)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(row.Stages, func(stage UsagePlanStage) bool { return stage.Key == key })
	if index < 0 {
		return ErrNotFound
	}
	stage := &row.Stages[index]
	if tail == "throttle" {
		if value(patch.Op) == "remove" {
			stage.Throttle = nil
			return nil
		}
		var text string
		if err := patchString(patch, &text, "add", "replace"); err != nil {
			return err
		}
		var settings api.MapOfApiStageThrottleSettings
		if err := json.Unmarshal([]byte(text), &settings); err != nil || settings == nil {
			return bad("API stage throttle must be a JSON object")
		}
		throttle, err := usageStageThrottleIn(tx, key, settings)
		if err != nil {
			return err
		}
		stage.Throttle = throttle
		return nil
	}
	method := "/" + strings.TrimPrefix(tail, "throttle/")
	separator := strings.LastIndexByte(method, '/')
	field := method[separator+1:]
	if value(patch.Op) == "remove" {
		if field == "burstLimit" || field == "rateLimit" {
			return bad("Invalid patch operation for " + value(patch.Path))
		}
		if _, exists := stage.Throttle[method]; !exists {
			return ErrNotFound
		}
		delete(stage.Throttle, method)
		return nil
	}
	method = method[:separator]
	if field != "burstLimit" && field != "rateLimit" {
		return bad("Invalid API stage throttle patch path")
	}
	if err := validUsageMethod(tx, key, method); err != nil {
		return err
	}
	throttle := stage.Throttle[method]
	if err := patchUsageThrottle(patch, field, &throttle); err != nil {
		return err
	}
	if stage.Throttle == nil {
		stage.Throttle = make(map[string]UsageThrottle)
	}
	stage.Throttle[method] = throttle
	return nil
}
