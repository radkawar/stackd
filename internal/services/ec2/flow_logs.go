package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/ec2"
)

const defaultFlowLogFormat = "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}"

func registerFlowLogs(s *Service) {
	registerExternalOwnedCommand(s, "CreateFlowLogs", s.createFlowLogs)
	register(s, "DescribeFlowLogs", s.describeFlowLogs)
	register(s, "DeleteFlowLogs", s.deleteFlowLogs)
}

func flowLogRequest(in *api.CreateFlowLogsRequest) (FlowLogRecord, string, error) {
	r := FlowLogRecord{ResourceType: str(in.ResourceType), TrafficType: str(in.TrafficType), DestinationType: str(in.LogDestinationType), Destination: str(in.LogDestination), LogGroupName: str(in.LogGroupName), PermissionARN: str(in.DeliverLogsPermissionArn), LogFormat: str(in.LogFormat), AggregationSeconds: 600, Status: "ACTIVE", DeliveryStatus: "SUCCESS", Version: 1}
	if len(in.ResourceIds) == 0 {
		return r, "", failure("MissingParameter", "ResourceIds is required.")
	}
	if len(in.ResourceIds) > 300 {
		return r, "", failure("InvalidParameterValue", "At most 300 resources may be selected.")
	}
	if len(in.TagFieldSpecifications) > 0 || str(in.DeliverCrossAccountRole) != "" {
		// TODO: Comeback implement flow-log tag enrichment and cross-account delivery roles.
		return r, "", unsupported("Flow-log tag enrichment and cross-account delivery roles are not supported.")
	}
	switch r.ResourceType {
	case "VPC", "Subnet", "NetworkInterface":
	default:
		// TODO: Comeback implement Transit Gateway and regional NAT gateway flow-log sources.
		return r, "", unsupported("Flow logs for " + r.ResourceType + " resources are not supported.")
	}
	switch r.TrafficType {
	case "ACCEPT", "REJECT", "ALL":
	default:
		return r, "", failure("InvalidParameterValue", "TrafficType must be ACCEPT, REJECT, or ALL.")
	}
	if in.MaxAggregationInterval != nil {
		r.AggregationSeconds = int(*in.MaxAggregationInterval)
	}
	if r.AggregationSeconds != 60 && r.AggregationSeconds != 600 {
		return r, "", failure("InvalidParameterValue", "MaxAggregationInterval must be 60 or 600 seconds.")
	}
	if r.DestinationType == "" {
		r.DestinationType = "cloud-watch-logs"
	}
	if r.DestinationType != "cloud-watch-logs" && r.DestinationType != "s3" {
		// TODO: Comeback implement Firehose flow-log delivery.
		return r, "", unsupported("The flow-log destination type is not supported.")
	}
	if in.DestinationOptions != nil {
		o := in.DestinationOptions
		if r.DestinationType != "s3" {
			return r, "", failure("InvalidParameterCombination", "DestinationOptions requires S3.")
		}
		if str(o.FileFormat) != "" && str(o.FileFormat) != "plain-text" {
			// TODO: Comeback implement Parquet flow-log delivery.
			return r, "", unsupported("Parquet flow-log delivery is not supported.")
		}
		r.HivePartitions, r.HourPartitions = boolValue(o.HiveCompatiblePartitions), boolValue(o.PerHourPartition)
	}
	if r.DestinationType == "cloud-watch-logs" {
		if r.PermissionARN == "" {
			return r, "", failure("MissingParameter", "DeliverLogsPermissionArn is required for CloudWatch Logs.")
		}
		if (r.Destination == "") == (r.LogGroupName == "") {
			return r, "", failure("InvalidParameterCombination", "Specify exactly one of LogDestination or LogGroupName.")
		}
	} else if r.Destination == "" || r.LogGroupName != "" || r.PermissionARN != "" {
		return r, "", failure("InvalidParameterCombination", "S3 requires LogDestination and does not accept LogGroupName or DeliverLogsPermissionArn.")
	}
	if r.Destination != "" {
		a, e := arn.Parse(r.Destination)
		if e != nil || (r.DestinationType == "s3" && (a.Service != "s3" || a.AccountID != "" || a.Region != "" || a.Resource == "")) || (r.DestinationType == "cloud-watch-logs" && (a.Service != "logs" || !strings.HasPrefix(a.Resource, "log-group:"))) {
			return r, "", failure("InvalidParameterValue", "LogDestination is not a valid destination ARN.")
		}
	}
	if r.LogFormat == "" {
		r.LogFormat = defaultFlowLogFormat
	}
	version, err := validateFlowLogFormat(r.LogFormat)
	if err != nil {
		return r, "", err
	}
	r.FormatVersion = version
	r.Tags, err = CreationTags(in.TagSpecifications, "vpc-flow-log")
	if err != nil {
		return r, "", err
	}
	token := str(in.ClientToken)
	if len(token) > 64 {
		return r, "", failure("InvalidParameterValue", "ClientToken must be at most 64 characters.")
	}
	return r, token, nil
}
func flowLogFingerprint(r FlowLogRecord, ids api.FlowLogResourceIds) string {
	copyIDs := stringsOf(ids)
	slices.Sort(copyIDs)
	b, _ := json.Marshal(struct {
		Record FlowLogRecord
		IDs    []string
	}{r, copyIDs})
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// Native EC2 groups admissions by scoped client token and selected record
// format, not by all request arguments. Existing group members keep their
// immutable traffic/destination/options; newly requested resources join it.
func flowLogAdmissionKey(scope Scope, token, format string) FlowLogTokenKey {
	sum := sha256.Sum256([]byte(format))
	return FlowLogTokenKey{Scope: scope, Token: fmt.Sprintf("%s:%x", token, sum)}
}

func flowLogLiveAdmissions(tx Reader, k FlowLogTokenKey) ([]FlowLogAdmissionResult, error) {
	record, err := tx.FlowLogToken(k)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	results := make([]FlowLogAdmissionResult, 0, len(record.Results))
	for _, result := range record.Results {
		if result.FlowLogID == "" {
			continue
		}
		if _, err := tx.FlowLog(ResourceKey{Scope: k.Scope, ID: result.FlowLogID}); errors.Is(err, ErrNotFound) {
			continue
		} else if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func flowLogDuplicate(a, b FlowLogRecord) bool {
	return a.ResourceID == b.ResourceID && a.ResourceType == b.ResourceType &&
		a.TrafficType == b.TrafficType && a.DestinationType == b.DestinationType &&
		a.Destination == b.Destination && a.LogGroupName == b.LogGroupName &&
		a.PermissionARN == b.PermissionARN && a.LogFormat == b.LogFormat &&
		a.AggregationSeconds == b.AggregationSeconds &&
		a.HivePartitions == b.HivePartitions && a.HourPartitions == b.HourPartitions
}

func scopeFlowLogDestination(ctx context.Context, r *FlowLogRecord) error {
	scope := scopeFor(ctx)
	if r.DestinationType == "s3" {
		destination, _ := arn.Parse(r.Destination)
		if destination.Partition != scope.Partition {
			return failure("InvalidParameterValue", "LogDestination must use the current AWS partition.")
		}
		return nil
	}
	role, err := arn.Parse(r.PermissionARN)
	if err != nil || role.Service != "iam" || role.Region != "" || !strings.HasPrefix(role.Resource, "role/") || strings.TrimPrefix(role.Resource, "role/") == "" {
		return failure("InvalidParameterValue", "DeliverLogsPermissionArn must identify an IAM role.")
	}
	if role.Partition != scope.Partition || role.AccountID != scope.AccountID {
		// TODO: Comeback implement cross-account flow-log delivery roles.
		return unsupported("Cross-account flow-log delivery roles are not supported.")
	}
	if r.Destination != "" {
		destination, _ := arn.Parse(r.Destination)
		if destination.Partition != scope.Partition || destination.Region != scope.Region || destination.AccountID != scope.AccountID {
			// TODO: Comeback implement cross-account or cross-region CloudWatch flow-log destinations.
			return unsupported("Cross-account or cross-region CloudWatch flow-log destinations are not supported.")
		}
		r.LogGroupName = strings.TrimSuffix(strings.TrimPrefix(destination.Resource, "log-group:"), ":*")
	}
	if r.LogGroupName == "" || strings.Contains(r.LogGroupName, ":") {
		return failure("InvalidParameterValue", "LogDestination must identify one CloudWatch log group.")
	}
	r.Destination = fmt.Sprintf("arn:%s:logs:%s:%s:log-group:%s", scope.Partition, scope.Region, scope.AccountID, r.LogGroupName)
	return nil
}
func flowLogResult(token string, results []FlowLogAdmissionResult) *api.CreateFlowLogsResult {
	out := &api.CreateFlowLogsResult{ClientToken: new(api.String(token)), FlowLogIds: api.ValueStringList{}, Unsuccessful: api.UnsuccessfulItemSet{}}
	for _, r := range results {
		if r.FlowLogID != "" {
			out.FlowLogIds = append(out.FlowLogIds, api.String(r.FlowLogID))
		} else {
			out.Unsuccessful = append(out.Unsuccessful, flowLogUnsuccessful(r.ResourceID, r.ErrorCode, r.ErrorMessage))
		}
	}
	return out
}
func flowLogUnsuccessful(id, code, message string) api.UnsuccessfulItem {
	return api.UnsuccessfulItem{ResourceId: new(api.String(id)), Error: &api.UnsuccessfulItemError{Code: new(api.String(code)), Message: new(api.String(message))}}
}
func (s *Service) admitFlowLog(ctx context.Context, tx Reader, r FlowLogRecord) error {
	if err := s.authorizeCreate(ctx, "CreateFlowLogs", "vpc-flow-log", "*", r.Tags); err != nil {
		return err
	}
	var err error
	switch r.ResourceType {
	case "VPC":
		_, err = tx.VPC(key(ctx, r.ResourceID))
	case "Subnet":
		_, err = tx.Subnet(key(ctx, r.ResourceID))
	case "NetworkInterface":
		_, err = tx.NetworkInterface(key(ctx, r.ResourceID))
	}
	if errors.Is(err, ErrNotFound) {
		kind := map[string]string{"VPC": "vpc", "Subnet": "subnet", "NetworkInterface": "network-interface"}[r.ResourceType]
		return missing(kind, r.ResourceID)
	}
	return err
}
func (s *Service) createFlowLogs(ctx context.Context, in *api.CreateFlowLogsRequest) (*api.CreateFlowLogsResult, error) {
	r, token, err := flowLogRequest(in)
	if err != nil {
		return nil, err
	}
	if err := scopeFlowLogDestination(ctx, &r); err != nil {
		return nil, err
	}
	fingerprint := flowLogFingerprint(r, in.ResourceIds)
	var replay *api.CreateFlowLogsResult
	planned := make(map[string]FlowLogRecord, len(in.ResourceIds))
	err = s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		if err := s.authorizeCreate(ctx, "CreateFlowLogs", "vpc-flow-log", "*", r.Tags); err != nil {
			return err
		}
		if err := dryRun(in.DryRun); err != nil {
			return err
		}
		if token == "" {
			var err error
			token, err = tx.NextID(scopeFor(ctx), "fl-token")
			if err != nil {
				return err
			}
		}
		results, err := flowLogLiveAdmissions(tx, flowLogAdmissionKey(scopeFor(ctx), token, r.LogFormat))
		if err != nil {
			return err
		}
		members := make(map[string]bool, len(results))
		for _, result := range results {
			members[result.ResourceID] = true
		}
		complete := true
		existing, err := tx.FlowLogs(scopeFor(ctx))
		if err != nil {
			return err
		}
		for _, raw := range in.ResourceIds {
			resourceID := string(raw)
			if members[resourceID] {
				continue
			}
			complete = false
			if _, exists := planned[resourceID]; exists {
				continue
			}
			candidate := r
			candidate.ResourceID = resourceID
			if err := s.admitFlowLog(ctx, tx, candidate); err != nil {
				rejected := wireError(err)
				if rejected.Code == "UnauthorizedOperation" || rejected.Code == "AuthFailure" {
					return err
				}
				continue
			}
			duplicate := false
			for _, old := range existing {
				if flowLogDuplicate(old, candidate) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			id, err := tx.NextID(scopeFor(ctx), "fl")
			if err != nil {
				return err
			}
			candidate.Key, candidate.Incarnation = key(ctx, id), id
			planned[resourceID] = candidate
		}
		if complete {
			replay = flowLogResult(token, results)
			return RecordExternalSuccess(ctx, replay)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if replay != nil {
		return replay, nil
	}
	if s.flowLogDestination == nil {
		return nil, unsupported("The flow-log destination adapter is unavailable.")
	}
	validated := make(map[string]bool, len(planned))
	candidates := make([]FlowLogRecord, 0, len(planned))
	for _, raw := range in.ResourceIds {
		if validated[string(raw)] {
			continue
		}
		validated[string(raw)] = true
		if candidate, exists := planned[string(raw)]; exists {
			if rejected := s.flowLogDestination.Validate(ctx, candidate); rejected != nil {
				return nil, rejected
			}
			candidates = append(candidates, candidate)
		}
	}
	readinessError := s.flowLogReadiness(ctx, candidates)

	var out *api.CreateFlowLogsResult
	err = s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		if err := s.authorizeCreate(ctx, "CreateFlowLogs", "vpc-flow-log", "*", r.Tags); err != nil {
			return err
		}
		admissionKey := flowLogAdmissionKey(scopeFor(ctx), token, r.LogFormat)
		results, err := flowLogLiveAdmissions(tx, admissionKey)
		if err != nil {
			return err
		}
		members := make(map[string]bool, len(results))
		for _, result := range results {
			members[result.ResourceID] = true
		}
		existing, err := tx.FlowLogs(scopeFor(ctx))
		if err != nil {
			return err
		}
		duplicates := 0
		for _, raw := range in.ResourceIds {
			resourceID := string(raw)
			if members[resourceID] {
				continue
			}
			members[resourceID] = true
			current := r
			current.ResourceID = resourceID
			if err := s.admitFlowLog(ctx, tx, current); err != nil {
				rejected := wireError(err)
				if rejected.Code == "UnauthorizedOperation" || rejected.Code == "AuthFailure" {
					return err
				}
				results = append(results, FlowLogAdmissionResult{ResourceID: resourceID, ErrorCode: rejected.Code, ErrorMessage: rejected.Message})
				continue
			}
			duplicate := false
			for _, old := range existing {
				if flowLogDuplicate(old, current) {
					duplicate = true
					break
				}
			}
			if duplicate {
				duplicates++
				results = append(results, FlowLogAdmissionResult{ResourceID: resourceID, ErrorCode: "FlowLogAlreadyExists", ErrorMessage: "A Flow Log with the same configuration and log destination already exists."})
				continue
			}
			candidate, exists := planned[resourceID]
			if !exists {
				return failure("InvalidParameterValue", "The resource changed during flow-log admission. Retry the request.")
			}
			current.Key, current.Incarnation = candidate.Key, candidate.Incarnation
			current.CreatedAt = s.clock.Now().UTC()
			if readinessError != nil {
				current.CaptureError = readinessError.Error()
			}
			reconcileFlowLogStatus(&current)
			if err := tx.PutFlowLog(current); err != nil {
				return err
			}
			results = append(results, FlowLogAdmissionResult{ResourceID: resourceID, FlowLogID: current.Key.ID})
			existing = append(existing, current)
		}
		if duplicates > 0 && duplicates == len(results) {
			return failure("FlowLogAlreadyExists", "A Flow Log with the same configuration and log destination already exists.")
		}
		if err := tx.PutFlowLogToken(FlowLogTokenRecord{Key: admissionKey, Fingerprint: fingerprint, Results: results}); err != nil {
			return err
		}
		state, err := tx.FlowLogCaptureState()
		if errors.Is(err, ErrNotFound) {
			state = FlowLogCaptureState{Due: s.clock.Now(), Version: 1}
		} else if err != nil {
			return err
		} else {
			// A concurrent Read must not checkpoint past a newly admitted
			// selector whose desired bindings were absent from that Read.
			state.Due, state.Version = s.clock.Now(), state.Version+1
		}
		if err := tx.PutFlowLogCaptureState(state); err != nil {
			return err
		}
		out = flowLogResult(token, results)
		return RecordExternalSuccess(ctx, out)
	})
	return out, err
}
func flowLogAPI(v FlowLogRecord) api.FlowLog {
	out := api.FlowLog{FlowLogId: new(api.String(v.Key.ID)), CreationTime: new(api.MillisecondDateTime(v.CreatedAt)), ResourceId: new(api.String(v.ResourceID)), TrafficType: new(api.TrafficType(v.TrafficType)), FlowLogStatus: new(api.String(v.Status)), DeliverLogsStatus: new(api.String(v.DeliveryStatus)), LogDestinationType: new(api.LogDestinationType(v.DestinationType)), LogFormat: new(api.String(v.LogFormat)), MaxAggregationInterval: new(api.Integer(v.AggregationSeconds)), Tags: api.CloneTagList(v.Tags)}
	if v.CaptureError != "" {
		v.DeliveryError = "Capture: " + v.CaptureError
	}
	if v.Destination != "" {
		out.LogDestination = new(api.String(v.Destination))
	}
	if v.LogGroupName != "" {
		out.LogGroupName = new(api.String(v.LogGroupName))
	}
	if v.PermissionARN != "" {
		out.DeliverLogsPermissionArn = new(api.String(v.PermissionARN))
	}
	if v.DeliveryError != "" {
		out.DeliverLogsErrorMessage = new(api.String(v.DeliveryError))
	}
	if v.DestinationType == "s3" {
		out.DestinationOptions = &api.DestinationOptionsResponse{FileFormat: new(api.DestinationFileFormat("plain-text")), HiveCompatiblePartitions: new(api.Boolean(v.HivePartitions)), PerHourPartition: new(api.Boolean(v.HourPartitions))}
	}
	return out
}
func (s *Service) describeFlowLogs(ctx context.Context, tx Transaction, in *api.DescribeFlowLogsRequest) (*api.DescribeFlowLogsResult, error) {
	if e := s.authorize(ctx, "DescribeFlowLogs", "", "", nil); e != nil {
		return nil, e
	}
	if e := dryRun(in.DryRun); e != nil {
		return nil, e
	}
	records, e := tx.FlowLogs(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	items := make([]pageItem, 0, len(records))
	byID := map[string]FlowLogRecord{}
	for _, r := range records {
		byID[r.Key.ID] = r
		items = append(items, pageItem{ID: r.Key.ID, Tags: r.Tags, Fields: map[string][]string{"flow-log-id": {r.Key.ID}, "resource-id": {r.ResourceID}, "traffic-type": {r.TrafficType}, "log-destination-type": {r.DestinationType}, "log-group-name": {r.LogGroupName}, "deliver-log-status": {r.DeliveryStatus}, "log-status": {r.Status}}})
	}
	if in.MaxResults != nil && (*in.MaxResults < 5 || *in.MaxResults > 1000) {
		return nil, failure("InvalidParameterValue", "MaxResults must be between 5 and 1000.")
	}
	ids, next, e := selectPageItems(ctx, "DescribeFlowLogs", stringsOf(in.FlowLogIds), in.Filter, maxResults(in.MaxResults), in.NextToken, items)
	if e != nil {
		return nil, e
	}
	out := &api.DescribeFlowLogsResult{FlowLogs: api.FlowLogSet{}, NextToken: next}
	for _, id := range ids {
		out.FlowLogs = append(out.FlowLogs, flowLogAPI(byID[id]))
	}
	return out, nil
}
func (s *Service) deleteFlowLogs(ctx context.Context, tx Transaction, in *api.DeleteFlowLogsRequest) (*api.DeleteFlowLogsResult, error) {
	if len(in.FlowLogIds) > 1000 {
		return nil, failure("InvalidParameterValue", "At most 1000 flow log IDs may be deleted.")
	}
	if len(in.FlowLogIds) == 0 {
		return nil, failure("MissingParameter", "FlowLogIds is required.")
	}
	out := &api.DeleteFlowLogsResult{Unsuccessful: api.UnsuccessfulItemSet{}}
	records := []FlowLogRecord{}
	seen := map[string]bool{}
	for _, raw := range in.FlowLogIds {
		id := string(raw)
		if seen[id] {
			continue
		}
		seen[id] = true
		r, e := tx.FlowLog(key(ctx, id))
		if errors.Is(e, ErrNotFound) {
			out.Unsuccessful = append(out.Unsuccessful, flowLogUnsuccessful(id, "InvalidFlowLogId.NotFound", "Flow log does not exist."))
			continue
		}
		if e != nil {
			return nil, e
		}
		if e = s.authorize(ctx, "DeleteFlowLogs", "vpc-flow-log", id, r.Tags); e != nil {
			return nil, e
		}
		records = append(records, r)
	}
	if len(records) == 0 {
		if e := s.authorize(ctx, "DeleteFlowLogs", "vpc-flow-log", "*", nil); e != nil {
			return nil, e
		}
	}
	if e := dryRun(in.DryRun); e != nil {
		return nil, e
	}
	for _, r := range records {
		if e := tx.DeleteFlowLog(r.Key); e != nil {
			return nil, e
		}
	}
	if state, e := tx.FlowLogCaptureState(); e == nil {
		state.Due = s.clock.Now()
		state.Version++
		if e = tx.PutFlowLogCaptureState(state); e != nil {
			return nil, e
		}
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	return out, nil
}
