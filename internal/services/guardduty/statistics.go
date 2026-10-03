package guardduty

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/guardduty"
)

type statisticKey struct {
	text, account, resourceType string
	severity                    float64
	day                         int64
}
type statistic struct {
	key   statisticKey
	count int32
	last  time.Time
}

func (s *Service) getFindingsStatistics(tx Transaction, in *api.GetFindingsStatisticsInput) (*api.GetFindingsStatisticsOutput, error) {
	d, err := s.loadDetector(tx, value(in.DetectorId), "GetFindingsStatistics")
	if err != nil {
		return nil, err
	}
	group := value(in.GroupBy)
	legacy := len(in.FindingStatisticTypes) > 0
	if legacy == (group != "") {
		return nil, invalid("Specify either findingStatisticTypes or groupBy, not both")
	}
	if legacy {
		if in.MaxResults != nil || in.OrderBy != nil {
			return nil, invalid("maxResults and orderBy require groupBy")
		}
		for _, kind := range in.FindingStatisticTypes {
			if kind != api.FindingStatisticTypeCOUNT_BY_SEVERITY {
				return nil, invalid("Invalid findingStatisticTypes")
			}
		}
	} else {
		switch group {
		case "ACCOUNT", "DATE", "FINDING_TYPE", "RESOURCE", "SEVERITY":
		default:
			return nil, invalid("Invalid groupBy")
		}
	}
	limit := 25
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	if limit < 1 || limit > 100 {
		return nil, invalid("maxResults must be between 1 and 100")
	}
	order := value(in.OrderBy)
	if order == "" {
		order = "DESC"
	}
	if order != "ASC" && order != "DESC" {
		return nil, invalid("Invalid orderBy")
	}
	if err := validateQueryCriteria(in.FindingCriteria); err != nil {
		return nil, err
	}
	rows, err := tx.Findings(d.Scope, d.ID)
	if err != nil {
		return nil, err
	}
	groups := map[statisticKey]statistic{}
	now := s.clock.Now()
	for _, row := range rows {
		if findingExpired(row, now) {
			continue
		}
		finding, err := findingOutput(row)
		if err != nil {
			return nil, err
		}
		if !matchesFinding(finding, in.FindingCriteria) {
			continue
		}
		severity := float64(*finding.Severity)
		add := func(key statisticKey) {
			v := groups[key]
			v.key = key
			v.count++
			if row.Updated.After(v.last) {
				v.last = row.Updated
			}
			groups[key] = v
		}
		switch {
		case legacy || group == "SEVERITY":
			add(statisticKey{severity: severity})
		case group == "ACCOUNT":
			add(statisticKey{text: row.AccountID})
		case group == "FINDING_TYPE":
			add(statisticKey{text: value(finding.Type)})
		case group == "DATE":
			add(statisticKey{day: row.Updated.UTC().Truncate(24 * time.Hour).Unix(), severity: severity})
		case group == "RESOURCE":
			kind := value(finding.Resource.ResourceType)
			path := resourceStatisticPath(kind)
			if path != "" {
				seen := map[string]bool{}
				selector := findingSelectors[path]
				selector.visit(finding, func(v findingValue) bool {
					if v.kind == findingString && v.text != "" && !seen[v.text] {
						add(statisticKey{text: v.text, account: row.AccountID, resourceType: kind})
						seen[v.text] = true
					}
					return false
				})
			}
		}
	}
	out := &api.GetFindingsStatisticsOutput{FindingStatistics: &api.FindingStatistics{}}
	if legacy {
		out.FindingStatistics.CountBySeverity = api.CountBySeverity{}
		for key, v := range groups {
			label := strconv.FormatFloat(key.severity, 'f', -1, 64)
			if !strings.Contains(label, ".") {
				label += ".0"
			}
			out.FindingStatistics.CountBySeverity[api.String(label)] = api.Integer(v.count)
		}
		return out, nil
	}
	ordered := make([]statistic, 0, len(groups))
	for _, v := range groups {
		ordered = append(ordered, v)
	}
	slices.SortFunc(ordered, func(a, b statistic) int {
		primary := cmp.Compare(a.count, b.count)
		if group == "SEVERITY" {
			primary = cmp.Compare(a.key.severity, b.key.severity)
		}
		if group == "DATE" && a.key.day != b.key.day {
			primary = cmp.Compare(a.key.day, b.key.day)
		}
		if order == "DESC" {
			primary = -primary
		}
		if primary != 0 {
			return primary
		}
		if c := cmp.Compare(a.key.text, b.key.text); c != 0 {
			return c
		}
		if c := cmp.Compare(a.key.resourceType, b.key.resourceType); c != 0 {
			return c
		}
		return cmp.Compare(a.key.severity, b.key.severity)
	})
	if len(ordered) > limit {
		ordered = ordered[:limit]
	}
	for _, v := range ordered {
		total, last, severity := api.Integer(v.count), api.Timestamp(v.last), api.Double(v.key.severity)
		switch group {
		case "ACCOUNT":
			row := api.AccountStatistics{LastGeneratedAt: &last, TotalFindings: &total}
			text(&row.AccountId, v.key.text)
			out.FindingStatistics.GroupedByAccount = append(out.FindingStatistics.GroupedByAccount, row)
		case "FINDING_TYPE":
			row := api.FindingTypeStatistics{LastGeneratedAt: &last, TotalFindings: &total}
			text(&row.FindingType, v.key.text)
			out.FindingStatistics.GroupedByFindingType = append(out.FindingStatistics.GroupedByFindingType, row)
		case "SEVERITY":
			out.FindingStatistics.GroupedBySeverity = append(out.FindingStatistics.GroupedBySeverity, api.SeverityStatistics{LastGeneratedAt: &last, TotalFindings: &total, Severity: &severity})
		case "DATE":
			date := api.Timestamp(time.Unix(v.key.day, 0).UTC())
			out.FindingStatistics.GroupedByDate = append(out.FindingStatistics.GroupedByDate, api.DateStatistics{Date: &date, LastGeneratedAt: &last, TotalFindings: &total, Severity: &severity})
		case "RESOURCE":
			row := api.ResourceStatistics{LastGeneratedAt: &last, TotalFindings: &total}
			text(&row.AccountId, v.key.account)
			text(&row.ResourceId, v.key.text)
			text(&row.ResourceType, v.key.resourceType)
			out.FindingStatistics.GroupedByResource = append(out.FindingStatistics.GroupedByResource, row)
		}
	}
	return out, nil
}

// Native resource grouping uses service resource identities, not finding IDs.
func resourceStatisticPath(kind string) string {
	switch kind {
	case "Instance":
		return "resource.instanceDetails.instanceId"
	case "EKSCluster":
		return "resource.eksClusterDetails.name"
	case "ECSCluster":
		return "resource.ecsClusterDetails.name"
	case "Container":
		return "resource.containerDetails.id"
	case "KubernetesCluster":
		return "resource.kubernetesDetails.kubernetesWorkloadDetails.name"
	case "AccessKey":
		return "resource.accessKeyDetails.accessKeyId"
	case "S3Bucket", "S3Object":
		return "resource.s3BucketDetails.name"
	case "RDSDBInstance":
		return "resource.rdsDbInstanceDetails.dbInstanceIdentifier"
	case "RDSLimitlessDB":
		return "resource.rdsLimitlessDbDetails.dbClusterIdentifier"
	case "Lambda":
		return "resource.lambdaDetails.functionName"
	case "EBSSnapshot":
		return "resource.ebsSnapshotDetails.snapshotArn"
	case "EC2AMI":
		return "resource.ec2ImageDetails.imageArn"
	case "EBSRecoveryPoint", "EC2RecoveryPoint", "S3RecoveryPoint":
		return "resource.recoveryPointDetails.recoveryPointArn"
	default:
		return ""
	}
}
