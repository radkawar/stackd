package cloudwatch

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func contributorThresholdReason(config *MetricAlarmConfig, state string, points []alarmEvaluationPoint, bad, good, required int) string {
	relation := ""
	switch config.Comparison {
	case "GreaterThanThreshold":
		relation = "greater than"
	case "GreaterThanOrEqualToThreshold":
		relation = "greater than or equal to"
	case "LessThanThreshold":
		relation = "less than"
	case "LessThanOrEqualToThreshold":
		relation = "less than or equal to"
	}
	count, crossed, transition := bad, "crossed", "OK -> ALARM"
	if state == "OK" {
		count, crossed, transition = good, "not crossed", "ALARM -> OK"
		relation = "not " + relation
	}
	missing := int(config.EvaluationPeriods) - len(points)
	treatment := ""
	if config.TreatMissingData == "breaching" {
		treatment = "Breaching"
	} else if config.TreatMissingData == "notBreaching" {
		treatment = "NonBreaching"
	}
	fill := ""
	if missing > 0 && treatment != "" {
		noun, verb := contributorPointWords(missing)
		fill = fmt.Sprintf(" and %d missing %s %s treated as [%s]", missing, noun, verb, treatment)
	}
	if count == 0 {
		noun, verb := contributorPointWords(len(points))
		return fmt.Sprintf("Threshold Crossed: %d %s %s received for %d periods%s.", len(points), noun, verb, config.EvaluationPeriods, fill)
	}
	_, verb := contributorPointWords(count)
	reason := fmt.Sprintf("Threshold Crossed: %d out of the last %d datapoints %s %s the threshold (%s)%s.", count, config.EvaluationPeriods, verb, relation, contributorReasonNumber(config.Threshold), fill)
	for _, point := range points {
		if alarmBreaches(config, point.value) == (state == "ALARM") {
			reason += fmt.Sprintf(" The most recent datapoint which %s the threshold: [%s (%s)]", crossed, contributorReasonNumber(point.value), time.Unix(point.at, 0).UTC().Format("02/01/06 15:04:05"))
			break
		}
	}
	noun, _ := contributorPointWords(required)
	return reason + fmt.Sprintf(" (minimum %d %s for %s transition).", required, noun, transition)
}

func contributorPointWords(count int) (string, string) {
	if count == 1 {
		return "datapoint", "was"
	}
	return "datapoints", "were"
}

func contributorReasonNumber(number float64) string {
	text := strconv.FormatFloat(number, 'g', -1, 64)
	if !strings.ContainsAny(text, ".eE") {
		text += ".0"
	}
	return text
}
