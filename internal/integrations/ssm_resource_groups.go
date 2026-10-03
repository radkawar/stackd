package integrations

import (
	"context"
	"net/http"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/resourcegroups"
)

// SSMResourceGroups projects the current owner's membership onto EC2 identities.
// ResourceGroups is assigned during assembly before requests are served.
type SSMResourceGroups struct{ ResourceGroups *resourcegroups.Service }

func (a *SSMResourceGroups) Instances(ctx context.Context, name string) ([]string, error) {
	if a == nil || a.ResourceGroups == nil {
		return nil, &awswire.Error{Code: "InternalServerError", Message: "Resource Groups is not configured.", StatusCode: http.StatusInternalServerError}
	}
	rows, err := a.ResourceGroups.CommandResources(ctx, name)
	if err != nil {
		return nil, err
	}
	scope := awsctx.FromContext(ctx)
	prefix := "arn:" + scope.Partition + ":ec2:" + scope.Region + ":" + scope.AccountID + ":instance/"
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.Type == "AWS::EC2::Instance" && !row.Pending && strings.HasPrefix(row.ARN, prefix) {
			id := strings.TrimPrefix(row.ARN, prefix)
			if strings.HasPrefix(id, "i-") && !strings.Contains(id, "/") {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}
