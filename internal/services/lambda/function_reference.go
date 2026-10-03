package lambda

import (
	"context"
	"regexp"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

var functionName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}

func parseFunctionReference(ctx context.Context, name, qualifier string) (FunctionReference, *awswire.Error) {
	requestScope := scopeFor(ctx)
	scope := requestScope
	if strings.HasPrefix(name, "arn:") {
		p := strings.SplitN(name, ":", 7)
		if len(p) != 7 || p[2] != "lambda" || p[5] != "function" {
			return FunctionReference{}, failure("InvalidParameterValueException", "Invalid function ARN.", 400)
		}
		scope = Scope{p[1], p[4], p[3]}
		name = p[6]
	} else if p := strings.SplitN(name, ":", 3); len(p) == 3 && p[1] == "function" {
		scope.Account = p[0]
		name = p[2]
	}
	if n, q, ok := strings.Cut(name, ":"); ok {
		if qualifier != "" && qualifier != q {
			return FunctionReference{}, failure("InvalidParameterValueException", "Conflicting function qualifiers.", 400)
		}
		name, qualifier = n, q
	}
	if !functionName.MatchString(name) || len(scope.Account) != 12 || strings.Trim(scope.Account, "0123456789") != "" {
		return FunctionReference{}, failure("InvalidParameterValueException", "Invalid function name or account.", 400)
	}
	if scope.Partition != requestScope.Partition || scope.Region != requestScope.Region {
		return FunctionReference{}, failure("ResourceNotFoundException", "Function not found in the request region and partition.", 404)
	}
	return FunctionReference{FunctionKey: FunctionKey{scope, name}, Qualifier: qualifier}, nil
}
