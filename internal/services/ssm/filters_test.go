package ssm

import (
	"slices"
	"testing"

	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
)

func TestParameterFiltersAndScopedPagination(t *testing.T) {
	s, ctx := parameterReadHarness(t)
	for _, name := range []string{"/filter/a", "/filter/b", "/filter/nested/c", "/other/d"} {
		readTestPut(t, s, ctx, name, name)
	}
	filter := func(key, option string, values ...string) api.ParameterStringFilter {
		out := api.ParameterStringFilter{Key: new(api.ParameterStringFilterKey(key))}
		if option != "" {
			out.Option = new(api.ParameterStringQueryOption(option))
		}
		for _, v := range values {
			out.Values = append(out.Values, api.ParameterStringFilterValue(v))
		}
		return out
	}
	for _, tc := range []struct {
		filters api.ParameterStringFilterList
		want    []string
	}{
		{api.ParameterStringFilterList{filter("Path", "", "/filter")}, []string{"/filter/a", "/filter/b"}},
		{api.ParameterStringFilterList{filter("Path", "Recursive", "/filter")}, []string{"/filter/a", "/filter/b", "/filter/nested/c"}},
		{api.ParameterStringFilterList{filter("Name", "Contains", "nested"), filter("Type", "Equals", "String")}, []string{"/filter/nested/c"}},
		{api.ParameterStringFilterList{filter("Name", "Equals", "/filter/a", "/other/d")}, []string{"/filter/a", "/other/d"}},
	} {
		out, err := runCommand(s, ctx, "DescribeParameters", &api.DescribeParametersRequest{ParameterFilters: tc.filters}, s.describeParameters)
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(out.Parameters))
		for _, p := range out.Parameters {
			names = append(names, value(p.Name))
		}
		// DescribeParameters does not promise a collection order.
		slices.Sort(names)
		if !slices.Equal(names, tc.want) {
			t.Fatalf("filters %+v = %v, want %v", tc.filters, names, tc.want)
		}
	}
	for _, tc := range []struct {
		filter api.ParameterStringFilter
		code   string
	}{
		{filter("Name", "Equals", "/filter/a"), "InvalidFilterKey"},
		{filter("Type", "Contains", "String"), "InvalidFilterOption"},
		{filter("Label", "BeginsWith", "stable"), "InvalidFilterOption"},
		{filter("Type", "Equals"), "InvalidFilterValue"},
		{filter("Label", "Equals", "old", "current"), "InvalidFilterValue"},
	} {
		_, err := runCommand(s, ctx, "GetParametersByPath", &api.GetParametersByPathRequest{Path: new(api.PSParameterName("/filter")), ParameterFilters: api.ParameterStringFilterList{tc.filter}}, s.getParametersByPath)
		readTestError(t, err, tc.code)
	}
	request := &api.GetParametersByPathRequest{Path: new(api.PSParameterName("/filter")), Recursive: new(api.Boolean(true)), MaxResults: new(api.GetParametersByPathMaxResults(1))}
	first, err := runCommand(s, ctx, "GetParametersByPath", request, s.getParametersByPath)
	if err != nil {
		t.Fatal(err)
	}
	for len(first.Parameters) == 0 && first.NextToken != nil {
		request.NextToken = first.NextToken
		first, err = runCommand(s, ctx, "GetParametersByPath", request, s.getParametersByPath)
		if err != nil {
			t.Fatal(err)
		}
	}
	if first.NextToken == nil || len(first.Parameters) != 1 {
		t.Fatalf("first nonempty page = %+v", first)
	}
	firstName := value(first.Parameters[0].Name)
	// Deleting the emitted row must not make the continuation omit another row.
	_, err = runCommand(s, ctx, "DeleteParameter", &api.DeleteParameterRequest{Name: new(api.PSParameterName(firstName))}, s.deleteParameter)
	if err != nil {
		t.Fatal(err)
	}
	continued := *request
	continued.NextToken = first.NextToken
	continued.MaxResults = new(api.GetParametersByPathMaxResults(10))
	names := []string{firstName}
	for page := continued; ; {
		next, pageErr := runCommand(s, ctx, "GetParametersByPath", &page, s.getParametersByPath)
		if pageErr != nil {
			t.Fatal(pageErr)
		}
		if len(next.Parameters) > int(*page.MaxResults) {
			t.Fatalf("page exceeds MaxResults: %+v", next)
		}
		for _, parameter := range next.Parameters {
			names = append(names, value(parameter.Name))
		}
		if next.NextToken == nil {
			break
		}
		page.NextToken = next.NextToken
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"/filter/a", "/filter/b", "/filter/nested/c"}) {
		t.Fatalf("pagination omitted or duplicated rows: %v", names)
	}
	changed := continued
	changed.Recursive = new(api.Boolean(false))
	_, err = runCommand(s, ctx, "GetParametersByPath", &changed, s.getParametersByPath)
	readTestError(t, err, "InvalidNextToken")
	changed = continued
	changed.NextToken = new(api.NextToken("!" + value(first.NextToken)))
	_, err = runCommand(s, ctx, "GetParametersByPath", &changed, s.getParametersByPath)
	readTestError(t, err, "InvalidNextToken")
	_, err = runCommand(s, ctx, "DescribeParameters", &api.DescribeParametersRequest{NextToken: first.NextToken}, s.describeParameters)
	readTestError(t, err, "InvalidNextToken")
	for _, field := range []string{"account", "region"} {
		metadata := awsctx.FromContext(ctx)
		if field == "account" {
			metadata.AccountID = "999999999999"
			metadata.PrincipalARN = "arn:aws:iam::999999999999:root"
			metadata.PrincipalID = metadata.AccountID
		} else {
			metadata.Region = "us-west-2"
		}
		_, err = runCommand(s, awsctx.WithMetadata(ctx, metadata), "GetParametersByPath", &continued, s.getParametersByPath)
		readTestError(t, err, "InvalidNextToken")
	}
	for _, limit := range []int32{0, 11} {
		changed = *request
		changed.MaxResults = new(api.GetParametersByPathMaxResults(limit))
		_, err = runCommand(s, ctx, "GetParametersByPath", &changed, s.getParametersByPath)
		readTestError(t, err, "ValidationException")
	}
}
