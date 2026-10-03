package account

import "stackd/internal/awscatalog"

// enumValues reads the legacy string-enum trait retained from Smithy. Account
// owns the rejection behavior: contact types fail access checks, while region
// filters fail request validation, so a blanket wire enum error is incorrect.
func enumValues(name string) []string {
	service, _ := awscatalog.LookupService("account")
	shape, _ := service.Shape(awscatalog.ShapeID("com.amazonaws.account#" + name))
	values := make([]string, len(shape.Enum))
	for i, member := range shape.Enum {
		values[i] = member.Value
	}
	return values
}
