package s3tables

// Both service-specific keys are String, not ArrayOfString. A namespace is its
// one typed name; never split it into synthetic hierarchy components or join an
// API NamespaceList to manufacture a different policy value.
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3tables.html
func namespaceAuthorizationContext(namespace string) map[string][]string {
	if namespace == "" {
		return nil
	}
	return map[string][]string{"s3tables:namespace": {namespace}}
}

func tableAuthorizationContext(table Table) map[string][]string {
	return map[string][]string{
		"s3tables:tableName": {table.Name},
		"s3tables:namespace": {table.Namespace},
	}
}
