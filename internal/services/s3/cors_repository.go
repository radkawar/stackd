package s3

// CORSRule is an admitted bucket rule. Order, optional ID/max age and each
// ordered header/origin/method list are retained independently of request XML.
type CORSRule struct {
	ID *string
	// TODO: Comeback support native out-of-model int64 max ages; the generated SDK contract is int32.
	MaxAgeSeconds                                                 *int32
	AllowedOrigins, AllowedMethods, AllowedHeaders, ExposeHeaders []string
}
