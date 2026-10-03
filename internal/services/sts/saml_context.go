package sts

// These mappings are the documented IAM SAML claim vocabulary, rather than an
// arbitrary projection of untrusted attribute names into global policy keys.
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html
var samlAttributeContextKeys = map[string]string{
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.1":                                        "saml:edupersonaffiliation",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.2":                                        "saml:edupersonnickname",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.3":                                        "saml:edupersonorgdn",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.4":                                        "saml:edupersonorgunitdn",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.5":                                        "saml:edupersonprimaryaffiliation",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.6":                                        "saml:edupersonprincipalname",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.7":                                        "saml:edupersonentitlement",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.8":                                        "saml:edupersonprimaryorgunitdn",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.9":                                        "saml:edupersonscopedaffiliation",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.10":                                       "saml:edupersontargetedid",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.11":                                       "saml:edupersonassurance",
	"urn:oid:1.3.6.1.4.1.5923.1.2.1.2":                                        "saml:eduorghomepageuri",
	"urn:oid:1.3.6.1.4.1.5923.1.2.1.3":                                        "saml:eduorgidentityauthnpolicyuri",
	"urn:oid:1.3.6.1.4.1.5923.1.2.1.4":                                        "saml:eduorglegalname",
	"urn:oid:1.3.6.1.4.1.5923.1.2.1.5":                                        "saml:eduorgsuperioruri",
	"urn:oid:1.3.6.1.4.1.5923.1.2.1.6":                                        "saml:eduorgwhitepagesuri",
	"urn:oid:2.5.4.3":                                                         "saml:cn",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":              "saml:name",
	"http://schemas.xmlsoap.org/claims/CommonName":                            "saml:commonname",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":         "saml:givenname",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":           "saml:surname",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":      "saml:mail",
	"http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid": "saml:uid",
	"2.5.4.3":                    "saml:commonname",
	"2.5.4.4":                    "saml:surname",
	"2.4.5.42":                   "saml:givenname",
	"2.5.4.45":                   "saml:x500uniqueidentifier",
	"0.9.2342.19200300100.1.1":   "saml:uid",
	"0.9.2342.19200300100.1.3":   "saml:mail",
	"0.9.2342.19200300.100.1.45": "saml:organizationstatus",
}
