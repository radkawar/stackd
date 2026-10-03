package identitycenter

import (
	"crypto/subtle"
	"html/template"
	"net/http"
	"net/url"
	"stackd/internal/awsctx"
	"strings"
)

const AuthorizationPath = "/_stackd/sso/"

var authorizationPage = template.Must(template.New("authorize").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Identity Center · stackd</title><style>body{font:17px system-ui,sans-serif;background:#f5f7fa;color:#182a3a;margin:0}main{max-width:440px;margin:8vh auto;padding:32px;background:white;border:1px solid #d0d8e0;border-radius:8px}h1{font-size:26px}label{display:block;margin:18px 0 6px}input{box-sizing:border-box;width:100%;padding:10px;border:1px solid #77889a;border-radius:4px;font:inherit}button{padding:11px 18px;margin:22px 10px 0 0;border:1px solid #1d4f82;border-radius:4px;background:#1d4f82;color:white;font:inherit;cursor:pointer}button[name=decision][value=deny]{background:white;color:#1d4f82}.notice{padding:12px;background:#eef3f8}.error{color:#a22}small{color:#53687a}</style></head><body><main><small>stackd local AWS access portal</small><h1>{{.Title}}</h1>{{if .Message}}<p class="{{if .Error}}error{{else}}notice{{end}}">{{.Message}}</p>{{end}}{{if .EnterCode}}<form method="get" action="/_stackd/sso/device"><label for="user_code">Device verification code</label><input id="user_code" name="user_code" autocomplete="off" required><button>Continue</button></form>{{end}}{{if .Authorize}}<p>Authorize <strong>{{.ClientName}}</strong> to access the AWS accounts and roles assigned to you.</p>{{if .RequestID}}<p class="notice">Return to <strong>{{.RedirectURI}}</strong> after signing in. Only approve a sign-in you started.</p>{{else}}<p class="notice">Verify that your terminal displays <strong>{{.UserCode}}</strong>. Do not approve a code sent by someone else.</p>{{end}}<form method="post" action="{{if .RequestID}}/authorize{{else}}/_stackd/sso/device{{end}}"><input type="hidden" name="request_id" value="{{.RequestID}}"><input type="hidden" name="user_code" value="{{.UserCode}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button name="decision" value="approve">Sign in and authorize</button><button name="decision" value="deny" formnovalidate>Deny</button></form><p><small>Authentication uses this emulator's explicitly configured Cognito identity source. Your directory administrator controls account assignments.</small></p>{{end}}</main></body></html>`))

type pageData struct {
	Title, Message, ClientName, UserCode, CSRF string
	RequestID, RedirectURI                     string
	Error, EnterCode, Authorize                bool
}

func (s *Service) AuthorizationHandler() http.Handler { return http.HandlerFunc(s.authorizeHTTP) }
func page(w http.ResponseWriter, status int, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	formAction := "'self'"
	if data.RedirectURI != "" {
		// Chromium applies form-action to the POST's redirect chain as well.
		// This URI has already matched the client's registered callback; allow
		// its origin without allowing arbitrary cross-origin form destinations.
		if redirect, err := url.Parse(data.RedirectURI); err == nil {
			destination := redirect.Scheme + ":"
			if redirect.Host != "" {
				host := strings.ReplaceAll(strings.ReplaceAll(redirect.Host, ";", "%3B"), ",", "%2C")
				destination += "//" + host
			}
			formAction += " " + destination
		}
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_ = authorizationPage.Execute(w, data)
}
func (s *Service) authorizeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == AuthorizePath {
		s.authorizeCodeHTTP(w, r)
		return
	}
	if r.URL.Path != AuthorizationPath+"device" {
		http.NotFound(w, r)
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if e := r.ParseForm(); e != nil {
		page(w, 400, pageData{Title: "Invalid request", Message: "The request could not be read.", Error: true})
		return
	}
	code := strings.ToUpper(strings.TrimSpace(r.Form.Get("user_code")))
	if code == "" && r.Method == "GET" {
		page(w, 200, pageData{Title: "Authorize your device", EnterCode: true})
		return
	}
	var device Device
	var instance Instance
	var client Client
	e := s.repository.View(r.Context(), func(rd Reader) error {
		var e error
		device, e = rd.DeviceByUserCode(code)
		if e != nil {
			return e
		}
		instance, e = rd.Instance(device.InstanceARN)
		if e != nil {
			return e
		}
		client, e = rd.Client(device.ClientID)
		return e
	})
	if e != nil || !s.clock.Now().Before(device.Expires) || device.State != "PENDING" {
		page(w, 400, pageData{Title: "Code unavailable", Message: "This device code is invalid, expired, or has already been used.", Error: true})
		return
	}
	if r.Method == "GET" {
		csrf, e := randomToken()
		if e == nil {
			e = s.repository.Update(r.Context(), func(tx Transaction) error {
				current, e := tx.Device(device.CodeHash)
				if e != nil {
					return e
				}
				if current.State != "PENDING" || !s.clock.Now().Before(current.Expires) {
					return ErrNotFound
				}
				current.CSRF = csrf
				return tx.PutDevice(current)
			})
		}
		if e != nil {
			page(w, 500, pageData{Title: "Unable to authorize", Message: "Authorization state is unavailable.", Error: true})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "stackd_sso_csrf", Value: csrf, Path: AuthorizationPath, SameSite: http.SameSiteStrictMode, HttpOnly: true, Secure: r.TLS != nil, MaxAge: 600})
		page(w, 200, pageData{Title: "Sign in to Identity Center", ClientName: client.Name, UserCode: code, CSRF: csrf, Authorize: true})
		return
	}
	cookie, cookieErr := r.Cookie("stackd_sso_csrf")
	csrf := r.Form.Get("csrf")
	origin := r.Header.Get("Origin")
	endpoint, _ := url.Parse(s.endpoint)
	if cookieErr != nil || csrf == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(device.CSRF)) != 1 || subtle.ConstantTimeCompare([]byte(csrf), []byte(cookie.Value)) != 1 || (origin != "" && (endpoint == nil || origin != endpoint.Scheme+"://"+endpoint.Host)) {
		page(w, 403, pageData{Title: "Authorization rejected", Message: "The browser authorization request is invalid. Reload the verification page.", Error: true})
		return
	}
	decision := r.Form.Get("decision")
	if decision != "approve" && decision != "deny" {
		page(w, 400, pageData{Title: "Invalid decision", Error: true})
		return
	}
	var username string
	if decision == "approve" {
		if s.login == nil {
			page(w, 503, pageData{Title: "Identity source unavailable", Message: "The local Cognito identity source has not been configured.", Error: true})
			return
		}
		// This is an unsigned Cognito authentication request, not a fabricated IAM
		// caller. It runs outside the retained device transaction.
		metadata := awsctx.Metadata{Partition: instance.Partition, AccountID: instance.AccountID, Region: instance.Region, SourceIP: r.RemoteAddr, UserAgent: r.UserAgent()}
		username, e = s.login.Authenticate(awsctx.WithMetadata(r.Context(), metadata), r.Form.Get("username"), r.Form.Get("password"))
		if e != nil {
			page(w, 401, pageData{Title: "Sign-in unsuccessful", Message: "Check your username and password. The configured identity source must support completed password authentication.", Error: true, ClientName: client.Name, UserCode: code, CSRF: csrf, Authorize: true})
			return
		}
	}
	e = s.repository.Update(r.Context(), func(tx Transaction) error {
		current, e := tx.Device(device.CodeHash)
		if e != nil {
			return e
		}
		if current.State != "PENDING" || current.CSRF != csrf || !s.clock.Now().Before(current.Expires) {
			return ErrNotFound
		}
		current.State = "DENIED"
		if decision == "approve" {
			if s.directory == nil {
				return ErrNotFound
			}
			actual, e := tx.Instance(instance.ARN)
			if e != nil {
				return e
			}
			user, e := s.directory.UserByName(tx.Context(), directoryScope(actual), actual.StoreID, username)
			if e != nil {
				return e
			}
			current.UserID = user.ID
			current.State = "AUTHORIZED"
		}
		current.CSRF = ""
		return tx.PutDevice(current)
	})
	if e != nil {
		page(w, 403, pageData{Title: "Authorization rejected", Message: "The user is not present in this directory, or the device authorization has expired.", Error: true})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "stackd_sso_csrf", Value: "", Path: AuthorizationPath, SameSite: http.SameSiteStrictMode, HttpOnly: true, Secure: r.TLS != nil, MaxAge: -1})
	if decision == "deny" {
		page(w, 200, pageData{Title: "Access denied", Message: "This device was not authorized. You can close this window."})
		return
	}
	page(w, 200, pageData{Title: "Device authorized", Message: "You have successfully signed in. Return to your terminal to continue. You can close this window."})
}
