// Initial file was taken from https://github.com/docker/distribution 2018 Sept
//
// Copyright (c) 2018 Wind River Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
        "context"
	"encoding/json"
	"flag"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/docker/distribution/registry/auth"
	"github.com/docker/libtrust"
	"github.com/gorilla/mux"
	_ "registry-token-server/keystone"
)

var (
	enforceRepoClass bool
)

func main() {
	var (
		issuer = &TokenIssuer{}
		pkFile string
		addr   string
		debug  bool
		err    error

		keystoneEndpoint string
		realm            string

		cert    string
		certKey string
	)

	flag.StringVar(&issuer.Issuer, "issuer", "distribution-token-server", "Issuer string for token")
	flag.StringVar(&pkFile, "key", "", "Private key file")
	flag.StringVar(&addr, "addr", "localhost:8080", "Address to listen on")
	flag.BoolVar(&debug, "debug", false, "Debug mode")

	flag.StringVar(&keystoneEndpoint, "endpoint", "", "Passwd file")
	flag.StringVar(&realm, "realm", "", "Authentication realm")

	flag.StringVar(&cert, "tlscert", "", "Certificate file for TLS")
	flag.StringVar(&certKey, "tlskey", "", "Certificate key for TLS")

	flag.BoolVar(&enforceRepoClass, "enforce-class", false, "Enforce policy for single repository class")

	flag.Parse()

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if pkFile == "" {
		issuer.SigningKey, err = libtrust.GenerateECP256PrivateKey()
		if err != nil {
			logrus.Fatalf("Error generating private key: %v", err)
		}
		logrus.Debugf("Using newly generated key with id %s", issuer.SigningKey.KeyID())
	} else {
		issuer.SigningKey, err = libtrust.LoadKeyFile(pkFile)
		if err != nil {
			logrus.Fatalf("Error loading key file %s: %v", pkFile, err)
		}
		logrus.Debugf("Loaded private key with id %s", issuer.SigningKey.KeyID())
	}

	if realm == "" {
		logrus.Fatalf("Must provide realm")
	}

	ac, err := auth.GetAccessController("keystone", map[string]interface{}{
		"realm":    realm,
		"endpoint": keystoneEndpoint,
	})
	if err != nil {
		logrus.Fatalf("Error initializing access controller: %v", err)
	}

	// TODO: Make configurable
	issuer.Expiration = 15 * time.Minute

	ctx := dcontext.Background()

	ts := &tokenServer{
		issuer:           issuer,
		accessController: ac,
		refreshCache:     map[string]refreshToken{},
	}

	router := mux.NewRouter()
	router.Path("/token/").Methods("GET").Handler(handlerWithContext(ctx, ts.getToken))
	router.Path("/token/").Methods("POST").Handler(handlerWithContext(ctx, ts.postToken))

	if cert == "" {
		err = http.ListenAndServe(addr, router)
	} else if certKey == "" {
		logrus.Fatalf("Must provide certficate (-tlscert) and key (-tlskey)")
	} else {
		err = http.ListenAndServeTLS(addr, cert, certKey, router)
	}

	if err != nil {
		logrus.Infof("Error serving: %v", err)
	}

}

// handlerWithContext wraps the given context-aware handler by setting up the
// request context from a base context.
func handlerWithContext(ctx context.Context, handler func(context.Context, http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := dcontext.WithRequest(ctx, r)
		logger := dcontext.GetRequestLogger(ctx)
		ctx = dcontext.WithLogger(ctx, logger)

		handler(ctx, w, r)
	})
}

func handleError(ctx context.Context, err error, w http.ResponseWriter) {
	ctx, w = dcontext.WithResponseWriter(ctx, w)

	if serveErr := errcode.ServeJSON(w, err); serveErr != nil {
		dcontext.GetResponseLogger(ctx).Errorf("error sending error response: %v", serveErr)
		return
	}

	dcontext.GetResponseLogger(ctx).Info("application error")
}

var refreshCharacters = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

const refreshTokenLength = 15

func newRefreshToken() string {
	s := make([]rune, refreshTokenLength)
	for i := range s {
		s[i] = refreshCharacters[rand.Intn(len(refreshCharacters))]
	}
	return string(s)
}

type refreshToken struct {
	subject string
	service string
}

type tokenServer struct {
	issuer           *TokenIssuer
	accessController auth.AccessController
	refreshCache     map[string]refreshToken
}

type tokenResponse struct {
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

var repositoryClassCache = map[string]string{}

func filterAccessList(ctx context.Context, scope string, requestedAccessList []auth.Access) []auth.Access {
	if !strings.HasSuffix(scope, "/") {
		scope = scope + "/"
	}
	grantedAccessList := make([]auth.Access, 0, len(requestedAccessList))
	for _, access := range requestedAccessList {
		if access.Type == "repository" {

			publicRepos := []string{"public/"}
			// pause is usually used as a test deployment by kubernetes and deployed without pull secrets
			// acmesolver is deployed in a namespace that don't have access to pull secrets
                        // n3000-opae is used during puppet manifest at which point credentials cannot be obtained
			publicImages := []string{"k8s.gcr.io/pause",
                                                 "docker.io/starlingx/n3000-opae",
						 "quay.io/jetstack/cert-manager-acmesolver"}

			// this controls our own authorization rules like admin accounts and public repos/images
			// if authorized through other means, skip the usual authorization policy of
			// user can only interact with their own repo
			skipStandardAuthz := false

			// public repo allows all images too be pulled by everyone
			if strings.EqualFold(access.Action, "pull") {
				for _, publicRepo := range publicRepos {
					if strings.HasPrefix(access.Name, publicRepo) {
						skipStandardAuthz = true
					}
				}
			}

                        // public images can be pulled by anyone, even though they sit in private repos
                        if strings.EqualFold(access.Action, "pull") {
                                for _, publicImage := range publicImages {
                                        if access.Name == publicImage {
                                                skipStandardAuthz = true
                                        }
                                }
                        }

			// filter access to repos if the user is not "admin" or "sysinv"
			// need to have a "/" at the end because it adds one at the beginning of the fcn
			// probably to prevent people making accounts like "adminnot" to steal admin powers
			if scope == "admin/" || scope == "sysinv/" {
				skipStandardAuthz = true
			}

			// we do not allow "mtce" to access the mtce repo because it is reserved for internal use
			// we still allow the admin accounts to access the "mtce repo though
                        if strings.HasPrefix(access.Name, scope) && scope == "mtce/" {
                                dcontext.GetLogger(ctx).Debugf("Resource scope not allowed: %s", access.Name)
                                continue
                        }

			if !strings.HasPrefix(access.Name, scope) && !skipStandardAuthz {
				dcontext.GetLogger(ctx).Debugf("Resource scope not allowed: %s", access.Name)
				continue
			}
			if enforceRepoClass {
				if class, ok := repositoryClassCache[access.Name]; ok {
					if class != access.Class {
						dcontext.GetLogger(ctx).Debugf("Different repository class: %q, previously %q", access.Class, class)
						continue
					}
				} else if strings.EqualFold(access.Action, "push") {
					repositoryClassCache[access.Name] = access.Class
				}
			}
		} else if access.Type == "registry" {
			if access.Name != "catalog" {
				dcontext.GetLogger(ctx).Debugf("Unknown registry resource: %s", access.Name)
				continue
			}
			// TODO: Limit some actions to "admin" users
		} else {
			dcontext.GetLogger(ctx).Debugf("Skipping unsupported resource type: %s", access.Type)
			continue
		}
		grantedAccessList = append(grantedAccessList, access)
	}
	return grantedAccessList
}

type acctSubject struct{}

func (acctSubject) String() string { return "acctSubject" }

type requestedAccess struct{}

func (requestedAccess) String() string { return "requestedAccess" }

type grantedAccess struct{}

func (grantedAccess) String() string { return "grantedAccess" }

// getToken handles authenticating the request and authorizing access to the
// requested scopes.
func (ts *tokenServer) getToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	dcontext.GetLogger(ctx).Debug("getToken")

	params := r.URL.Query()
	service := params.Get("service")
	scopeSpecifiers := params["scope"]
	var offline bool
	if offlineStr := params.Get("offline_token"); offlineStr != "" {
		var err error
		offline, err = strconv.ParseBool(offlineStr)
		if err != nil {
			handleError(ctx, ErrorBadTokenOption.WithDetail(err), w)
			return
		}
	}

	requestedAccessList := ResolveScopeSpecifiers(ctx, scopeSpecifiers)

	authorizedCtx, err := ts.accessController.Authorized(ctx, requestedAccessList...)
	if err != nil {
		challenge, ok := err.(auth.Challenge)
		if !ok {
			handleError(ctx, err, w)
			return
		}

		// Get response context.
		ctx, w = dcontext.WithResponseWriter(ctx, w)

		challenge.SetHeaders(r, w)
		handleError(ctx, errcode.ErrorCodeUnauthorized.WithDetail(challenge.Error()), w)

		dcontext.GetResponseLogger(ctx).Info("get token authentication challenge")

		return
	}
	ctx = authorizedCtx

	username := dcontext.GetStringValue(ctx, "auth.user.name")

	ctx = context.WithValue(ctx, acctSubject{}, username)
	ctx = dcontext.WithLogger(ctx, dcontext.GetLogger(ctx, acctSubject{}))

	dcontext.GetLogger(ctx).Debug("authenticated client")

	ctx = context.WithValue(ctx, requestedAccess{}, requestedAccessList)
	ctx = dcontext.WithLogger(ctx, dcontext.GetLogger(ctx, requestedAccess{}))

	grantedAccessList := filterAccessList(ctx, username, requestedAccessList)
	ctx = context.WithValue(ctx, grantedAccess{}, grantedAccessList)
	ctx = dcontext.WithLogger(ctx, dcontext.GetLogger(ctx, grantedAccess{}))

	token, err := ts.issuer.CreateJWT(username, service, grantedAccessList)
	if err != nil {
		handleError(ctx, err, w)
		return
	}

	dcontext.GetLogger(ctx).Debug("authorized client")

	response := tokenResponse{
		Token:     token,
		ExpiresIn: int(ts.issuer.Expiration.Seconds()),
	}

	if offline {
		response.RefreshToken = newRefreshToken()
		ts.refreshCache[response.RefreshToken] = refreshToken{
			subject: username,
			service: service,
		}
	}

	ctx, w = dcontext.WithResponseWriter(ctx, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	dcontext.GetResponseLogger(ctx).Debug("get token complete")
}

type postTokenResponse struct {
	Token        string `json:"access_token"`
	Scope        string `json:"scope,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IssuedAt     string `json:"issued_at,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// postToken handles authenticating the request and authorizing access to the
// requested scopes.
func (ts *tokenServer) postToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	grantType := r.PostFormValue("grant_type")
	if grantType == "" {
		handleError(ctx, ErrorMissingRequiredField.WithDetail("missing grant_type value"), w)
		return
	}

	service := r.PostFormValue("service")
	if service == "" {
		handleError(ctx, ErrorMissingRequiredField.WithDetail("missing service value"), w)
		return
	}

	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		handleError(ctx, ErrorMissingRequiredField.WithDetail("missing client_id value"), w)
		return
	}

	var offline bool
	switch r.PostFormValue("access_type") {
	case "", "online":
	case "offline":
		offline = true
	default:
		handleError(ctx, ErrorUnsupportedValue.WithDetail("unknown access_type value"), w)
		return
	}

	requestedAccessList := ResolveScopeList(ctx, r.PostFormValue("scope"))

	var subject string
	var rToken string
	switch grantType {
	case "refresh_token":
		rToken = r.PostFormValue("refresh_token")
		if rToken == "" {
			handleError(ctx, ErrorUnsupportedValue.WithDetail("missing refresh_token value"), w)
			return
		}
		rt, ok := ts.refreshCache[rToken]
		if !ok || rt.service != service {
			handleError(ctx, errcode.ErrorCodeUnauthorized.WithDetail("invalid refresh token"), w)
			return
		}
		subject = rt.subject
	case "password":
		ca, ok := ts.accessController.(auth.CredentialAuthenticator)
		if !ok {
			handleError(ctx, ErrorUnsupportedValue.WithDetail("password grant type not supported"), w)
			return
		}
		subject = r.PostFormValue("username")
		if subject == "" {
			handleError(ctx, ErrorUnsupportedValue.WithDetail("missing username value"), w)
			return
		}
		password := r.PostFormValue("password")
		if password == "" {
			handleError(ctx, ErrorUnsupportedValue.WithDetail("missing password value"), w)
			return
		}
		if err := ca.AuthenticateUser(subject, password); err != nil {
			handleError(ctx, errcode.ErrorCodeUnauthorized.WithDetail("invalid credentials"), w)
			return
		}
	default:
		handleError(ctx, ErrorUnsupportedValue.WithDetail("unknown grant_type value"), w)
		return
	}

	ctx = context.WithValue(ctx, acctSubject{}, subject)
	ctx = dcontext.WithLogger(ctx, dcontext.GetLogger(ctx, acctSubject{}))

	dcontext.GetLogger(ctx).Debug("authenticated client")

	ctx = context.WithValue(ctx, requestedAccess{}, requestedAccessList)
	ctx = dcontext.WithLogger(ctx, dcontext.GetLogger(ctx, requestedAccess{}))

	grantedAccessList := filterAccessList(ctx, subject, requestedAccessList)
	ctx = context.WithValue(ctx, grantedAccess{}, grantedAccessList)
	ctx = dcontext.WithLogger(ctx, dcontext.GetLogger(ctx, grantedAccess{}))

	token, err := ts.issuer.CreateJWT(subject, service, grantedAccessList)
	if err != nil {
		handleError(ctx, err, w)
		return
	}

	dcontext.GetLogger(ctx).Debug("authorized client")

	response := postTokenResponse{
		Token:     token,
		ExpiresIn: int(ts.issuer.Expiration.Seconds()),
		IssuedAt:  time.Now().UTC().Format(time.RFC3339),
		Scope:     ToScopeList(grantedAccessList),
	}

	if offline {
		rToken = newRefreshToken()
		ts.refreshCache[rToken] = refreshToken{
			subject: subject,
			service: service,
		}
	}

	if rToken != "" {
		response.RefreshToken = rToken
	}

	ctx, w = dcontext.WithResponseWriter(ctx, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	dcontext.GetResponseLogger(ctx).Debug("post token complete")
}
