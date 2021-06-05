// Initial file was taken from https://github.com/docker/distribution 2018 Sept
//
// Copyright (c) 2018 Wind River Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Package keystone provides a simple authentication scheme that checks for the
// user credential against keystone with configuration-determined endpoint
//
// This authentication method MUST be used under TLS, as simple token-replay attack is possible.
package keystone

import (
        "context"
	"fmt"
	"net/http"
	"time"

	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
)

type credentials struct {
	username, password string
}

var credentialsCache = make([]credentials, 0)
var cacheInvalidateInterval = time.Duration(10) * time.Minute
var lastCacheInvalidation = time.Now()
const cacheSize = 20

// add the username and password pair into the cache
// if the cache is already full, the oldest entry is removed
// if the username already exist, update the password
func cacheStore(username string, password string) {
	// invalidate cache every <interval>
	currentTime := time.Now()
	if currentTime.Sub(lastCacheInvalidation) > cacheInvalidateInterval {
		credentialsCache = make([]credentials, 0)
		lastCacheInvalidation = time.Now()
	}

	for i, cacheEntry := range credentialsCache {
		if cacheEntry.username == username {
			credentialsCache[i].password = password
			return
		}
	}

	// credentials does not exist in the cache
	if len(credentialsCache) >= cacheSize {
		credentialsCache = credentialsCache[:cacheSize - 1]
	}
	newCredentials := credentials{
		username: username,
		password: password,
	}
	credentialsCache = append(credentialsCache, newCredentials)
}

// check if the username password pair exist in the cache
// if the user exists, move them to the top of the cache
func cacheCheck(username string, password string) bool {
	// invalidate cache every <interval>
	currentTime := time.Now()
	if currentTime.Sub(lastCacheInvalidation) > cacheInvalidateInterval {
		credentialsCache = make([]credentials, 0)
		lastCacheInvalidation = time.Now()
	}
	for i, cacheEntry := range credentialsCache {
		if cacheEntry.username == username && cacheEntry.password == password{
			// move the entry to the top if it is not at the top already
			if i != 0 {
				temp := credentials{
					username: username,
					password: password,
				}
				credentialsCache = append(credentialsCache[:i], credentialsCache[i+1:]...)
				credentialsCache = append([]credentials{temp}, credentialsCache...)
			}
			return true
		}
	}
	// entry not found
	return false
}

type accessController struct {
	realm    string
	endpoint string
}

var _ auth.AccessController = &accessController{}

func newAccessController(options map[string]interface{}) (auth.AccessController, error) {
	realm, present := options["realm"]
	if _, ok := realm.(string); !present || !ok {
		return nil, fmt.Errorf(`"realm" must be set for keystone access controller`)
	}

	endpoint, present := options["endpoint"]
	if _, ok := endpoint.(string); !present || !ok {
		return nil, fmt.Errorf(`"endpoint" must be set for keystone access controller`)
	}

	return &accessController{realm: realm.(string), endpoint: endpoint.(string)}, nil
}

func (ac *accessController) Authorized(ctx context.Context, accessRecords ...auth.Access) (context.Context, error) {
	req, err := dcontext.GetRequest(ctx)
	if err != nil {
		return nil, err
	}

	username, password, ok := req.BasicAuth()
	if !ok {
		return nil, &challenge{
			realm: ac.realm,
			err:   auth.ErrInvalidCredential,
		}
	}

	opts := gophercloud.AuthOptions{
		IdentityEndpoint: ac.endpoint,
		Username:         username,
		Password:         password,
		DomainID:         "default",
	}

	if !cacheCheck(username, password){
		if _, err := openstack.AuthenticatedClient(opts); err != nil {
			dcontext.GetLogger(ctx).Errorf("error authenticating user %q: %v", username, err)
			return nil, &challenge{
				realm: ac.realm,
				err:   auth.ErrAuthenticationFailure,
			}
		}
		cacheStore(username, password)
	}

	return auth.WithUser(ctx, auth.UserInfo{Name: username}), nil
}

// AuthenticateUser checks a given user:password credential by keystone.
// If the check passes, nil is returned.
func (ac *accessController) AuthenticateUser(username string, password string) error {

	opts := gophercloud.AuthOptions{
		IdentityEndpoint: ac.endpoint,
		Username:         username,
		Password:         password,
		DomainID:         "default",
	}

        if !cacheCheck(username, password){
		if _, err := openstack.AuthenticatedClient(opts); err != nil {
			dcontext.GetLogger(context.Background()).Errorf("error authenticating user %q: %v", username, err)
			return auth.ErrAuthenticationFailure
		}
                cacheStore(username, password)
	}

	return nil
}

// challenge implements the auth.Challenge interface.
type challenge struct {
	realm string
	err   error
}

var _ auth.Challenge = challenge{}

// SetHeaders sets the basic challenge header on the response.
func (ch challenge) SetHeaders(r *http.Request, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", ch.realm))
}

func (ch challenge) Error() string {
	return fmt.Sprintf("basic authentication challenge for realm %q: %s", ch.realm, ch.err)
}

func init() {
	auth.Register("keystone", auth.InitFunc(newAccessController))
}
