//
// Copyright (c) 2026 Wind River Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package keystone

import (
	"net/http/httptest"
	"testing"
	"time"

	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
)

// --- Authorized with BasicAuth tests ---

func TestAuthorized_WithCachedCredentials(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()
	cacheStore("cacheduser", "cachedpass")

	ac := &accessController{
		realm:    "testrealm",
		endpoint: "http://keystone:5000/v3",
	}

	req := httptest.NewRequest("GET", "/token/", nil)
	req.SetBasicAuth("cacheduser", "cachedpass")
	ctx := dcontext.WithRequest(dcontext.Background(), req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	resultCtx, err := ac.Authorized(ctx)
	if err != nil {
		t.Fatalf("expected no error for cached credentials, got: %v", err)
	}
	if resultCtx == nil {
		t.Error("expected non-nil context")
	}
}

func TestAuthorized_WithInvalidCredentials(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	ac := &accessController{
		realm:    "testrealm",
		endpoint: "http://invalid-endpoint:5000/v3",
	}

	req := httptest.NewRequest("GET", "/token/", nil)
	req.SetBasicAuth("baduser", "badpass")
	ctx := dcontext.WithRequest(dcontext.Background(), req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	_, err := ac.Authorized(ctx)
	if err == nil {
		t.Error("expected error for invalid credentials")
	}
	// Should be a challenge
	if _, ok := err.(*challenge); !ok {
		t.Errorf("expected challenge error, got %T", err)
	}
}

func TestAuthorized_NoBasicAuth_Challenge(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	ac := &accessController{
		realm:    "testrealm",
		endpoint: "http://keystone:5000/v3",
	}

	req := httptest.NewRequest("GET", "/token/", nil)
	// No basic auth
	ctx := dcontext.WithRequest(dcontext.Background(), req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	_, err := ac.Authorized(ctx)
	if err == nil {
		t.Error("expected error without basic auth")
	}
	ch, ok := err.(*challenge)
	if !ok {
		t.Fatalf("expected challenge error, got %T", err)
	}
	if ch.realm != "testrealm" {
		t.Errorf("expected realm 'testrealm', got '%s'", ch.realm)
	}
}

func TestAuthorized_WithAccessRecords(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()
	cacheStore("testuser", "testpass")

	ac := &accessController{
		realm:    "testrealm",
		endpoint: "http://keystone:5000/v3",
	}

	req := httptest.NewRequest("GET", "/token/", nil)
	req.SetBasicAuth("testuser", "testpass")
	ctx := dcontext.WithRequest(dcontext.Background(), req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	access := auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "testuser/myrepo"},
		Action:   "pull",
	}
	resultCtx, err := ac.Authorized(ctx, access)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resultCtx == nil {
		t.Error("expected non-nil context")
	}
}

func TestAuthorized_SuccessStoresInCache(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()
	// Pre-cache so we don't need a real keystone
	cacheStore("newuser", "newpass")

	ac := &accessController{
		realm:    "testrealm",
		endpoint: "http://keystone:5000/v3",
	}

	req := httptest.NewRequest("GET", "/token/", nil)
	req.SetBasicAuth("newuser", "newpass")
	ctx := dcontext.WithRequest(dcontext.Background(), req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	_, err := ac.Authorized(ctx)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// Verify credentials are in cache
	if !cacheCheck("newuser", "newpass") {
		t.Error("expected credentials to be in cache after successful auth")
	}
}

func TestAuthenticateUser_SuccessStoresInCache(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()
	// Pre-cache
	cacheStore("authuser", "authpass")

	ac := &accessController{
		realm:    "testrealm",
		endpoint: "http://keystone:5000/v3",
	}

	err := ac.AuthenticateUser("authuser", "authpass")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !cacheCheck("authuser", "authpass") {
		t.Error("expected credentials in cache")
	}
}

func TestCacheStore_OverflowTruncates(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	// Fill to exactly cacheSize
	for i := 0; i < cacheSize; i++ {
		cacheStore("u"+string(rune('a'+i)), "p")
	}
	if len(credentialsCache) != cacheSize {
		t.Fatalf("expected %d entries, got %d", cacheSize, len(credentialsCache))
	}

	// Add one more - should truncate
	cacheStore("overflow", "pass")
	if len(credentialsCache) > cacheSize {
		t.Errorf("cache should not exceed %d, got %d", cacheSize, len(credentialsCache))
	}
}

func TestCacheCheck_MiddleEntry(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	cacheStore("user1", "pass1")
	cacheStore("user2", "pass2")
	cacheStore("user3", "pass3")
	cacheStore("user4", "pass4")

	// Check middle entry
	if !cacheCheck("user2", "pass2") {
		t.Error("expected to find user2")
	}
	// user2 should now be at top
	if credentialsCache[0].username != "user2" {
		t.Errorf("expected user2 at top, got %s", credentialsCache[0].username)
	}
}
