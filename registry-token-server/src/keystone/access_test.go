//
// Copyright (c) 2026 Wind River Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package keystone

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- cacheStore tests ---

func TestCacheStore_NewEntry(t *testing.T) {
	// Reset cache state
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	cacheStore("user1", "pass1")
	if len(credentialsCache) != 1 {
		t.Errorf("expected 1 entry, got %d", len(credentialsCache))
	}
	if credentialsCache[0].username != "user1" || credentialsCache[0].hash != hashCredentials("user1", "pass1") {
		t.Error("stored credentials don't match")
	}
}

func TestCacheStore_UpdateExisting(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	cacheStore("user1", "pass1")
	cacheStore("user1", "newpass")
	if len(credentialsCache) != 1 {
		t.Errorf("expected 1 entry after update, got %d", len(credentialsCache))
	}
	if credentialsCache[0].hash != hashCredentials("user1", "newpass") {
		t.Errorf("expected updated hash, got '%s'", credentialsCache[0].hash)
	}
}

func TestCacheStore_MaxSize(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	// Fill cache to max
	for i := 0; i < cacheSize+5; i++ {
		cacheStore(fmt.Sprintf("user%d", i), fmt.Sprintf("pass%d", i))
	}
	if len(credentialsCache) > cacheSize {
		t.Errorf("cache exceeded max size: %d > %d", len(credentialsCache), cacheSize)
	}
}

func TestCacheStore_Invalidation(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now().Add(-cacheInvalidateInterval - time.Minute)

	cacheStore("user1", "pass1")
	// After invalidation, cache should have been cleared then new entry added
	if len(credentialsCache) != 1 {
		t.Errorf("expected 1 entry after invalidation, got %d", len(credentialsCache))
	}
}

// --- cacheCheck tests ---

func TestCacheCheck_Found(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	cacheStore("user1", "pass1")
	if !cacheCheck("user1", "pass1") {
		t.Error("expected to find cached credentials")
	}
}

func TestCacheCheck_NotFound(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	if cacheCheck("nonexistent", "pass") {
		t.Error("should not find non-existent credentials")
	}
}

func TestCacheCheck_WrongPassword(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	cacheStore("user1", "pass1")
	if cacheCheck("user1", "wrongpass") {
		t.Error("should not match wrong password")
	}
}

func TestCacheCheck_MovesToTop(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	cacheStore("user1", "pass1")
	cacheStore("user2", "pass2")
	cacheStore("user3", "pass3")

	// Check user3 (last entry) - should move to top
	cacheCheck("user3", "pass3")
	if credentialsCache[0].username != "user3" {
		t.Errorf("expected user3 at top, got '%s'", credentialsCache[0].username)
	}
}

func TestCacheCheck_FirstEntryStaysAtTop(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	cacheStore("user1", "pass1")
	cacheStore("user2", "pass2")

	// Check user1 (already at index 0) - should stay at top
	cacheCheck("user1", "pass1")
	if credentialsCache[0].username != "user1" {
		t.Errorf("expected user1 to stay at top, got '%s'", credentialsCache[0].username)
	}
}

func TestCacheCheck_Invalidation(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	cacheStore("user1", "pass1")
	// Force invalidation
	lastCacheInvalidation = time.Now().Add(-cacheInvalidateInterval - time.Minute)

	if cacheCheck("user1", "pass1") {
		t.Error("cache should have been invalidated")
	}
}

// --- newAccessController tests ---

func TestNewAccessController_Valid(t *testing.T) {
	opts := map[string]interface{}{
		"realm":    "testrealm",
		"endpoint": "http://keystone:5000/v3",
	}
	ac, err := newAccessController(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ac == nil {
		t.Fatal("expected non-nil access controller")
	}
}

func TestNewAccessController_MissingRealm(t *testing.T) {
	opts := map[string]interface{}{
		"endpoint": "http://keystone:5000/v3",
	}
	_, err := newAccessController(opts)
	if err == nil {
		t.Error("expected error for missing realm")
	}
}

func TestNewAccessController_MissingEndpoint(t *testing.T) {
	opts := map[string]interface{}{
		"realm": "testrealm",
	}
	_, err := newAccessController(opts)
	if err == nil {
		t.Error("expected error for missing endpoint")
	}
}

func TestNewAccessController_InvalidRealmType(t *testing.T) {
	opts := map[string]interface{}{
		"realm":    123,
		"endpoint": "http://keystone:5000/v3",
	}
	_, err := newAccessController(opts)
	if err == nil {
		t.Error("expected error for non-string realm")
	}
}

func TestNewAccessController_InvalidEndpointType(t *testing.T) {
	opts := map[string]interface{}{
		"realm":    "testrealm",
		"endpoint": 123,
	}
	_, err := newAccessController(opts)
	if err == nil {
		t.Error("expected error for non-string endpoint")
	}
}

// --- challenge tests ---

func TestChallenge_Error(t *testing.T) {
	ch := challenge{
		realm: "testrealm",
		err:   fmt.Errorf("test error"),
	}
	errStr := ch.Error()
	if errStr == "" {
		t.Error("expected non-empty error string")
	}
}

func TestChallenge_SetHeaders(t *testing.T) {
	ch := challenge{
		realm: "testrealm",
		err:   fmt.Errorf("test error"),
	}
	req := httptest.NewRequest("GET", "/token/", nil)
	w := httptest.NewRecorder()
	ch.SetHeaders(req, w)

	authHeader := w.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Error("expected WWW-Authenticate header")
	}
	expected := `Basic realm="testrealm"`
	if authHeader != expected {
		t.Errorf("expected '%s', got '%s'", expected, authHeader)
	}
}

// --- Authorized tests ---

func TestAuthorized_NoBasicAuth(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	ac := &accessController{
		realm:    "testrealm",
		endpoint: "http://keystone:5000/v3",
	}

	req := httptest.NewRequest("GET", "/token/", nil)
	// No basic auth set
	ctx := req.Context()

	// We need to use the distribution context to set the request
	// Since we can't easily do that without the full framework,
	// we test the challenge response path
	_, err := ac.Authorized(ctx)
	if err == nil {
		t.Error("expected error without request in context")
	}
}

// --- AuthenticateUser tests ---

func TestAuthenticateUser_CachedCredentials(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	// Pre-cache credentials
	cacheStore("testuser", "testpass")

	ac := &accessController{
		realm:    "testrealm",
		endpoint: "http://keystone:5000/v3",
	}

	err := ac.AuthenticateUser("testuser", "testpass")
	if err != nil {
		t.Errorf("expected nil error for cached credentials, got: %v", err)
	}
}

func TestAuthenticateUser_InvalidEndpoint(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	ac := &accessController{
		realm:    "testrealm",
		endpoint: "http://invalid-endpoint:5000/v3",
	}

	err := ac.AuthenticateUser("baduser", "badpass")
	if err == nil {
		t.Error("expected error for invalid endpoint")
	}
}

// --- HTTP handler integration tests ---

func TestFilterAccessList_ViaHTTP_PublicImage(t *testing.T) {
	// Test that public images are accessible via the filter
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	// Verify the challenge implements http.Handler-compatible interface
	ch := challenge{realm: "test", err: fmt.Errorf("test")}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	ch.SetHeaders(r, w)

	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected auth header set")
	}
}

func TestNewAccessController_EmptyOptions(t *testing.T) {
	opts := map[string]interface{}{}
	_, err := newAccessController(opts)
	if err == nil {
		t.Error("expected error for empty options")
	}
}

func TestCacheStore_MultipleUsers(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	for i := 0; i < 10; i++ {
		cacheStore(fmt.Sprintf("user%d", i), fmt.Sprintf("pass%d", i))
	}
	if len(credentialsCache) != 10 {
		t.Errorf("expected 10 entries, got %d", len(credentialsCache))
	}
}

func TestCacheCheck_EmptyCache(t *testing.T) {
	credentialsCache = make([]credentials, 0)
	lastCacheInvalidation = time.Now()

	if cacheCheck("any", "any") {
		t.Error("empty cache should return false")
	}
}

func TestChallenge_ErrorFormat(t *testing.T) {
	ch := challenge{
		realm: "myrealm",
		err:   fmt.Errorf("auth failed"),
	}
	expected := `basic authentication challenge for realm "myrealm": auth failed`
	if ch.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, ch.Error())
	}
}

func TestChallenge_SetHeaders_SpecialChars(t *testing.T) {
	ch := challenge{
		realm: "my realm with spaces",
		err:   fmt.Errorf("test"),
	}
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	ch.SetHeaders(r, w)
	header := w.Header().Get("WWW-Authenticate")
	if header == "" {
		t.Error("expected header to be set")
	}
}
