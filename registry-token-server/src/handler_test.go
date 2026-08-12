//
// Copyright (c) 2026 Wind River Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
)

// mockAccessController implements auth.AccessController for testing
type mockAccessController struct {
	authorizedUser string
	shouldFail     bool
	failChallenge  bool
}

func (m *mockAccessController) Authorized(ctx context.Context, access ...auth.Access) (context.Context, error) {
	if m.shouldFail {
		if m.failChallenge {
			return nil, &mockChallenge{realm: "test"}
		}
		return nil, auth.ErrAuthenticationFailure
	}
	return auth.WithUser(ctx, auth.UserInfo{Name: m.authorizedUser}), nil
}

type mockChallenge struct {
	realm string
}

func (c *mockChallenge) SetHeaders(r *http.Request, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\""+c.realm+"\"")
}

func (c *mockChallenge) Error() string {
	return "mock challenge"
}

func newTestTokenServer(user string, shouldFail, failChallenge bool) *tokenServer {
	issuer, _ := newTestIssuer()
	return &tokenServer{
		issuer: issuer,
		accessController: &mockAccessController{
			authorizedUser: user,
			shouldFail:     shouldFail,
			failChallenge:  failChallenge,
		},
		refreshCache: map[string]refreshToken{},
	}
}

// --- handleError tests ---

func TestHandleError(t *testing.T) {
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/token/", nil)
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	handleError(ctx, ErrorBadTokenOption.WithDetail("test"), w)

	if w.Code == 0 {
		t.Error("expected non-zero status code")
	}
}

// --- handlerWithContext tests ---

func TestHandlerWithContext(t *testing.T) {
	ctx := dcontext.Background()
	called := false
	handler := handlerWithContext(ctx, func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler was not called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- getToken tests ---

func TestGetToken_Success(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/token/?service=registry&scope=repository:myrepo:pull", nil)
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.getToken(ctx, w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp tokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
}

func TestGetToken_WithOfflineToken(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/token/?service=registry&scope=repository:myrepo:pull&offline_token=true", nil)
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.getToken(ctx, w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp tokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh token for offline request")
	}
}

func TestGetToken_BadOfflineParam(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/token/?service=registry&offline_token=notabool", nil)
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.getToken(ctx, w, req)

	if w.Code == http.StatusOK {
		t.Error("expected error for bad offline_token param")
	}
}

func TestGetToken_AuthFailure(t *testing.T) {
	ts := newTestTokenServer("", true, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/token/?service=registry", nil)
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.getToken(ctx, w, req)

	if w.Code == http.StatusOK {
		t.Error("expected auth failure")
	}
}

func TestGetToken_AuthChallenge(t *testing.T) {
	ts := newTestTokenServer("", true, true)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/token/?service=registry", nil)
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.getToken(ctx, w, req)

	authHeader := w.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Error("expected WWW-Authenticate header on challenge")
	}
}

func TestGetToken_NoScope(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/token/?service=registry", nil)
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.getToken(ctx, w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with no scope, got %d", w.Code)
	}
}

func TestGetToken_ExpiresIn(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ts.issuer.Expiration = 10 * time.Minute
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/token/?service=registry", nil)
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.getToken(ctx, w, req)

	var resp tokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.ExpiresIn != 600 {
		t.Errorf("expected 600 seconds, got %d", resp.ExpiresIn)
	}
}

// --- postToken tests ---

func TestPostToken_MissingGrantType(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == http.StatusOK {
		t.Error("expected error for missing grant_type")
	}
}

func TestPostToken_MissingService(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{"grant_type": {"password"}}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == http.StatusOK {
		t.Error("expected error for missing service")
	}
}

func TestPostToken_MissingClientID(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{"grant_type": {"password"}, "service": {"registry"}}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == http.StatusOK {
		t.Error("expected error for missing client_id")
	}
}

func TestPostToken_InvalidAccessType(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type":  {"password"},
		"service":     {"registry"},
		"client_id":   {"docker"},
		"access_type": {"invalid"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == http.StatusOK {
		t.Error("expected error for invalid access_type")
	}
}

func TestPostToken_UnknownGrantType(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type": {"unknown"},
		"service":    {"registry"},
		"client_id":  {"docker"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == http.StatusOK {
		t.Error("expected error for unknown grant_type")
	}
}

func TestPostToken_RefreshToken_Missing(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type": {"refresh_token"},
		"service":    {"registry"},
		"client_id":  {"docker"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == http.StatusOK {
		t.Error("expected error for missing refresh_token")
	}
}

func TestPostToken_RefreshToken_Invalid(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"service":       {"registry"},
		"client_id":     {"docker"},
		"refresh_token": {"invalid-token"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == http.StatusOK {
		t.Error("expected error for invalid refresh_token")
	}
}

func TestPostToken_RefreshToken_Valid(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	// Pre-populate refresh cache
	ts.refreshCache["valid-refresh"] = refreshToken{subject: "testuser", service: "registry"}

	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"service":       {"registry"},
		"client_id":     {"docker"},
		"refresh_token": {"valid-refresh"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp postTokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
}

func TestPostToken_RefreshToken_WrongService(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ts.refreshCache["valid-refresh"] = refreshToken{subject: "testuser", service: "other-service"}

	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"service":       {"registry"},
		"client_id":     {"docker"},
		"refresh_token": {"valid-refresh"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == http.StatusOK {
		t.Error("expected error for wrong service")
	}
}

func TestPostToken_Password_MissingUsername(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type": {"password"},
		"service":    {"registry"},
		"client_id":  {"docker"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	// mockAccessController doesn't implement CredentialAuthenticator
	// so password grant type is not supported
	if w.Code == http.StatusOK {
		t.Error("expected error")
	}
}

func TestPostToken_OfflineAccessType(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ts.refreshCache["valid-refresh"] = refreshToken{subject: "testuser", service: "registry"}

	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"service":       {"registry"},
		"client_id":     {"docker"},
		"refresh_token": {"valid-refresh"},
		"access_type":   {"offline"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp postTokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.RefreshToken == "" {
		t.Error("expected refresh token for offline access")
	}
}

func TestPostToken_OnlineAccessType(t *testing.T) {
	ts := newTestTokenServer("testuser", false, false)
	ts.refreshCache["valid-refresh"] = refreshToken{subject: "testuser", service: "registry"}

	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"service":       {"registry"},
		"client_id":     {"docker"},
		"refresh_token": {"valid-refresh"},
		"access_type":   {"online"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestPostToken_WithScope(t *testing.T) {
	ts := newTestTokenServer("admin", false, false)
	ts.refreshCache["valid-refresh"] = refreshToken{subject: "admin", service: "registry"}

	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"service":       {"registry"},
		"client_id":     {"docker"},
		"refresh_token": {"valid-refresh"},
		"scope":         {"repository:myrepo:pull"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp postTokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.IssuedAt == "" {
		t.Error("expected issued_at in response")
	}
}

func TestHandleError_Success(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := dcontext.WithLogger(
		context.Background(),
		dcontext.GetLogger(context.Background()),
	)
	testErr := ErrorBadTokenOption.WithDetail("test")
	handleError(ctx, testErr, w)
	if w.Code == 0 {
		t.Error("expected non-zero status code")
	}
}
