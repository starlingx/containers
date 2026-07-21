//
// Copyright (c) 2026 Wind River Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
)

// mockCredentialAC implements both AccessController and CredentialAuthenticator
type mockCredentialAC struct {
	authorizedUser string
	validUsers     map[string]string // username -> password
}

func (m *mockCredentialAC) Authorized(ctx context.Context, access ...auth.Access) (context.Context, error) {
	return auth.WithUser(ctx, auth.UserInfo{Name: m.authorizedUser}), nil
}

func (m *mockCredentialAC) AuthenticateUser(username, password string) error {
	if pass, ok := m.validUsers[username]; ok && pass == password {
		return nil
	}
	return auth.ErrAuthenticationFailure
}

func newTestTokenServerWithCreds(validUsers map[string]string) *tokenServer {
	issuer, _ := newTestIssuer()
	return &tokenServer{
		issuer: issuer,
		accessController: &mockCredentialAC{
			authorizedUser: "admin",
			validUsers:     validUsers,
		},
		refreshCache: map[string]refreshToken{},
	}
}

func TestPostToken_Password_Success(t *testing.T) {
	ts := newTestTokenServerWithCreds(map[string]string{"testuser": "testpass"})
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type": {"password"},
		"service":    {"registry"},
		"client_id":  {"docker"},
		"username":   {"testuser"},
		"password":   {"testpass"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp postTokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
}

func TestPostToken_Password_InvalidCreds(t *testing.T) {
	ts := newTestTokenServerWithCreds(map[string]string{"testuser": "testpass"})
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type": {"password"},
		"service":    {"registry"},
		"client_id":  {"docker"},
		"username":   {"testuser"},
		"password":   {"wrongpass"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == 200 {
		t.Error("expected error for invalid credentials")
	}
}

func TestPostToken_Password_MissingPassword(t *testing.T) {
	ts := newTestTokenServerWithCreds(map[string]string{"testuser": "testpass"})
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type": {"password"},
		"service":    {"registry"},
		"client_id":  {"docker"},
		"username":   {"testuser"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == 200 {
		t.Error("expected error for missing password")
	}
}

func TestPostToken_Password_MissingUsernameWithCreds(t *testing.T) {
	ts := newTestTokenServerWithCreds(map[string]string{"testuser": "testpass"})
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type": {"password"},
		"service":    {"registry"},
		"client_id":  {"docker"},
		"password":   {"testpass"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code == 200 {
		t.Error("expected error for missing username")
	}
}

func TestPostToken_Password_WithOffline(t *testing.T) {
	ts := newTestTokenServerWithCreds(map[string]string{"testuser": "testpass"})
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type":  {"password"},
		"service":     {"registry"},
		"client_id":   {"docker"},
		"username":    {"testuser"},
		"password":    {"testpass"},
		"access_type": {"offline"},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp postTokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.RefreshToken == "" {
		t.Error("expected refresh token for offline access")
	}
}

func TestPostToken_EmptyAccessType(t *testing.T) {
	ts := newTestTokenServerWithCreds(map[string]string{"testuser": "testpass"})
	ctx := dcontext.Background()
	w := httptest.NewRecorder()
	form := url.Values{
		"grant_type":  {"password"},
		"service":     {"registry"},
		"client_id":   {"docker"},
		"username":    {"testuser"},
		"password":    {"testpass"},
		"access_type": {""},
	}
	req := httptest.NewRequest("POST", "/token/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = dcontext.WithRequest(ctx, req)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	ts.postToken(ctx, w, req)

	if w.Code != 200 {
		t.Errorf("expected 200 for empty access_type, got %d", w.Code)
	}
}
