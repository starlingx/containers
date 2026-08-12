//
// Copyright (c) 2026 Wind River Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"context"
	"testing"
	"time"

	"github.com/docker/distribution/registry/auth"
	"github.com/docker/libtrust"
)

func TestResolveScopeSpecifiers_ValidScope(t *testing.T) {
	ctx := context.Background()
	specs := []string{"repository:myrepo:pull"}
	result := ResolveScopeSpecifiers(ctx, specs)
	if len(result) != 1 {
		t.Fatalf("expected 1 access, got %d", len(result))
	}
	if result[0].Type != "repository" || result[0].Name != "myrepo" || result[0].Action != "pull" {
		t.Errorf("unexpected access: %+v", result[0])
	}
}

func TestResolveScopeSpecifiers_MultipleActions(t *testing.T) {
	ctx := context.Background()
	specs := []string{"repository:myrepo:pull,push"}
	result := ResolveScopeSpecifiers(ctx, specs)
	if len(result) != 2 {
		t.Fatalf("expected 2 access entries, got %d", len(result))
	}
}

func TestResolveScopeSpecifiers_InvalidFormat(t *testing.T) {
	ctx := context.Background()
	specs := []string{"invalid-scope"}
	result := ResolveScopeSpecifiers(ctx, specs)
	if len(result) != 0 {
		t.Errorf("expected 0 access for invalid scope, got %d", len(result))
	}
}

func TestResolveScopeSpecifiers_TwoParts(t *testing.T) {
	ctx := context.Background()
	specs := []string{"repository:myrepo"}
	result := ResolveScopeSpecifiers(ctx, specs)
	if len(result) != 0 {
		t.Errorf("expected 0 access for 2-part scope, got %d", len(result))
	}
}

func TestResolveScopeSpecifiers_EmptyList(t *testing.T) {
	ctx := context.Background()
	result := ResolveScopeSpecifiers(ctx, []string{})
	if len(result) != 0 {
		t.Errorf("expected 0 access for empty list, got %d", len(result))
	}
}

func TestResolveScopeSpecifiers_WithClass(t *testing.T) {
	ctx := context.Background()
	specs := []string{"repository(class1):myrepo:pull"}
	result := ResolveScopeSpecifiers(ctx, specs)
	if len(result) != 1 {
		t.Fatalf("expected 1 access, got %d", len(result))
	}
	if result[0].Class != "class1" {
		t.Errorf("expected class 'class1', got '%s'", result[0].Class)
	}
}

func TestResolveScopeSpecifiers_DuplicateScopes(t *testing.T) {
	ctx := context.Background()
	specs := []string{"repository:myrepo:pull", "repository:myrepo:pull"}
	result := ResolveScopeSpecifiers(ctx, specs)
	if len(result) != 1 {
		t.Errorf("expected 1 deduplicated access, got %d", len(result))
	}
}

func TestResolveScopeSpecifiers_MultipleScopes(t *testing.T) {
	ctx := context.Background()
	specs := []string{"repository:repo1:pull", "repository:repo2:push"}
	result := ResolveScopeSpecifiers(ctx, specs)
	if len(result) != 2 {
		t.Errorf("expected 2 access entries, got %d", len(result))
	}
}

func TestResolveScopeSpecifiers_EmptyResourceType(t *testing.T) {
	ctx := context.Background()
	specs := []string{"INVALID_TYPE:myrepo:pull"}
	result := ResolveScopeSpecifiers(ctx, specs)
	if len(result) != 0 {
		t.Errorf("expected 0 for invalid type, got %d", len(result))
	}
}

func TestSplitResourceClass_NoClass(t *testing.T) {
	rt, rc := splitResourceClass("repository")
	if rt != "repository" || rc != "" {
		t.Errorf("expected ('repository',''), got ('%s','%s')", rt, rc)
	}
}

func TestSplitResourceClass_WithClass(t *testing.T) {
	rt, rc := splitResourceClass("repository(image)")
	if rt != "repository" || rc != "image" {
		t.Errorf("expected ('repository','image'), got ('%s','%s')", rt, rc)
	}
}

func TestSplitResourceClass_Invalid(t *testing.T) {
	rt, rc := splitResourceClass("INVALID")
	if rt != "" || rc != "" {
		t.Errorf("expected ('',''), got ('%s','%s')", rt, rc)
	}
}

func TestSplitResourceClass_Empty(t *testing.T) {
	rt, rc := splitResourceClass("")
	if rt != "" || rc != "" {
		t.Errorf("expected ('',''), got ('%s','%s')", rt, rc)
	}
}

func TestSplitResourceClass_EmptyParens(t *testing.T) {
	rt, rc := splitResourceClass("repository()")
	// regex requires at least one char inside parens, so () doesn't match
	if rt != "" || rc != "" {
		t.Errorf("expected ('','') for empty parens, got ('%s','%s')", rt, rc)
	}
}

func TestResolveScopeList_Single(t *testing.T) {
	ctx := context.Background()
	result := ResolveScopeList(ctx, "repository:myrepo:pull")
	if len(result) != 1 {
		t.Fatalf("expected 1 access, got %d", len(result))
	}
}

func TestResolveScopeList_Multiple(t *testing.T) {
	ctx := context.Background()
	result := ResolveScopeList(ctx, "repository:repo1:pull repository:repo2:push")
	if len(result) != 2 {
		t.Errorf("expected 2 access entries, got %d", len(result))
	}
}

func TestResolveScopeList_Empty(t *testing.T) {
	ctx := context.Background()
	result := ResolveScopeList(ctx, "")
	// empty string split gives [""] which is invalid format
	for _, a := range result {
		t.Errorf("unexpected access: %+v", a)
	}
}

func TestScopeString_NoClass(t *testing.T) {
	a := auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "myrepo"},
		Action:   "pull",
	}
	s := scopeString(a)
	if s != "repository:myrepo:pull" {
		t.Errorf("expected 'repository:myrepo:pull', got '%s'", s)
	}
}

func TestScopeString_WithClass(t *testing.T) {
	a := auth.Access{
		Resource: auth.Resource{Type: "repository", Class: "image", Name: "myrepo"},
		Action:   "pull",
	}
	s := scopeString(a)
	expected := "repository(image):myrepo:pull"
	if s != expected {
		t.Errorf("expected '%s', got '%s'", expected, s)
	}
}

func TestToScopeList_Empty(t *testing.T) {
	result := ToScopeList([]auth.Access{})
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestToScopeList_Single(t *testing.T) {
	access := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "repo1"}, Action: "pull"},
	}
	result := ToScopeList(access)
	if result != "repository:repo1:pull" {
		t.Errorf("expected 'repository:repo1:pull', got '%s'", result)
	}
}

func TestToScopeList_Multiple(t *testing.T) {
	access := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "repo1"}, Action: "pull"},
		{Resource: auth.Resource{Type: "repository", Name: "repo2"}, Action: "push"},
	}
	result := ToScopeList(access)
	if result == "" {
		t.Error("expected non-empty scope list")
	}
}

func TestJoseBase64Encode(t *testing.T) {
	data := []byte("hello world")
	encoded := joseBase64Encode(data)
	if encoded == "" {
		t.Error("expected non-empty encoded string")
	}
	// Should not end with '='
	if len(encoded) > 0 && encoded[len(encoded)-1] == '=' {
		t.Error("encoded string should not end with '='")
	}
}

func TestJoseBase64Encode_Empty(t *testing.T) {
	encoded := joseBase64Encode([]byte{})
	if encoded != "" {
		t.Errorf("expected empty string for empty input, got '%s'", encoded)
	}
}

func TestCreateJWT_Success(t *testing.T) {
	issuer, err := newTestIssuer()
	if err != nil {
		t.Fatalf("failed to create test issuer: %v", err)
	}
	access := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "myrepo"}, Action: "pull"},
	}
	token, err := issuer.CreateJWT("testuser", "testservice", access)
	if err != nil {
		t.Fatalf("CreateJWT failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
	// JWT should have 3 parts separated by dots
	parts := 0
	for _, c := range token {
		if c == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("expected JWT with 2 dots, got %d", parts)
	}
}

func TestCreateJWT_EmptyAccess(t *testing.T) {
	issuer, err := newTestIssuer()
	if err != nil {
		t.Fatalf("failed to create test issuer: %v", err)
	}
	token, err := issuer.CreateJWT("testuser", "testservice", []auth.Access{})
	if err != nil {
		t.Fatalf("CreateJWT failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token even with empty access")
	}
}

func TestCreateJWT_MultipleAccess(t *testing.T) {
	issuer, err := newTestIssuer()
	if err != nil {
		t.Fatalf("failed to create test issuer: %v", err)
	}
	access := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "repo1"}, Action: "pull"},
		{Resource: auth.Resource{Type: "repository", Name: "repo1"}, Action: "push"},
		{Resource: auth.Resource{Type: "repository", Name: "repo2"}, Action: "pull"},
	}
	token, err := issuer.CreateJWT("admin", "registry", access)
	if err != nil {
		t.Fatalf("CreateJWT failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

func TestCreateJWT_ZeroExpiration(t *testing.T) {
	issuer, err := newTestIssuer()
	if err != nil {
		t.Fatalf("failed to create test issuer: %v", err)
	}
	issuer.Expiration = 0 // should default to 5 minutes
	token, err := issuer.CreateJWT("user", "svc", []auth.Access{})
	if err != nil {
		t.Fatalf("CreateJWT with zero expiration failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

func TestCreateJWT_WithClass(t *testing.T) {
	issuer, err := newTestIssuer()
	if err != nil {
		t.Fatalf("failed to create test issuer: %v", err)
	}
	access := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Class: "image", Name: "repo1"}, Action: "pull"},
	}
	token, err := issuer.CreateJWT("user", "svc", access)
	if err != nil {
		t.Fatalf("CreateJWT failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

func TestCreateJWT_RSAKey(t *testing.T) {
	key, err := libtrust.GenerateRSA2048PrivateKey()
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	issuer := &TokenIssuer{
		Issuer:     "test-issuer",
		SigningKey:  key,
		Expiration: 15 * time.Minute,
	}
	access := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "myrepo"}, Action: "pull"},
	}
	token, err := issuer.CreateJWT("testuser", "testservice", access)
	if err != nil {
		t.Fatalf("CreateJWT with RSA key failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

func TestCreateJWT_ECKey(t *testing.T) {
	key, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	issuer := &TokenIssuer{
		Issuer:     "test-issuer",
		SigningKey:  key,
		Expiration: 5 * time.Minute,
	}
	accessEntries := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "test"}, Action: "pull"},
	}
	jwtToken, err := issuer.CreateJWT("user", "registry", accessEntries)
	if err != nil {
		t.Fatalf("CreateJWT with EC key failed: %v", err)
	}
	if jwtToken == "" {
		t.Error("expected non-empty token")
	}
}
