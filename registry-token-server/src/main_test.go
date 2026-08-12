//
// Copyright (c) 2026 Wind River Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"context"
	"testing"

	"github.com/docker/distribution/registry/auth"
)

// --- newRefreshToken tests ---

func TestNewRefreshToken_Length(t *testing.T) {
	token := newRefreshToken()
	if len(token) != refreshTokenLength {
		t.Errorf("expected length %d, got %d", refreshTokenLength, len(token))
	}
}

func TestNewRefreshToken_Unique(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok := newRefreshToken()
		if tokens[tok] {
			t.Errorf("duplicate token generated: %s", tok)
		}
		tokens[tok] = true
	}
}

func TestNewRefreshToken_ValidChars(t *testing.T) {
	token := newRefreshToken()
	valid := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for _, c := range token {
		found := false
		for _, v := range valid {
			if c == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("invalid character in token: %c", c)
		}
	}
}

// --- filterAccessList tests ---

func TestFilterAccessList_AdminFullAccess(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "somerepo"}, Action: "pull"},
		{Resource: auth.Resource{Type: "repository", Name: "somerepo"}, Action: "push"},
	}
	result := filterAccessList(ctx, "admin", accessList)
	if len(result) != 2 {
		t.Errorf("admin should have full access, got %d", len(result))
	}
}

func TestFilterAccessList_SysinvFullAccess(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "anyrepo"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "sysinv", accessList)
	if len(result) != 1 {
		t.Errorf("sysinv should have full access, got %d", len(result))
	}
}

func TestFilterAccessList_UserOwnRepo(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "testuser/myimage"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "testuser", accessList)
	if len(result) != 1 {
		t.Errorf("user should access own repo, got %d", len(result))
	}
}

func TestFilterAccessList_UserOtherRepo(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "otheruser/image"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "testuser", accessList)
	if len(result) != 0 {
		t.Errorf("user should not access other's repo, got %d", len(result))
	}
}

func TestFilterAccessList_PublicRepoPull(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "public/myimage"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "anyuser", accessList)
	if len(result) != 1 {
		t.Errorf("public repo pull should be allowed, got %d", len(result))
	}
}

func TestFilterAccessList_PublicRepoPush(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "public/myimage"}, Action: "push"},
	}
	result := filterAccessList(ctx, "randomuser", accessList)
	// push to public repo by non-admin should be denied (no prefix match, no skip)
	if len(result) != 0 {
		t.Errorf("public repo push by non-owner should be denied, got %d", len(result))
	}
}

func TestFilterAccessList_PublicImagePause(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "k8s.gcr.io/pause"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "anyuser", accessList)
	if len(result) != 1 {
		t.Errorf("k8s.gcr.io/pause pull should be allowed, got %d", len(result))
	}
}

func TestFilterAccessList_PublicImageRegistryPause(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "registry.k8s.io/pause"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "anyuser", accessList)
	if len(result) != 1 {
		t.Errorf("registry.k8s.io/pause pull should be allowed, got %d", len(result))
	}
}

func TestFilterAccessList_PublicImageN3000(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "docker.io/starlingx/n3000-opae"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "anyuser", accessList)
	if len(result) != 1 {
		t.Errorf("n3000-opae pull should be allowed, got %d", len(result))
	}
}

func TestFilterAccessList_PublicImageAcmesolver(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "quay.io/jetstack/cert-manager-acmesolver"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "anyuser", accessList)
	if len(result) != 1 {
		t.Errorf("acmesolver pull should be allowed, got %d", len(result))
	}
}

func TestFilterAccessList_MtceBlocked(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "mtce/image"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "mtce", accessList)
	if len(result) != 0 {
		t.Errorf("mtce should not access mtce/ repo, got %d", len(result))
	}
}

func TestFilterAccessList_AdminAccessMtce(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "mtce/image"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "admin", accessList)
	if len(result) != 1 {
		t.Errorf("admin should access mtce/ repo, got %d", len(result))
	}
}

func TestFilterAccessList_RegistryCatalog(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "registry", Name: "catalog"}, Action: "*"},
	}
	result := filterAccessList(ctx, "admin", accessList)
	if len(result) != 1 {
		t.Errorf("catalog access should be allowed, got %d", len(result))
	}
}

func TestFilterAccessList_RegistryUnknown(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "registry", Name: "unknown"}, Action: "*"},
	}
	result := filterAccessList(ctx, "admin", accessList)
	if len(result) != 0 {
		t.Errorf("unknown registry resource should be denied, got %d", len(result))
	}
}

func TestFilterAccessList_UnsupportedType(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "unsupported", Name: "thing"}, Action: "pull"},
	}
	result := filterAccessList(ctx, "admin", accessList)
	if len(result) != 0 {
		t.Errorf("unsupported type should be denied, got %d", len(result))
	}
}

func TestFilterAccessList_EmptyList(t *testing.T) {
	ctx := context.Background()
	result := filterAccessList(ctx, "admin", []auth.Access{})
	if len(result) != 0 {
		t.Errorf("empty list should return empty, got %d", len(result))
	}
}

func TestFilterAccessList_EnforceRepoClass(t *testing.T) {
	// Save and restore global state
	origEnforce := enforceRepoClass
	origCache := repositoryClassCache
	defer func() {
		enforceRepoClass = origEnforce
		repositoryClassCache = origCache
	}()

	enforceRepoClass = true
	repositoryClassCache = map[string]string{}

	ctx := context.Background()

	// First push sets the class
	pushAccess := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "user/repo", Class: "image"}, Action: "push"},
	}
	result := filterAccessList(ctx, "user", pushAccess)
	if len(result) != 1 {
		t.Errorf("first push should be allowed, got %d", len(result))
	}

	// Same class should be allowed
	pullAccess := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "user/repo", Class: "image"}, Action: "pull"},
	}
	result = filterAccessList(ctx, "user", pullAccess)
	if len(result) != 1 {
		t.Errorf("same class should be allowed, got %d", len(result))
	}

	// Different class should be denied
	diffClassAccess := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "user/repo", Class: "plugin"}, Action: "pull"},
	}
	result = filterAccessList(ctx, "user", diffClassAccess)
	if len(result) != 0 {
		t.Errorf("different class should be denied, got %d", len(result))
	}
}

func TestFilterAccessList_ScopeTrailingSlash(t *testing.T) {
	ctx := context.Background()
	accessList := []auth.Access{
		{Resource: auth.Resource{Type: "repository", Name: "testuser/image"}, Action: "pull"},
	}
	// scope without trailing slash should still work
	result := filterAccessList(ctx, "testuser", accessList)
	if len(result) != 1 {
		t.Errorf("expected 1 access, got %d", len(result))
	}
}

// --- struct String() method tests ---

func TestAcctSubject_String(t *testing.T) {
	s := acctSubject{}
	if s.String() != "acctSubject" {
		t.Errorf("expected 'acctSubject', got '%s'", s.String())
	}
}

func TestRequestedAccess_String(t *testing.T) {
	s := requestedAccess{}
	if s.String() != "requestedAccess" {
		t.Errorf("expected 'requestedAccess', got '%s'", s.String())
	}
}

func TestGrantedAccess_String(t *testing.T) {
	s := grantedAccess{}
	if s.String() != "grantedAccess" {
		t.Errorf("expected 'grantedAccess', got '%s'", s.String())
	}
}
