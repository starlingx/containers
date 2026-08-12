//
// Copyright (c) 2026 Wind River Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"testing"
)

func TestErrorBadTokenOption_HasMessage(t *testing.T) {
	msg := ErrorBadTokenOption.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}

func TestErrorMissingRequiredField_HasMessage(t *testing.T) {
	msg := ErrorMissingRequiredField.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}

func TestErrorUnsupportedValue_HasMessage(t *testing.T) {
	msg := ErrorUnsupportedValue.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}

func TestErrorBadTokenOption_WithDetail(t *testing.T) {
	err := ErrorBadTokenOption.WithDetail("test detail")
	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error with detail")
	}
}

func TestErrorMissingRequiredField_WithDetail(t *testing.T) {
	err := ErrorMissingRequiredField.WithDetail("missing field")
	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error with detail")
	}
}

func TestErrorUnsupportedValue_WithDetail(t *testing.T) {
	err := ErrorUnsupportedValue.WithDetail("bad value")
	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error with detail")
	}
}
