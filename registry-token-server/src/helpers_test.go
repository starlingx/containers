//
// Copyright (c) 2026 Wind River Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"time"

	"github.com/docker/libtrust"
)

// newTestIssuer creates a TokenIssuer with a generated key for testing.
func newTestIssuer() (*TokenIssuer, error) {
	key, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		return nil, err
	}
	return &TokenIssuer{
		Issuer:     "test-issuer",
		SigningKey:  key,
		Expiration: 15 * time.Minute,
	}, nil
}
