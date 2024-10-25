// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package secrets contains types for secret sharing. When splitting a secret, a dealer needs
// to provide both the `secret` + `Metadata`. A dealer would then get a `Split`, which contains
// the `Metadata`, the secret shares, and the secret length.
package secrets

import (
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/finitefield"
)

// Metadata contains the necessary secret sharing scheme information to split and/or reconstruct a secret.
type Metadata struct {
	Field     finitefield.ID
	NumShares int
	Threshold int
}

// Split represents a secret split into shares alongside the metadata needed to reconstruct it.
type Split struct {
	Metadata Metadata
	Shares   []Share
	// The length of the original split secret in bytes.
	SecretLen int
}

// Share represents one share of a shared secret without any metadata.
type Share struct {
	Value []byte
	X     int
}
