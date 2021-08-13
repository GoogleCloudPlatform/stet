// Copyright 2021 Google LLC
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

// Utility functions for processing DEK shares.

package client

import (
	"bytes"

	"crypto/sha256"
)

// HashShare performs a SHA-256 hash on the provided share.
func HashShare(share []byte) []byte {
	hash := sha256.Sum256(share)
	return hash[:]
}

// ValidateShare performs HashShare on the provided share, then returns whether
// the result is equal to the provided hash.
func ValidateShare(share []byte, expectedHash []byte) bool {
	actualHash := HashShare(share)
	return bytes.Equal(actualHash[:], expectedHash[:])
}
