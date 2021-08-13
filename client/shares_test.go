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

package client

import (
	"testing"

	"github.com/google/tink/go/subtle/random"
)

func TestHashShareIsVerifiedByValidateShare(t *testing.T) {
	var share = random.GetRandomBytes(16)

	var hashed = HashShare(share)

	if !ValidateShare(share, hashed) {
		t.Fatalf("Got ValidateShare(share, HashShare(share)) = false, expected true")
	}
}

func TestValidateShareFailsForNonmatchingShareAndHash(t *testing.T) {
	// Generate two different shares and their hashes
	var share1 = random.GetRandomBytes(16)
	var share2 = random.GetRandomBytes(16)

	var hashed1 = HashShare(share1)
	var hashed2 = HashShare(share2)

	// Verify that ValidateShare fails for a given share and a hash of a different share
	if ValidateShare(share1, hashed2) { // if ValidateShare succeeds
		t.Fatalf("Got ValidateShare(share1, HashShare(share2)) = true, expected false")
	}

	if ValidateShare(share2, hashed1) { // if ValidateShare succeeds
		t.Fatalf("Got ValidateShare(share2, HashShare(share1)) = true, expected false")
	}
}
