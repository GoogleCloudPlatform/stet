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

package shares

import (
	"bytes"
	"testing"

	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/secrets"
	"github.com/google/go-cmp/cmp"
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

func TestSplitSharesAndCombineSharesRestoresSecret(t *testing.T) {
	var secret = random.GetRandomBytes(32)
	var nShares = 5
	var threshold = 3

	shares, err := SplitShares(secret, nShares, threshold)

	if err != nil {
		t.Fatalf("SplitShares(secret, %d, %d) failed with error %s", nShares, threshold, err)
	}
	if len(shares) != nShares {
		t.Fatalf("SplitShares(secret, %d, %d) returned %d shares, expected %d", nShares, threshold, len(shares), nShares)
	}

	// There are 5*4*3 possible permutations for recombining the secret.
	for i := 0; i < nShares; i++ {
		for j := 0; j < nShares; j++ {
			if j == i {
				continue
			}
			for k := 0; k < nShares; k++ {
				if k == i || k == j {
					continue
				}
				parts := []UnwrappedShare{
					{Share: shares[i]},
					{Share: shares[j]},
					{Share: shares[k]},
				}

				recomb, err := CombineShares(parts, nShares, threshold)
				if err != nil {
					t.Fatalf("err: %v", err)
				}

				if !bytes.Equal(recomb, secret) {
					t.Errorf("CombineShares(%v) = %v, want %v", parts, recomb, secret)
					t.Fatalf("Indices of shares were (i:%d, j:%d, k:%d)", i, j, k)
				}
			}
		}
	}
}

func TestConvertToByteShares(t *testing.T) {
	secretShares := []secrets.Share{
		{X: 0, Value: []byte("share 0")},
		{X: 1, Value: []byte("share 1")},
		{X: 2, Value: []byte("share 2")},
	}

	converted := convertToByteShares(secretShares)

	expected := [][]byte{
		append(secretShares[0].Value, byte(secretShares[0].X)),
		append(secretShares[1].Value, byte(secretShares[1].X)),
		append(secretShares[2].Value, byte(secretShares[2].X)),
	}

	for i, share := range converted {
		if !bytes.Equal(share, expected[i]) {
			t.Errorf("convertToByteShares(%v) = %v at index %d, want %v", secretShares, share, i, expected[i])
		}
	}
}

func TestConvertToSecretShares(t *testing.T) {
	expectedShares := []secrets.Share{
		{
			X:     0,
			Value: []byte("share 0"),
		},
		{
			X:     1,
			Value: []byte("share 1"),
		},
		{
			X:     2,
			Value: []byte("share 2"),
		},
	}

	unwrappedShares := []UnwrappedShare{
		{
			Share: append(expectedShares[0].Value, byte(expectedShares[0].X)),
			URI:   "uri 0",
		},
		{
			Share: append(expectedShares[1].Value, byte(expectedShares[1].X)),
			URI:   "uri 1",
		},
		{
			Share: append(expectedShares[2].Value, byte(expectedShares[2].X)),
			URI:   "uri 2",
		},
	}

	converted := convertToSecretShares(unwrappedShares)

	for i, share := range converted {
		if !cmp.Equal(share, expectedShares[i]) {
			t.Errorf("convertToSecretShares() = %v at index %d, want %v", share, i, expectedShares[i])
		}
	}
}
