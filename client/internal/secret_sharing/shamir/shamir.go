// Copyright 2022 Google LLC
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

// Package shamir encapsulates all of the logic needed to perform t-of-n [Shamir
// Secret Sharing] (SSS) on arbitrary-size secrets over
// a finite field. SSS is based on the Lagrange interpolation theorem, which
// states that `k` points are enough to uniquely determine a polynomial of
// degree less than or equal to `k - 1`.
//
// This scheme is secure under the following assumptions:
//   - The scheme requires a trusted dealer to generate the shares. Participants
//     must trust the dealer with access to the secret and to properly generate the
//     shares.
//   - The scheme assumes a passive adversary which can observe (n - t) shares
//     without being able to reconstruct the secrets. However, this scheme
//     assumes the adversary isn't allowed to participate in the `reconstruct` step by
//     providing a chosen share.
//     Examples of this attack: https://crypto.stackexchange.com/q/41994/76875
//
// [Shamir Secret Sharing]: https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareAsecrets.pdf
package shamir

import (
	"fmt"

	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/finitefield"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/field"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/field/gf32"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/field/gf8"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/shamirgeneric"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/secrets"
)

func createField(fieldID finitefield.ID) (field.GaloisField, error) {
	switch fieldID {
	case finitefield.GF32:
		return gf32.New(), nil
	case finitefield.GF8:
		return gf8.New(), nil
	default:
		return nil, fmt.Errorf("invalid field: %q", fieldID)
	}
}

// SplitSecret splits a secret into metadata.NumShares shares where metadata.Threshold
// or more shares can be combined to reconstruct the original secret.
func SplitSecret(metadata secrets.Metadata, secret []byte) (secrets.Split, error) {
	f, err := createField(metadata.Field)
	if err != nil {
		return secrets.Split{}, err
	}
	return shamirgeneric.SplitSecret(metadata, secret, f)
}

// Reconstruct reconstructs the secret from secretSplit.
//
// The number of shares provided must meet the threshold specified when the
// shares were created by [SplitSecret].
//
// Reconstruct will not detect bogus or corrupted shares.
func Reconstruct(secretSplit secrets.Split) ([]byte, error) {
	if len(secretSplit.Shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}
	f, err := createField(secretSplit.Metadata.Field)
	if err != nil {
		return nil, err
	}
	return shamirgeneric.Reconstruct(secretSplit, f)
}
