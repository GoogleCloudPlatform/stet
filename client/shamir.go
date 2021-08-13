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

// Utility functions for share splitting via Shamir's Secret Sharing.

package client

import (
	"github.com/hashicorp/vault/shamir"
)

// SplitShares takes a DEK as `data`, and returns a slice of byte slices, each representing
// one of the n shares.
func SplitShares(data []byte, shares, threshold int) ([][]byte, error) {
	return shamir.Split(data, shares, threshold)
}

// CombineShares takes a list of shares and reconstitutes the original data. Note that this does not
// guarantee the shares are correct (SSS will succeed at "reconstructing" data from
// even faulty shares), so integrity checks are done separately.
func CombineShares(shares [][]byte) ([]byte, error) {
	return shamir.Combine(shares)
}
