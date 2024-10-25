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

package shamir_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/finitefield"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/secrets"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/shamir"
)

const smallSecret = "abcdefghijklmnopqrstuvwxyz123456"

func getRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatalf("Failed to read random bytes: %v", err)
	}
	return b
}

func removeAtIndex(s []secrets.Share, index int) []secrets.Share {
	return append(s[:index], s[index+1:]...)
}

func swap(s []secrets.Share, i int, j int) {
	s[i], s[j] = s[j], s[i]
}

type testCase struct {
	name     string
	secret   []byte
	metadata secrets.Metadata
	shares   []secrets.Share
}

func TestSplitReconstructWorks(t *testing.T) {
	for _, tc := range []testCase{
		{
			name:   "small secret gf32 n-6 t-4",
			secret: []byte(smallSecret),
			metadata: secrets.Metadata{
				Field:     finitefield.GF32,
				NumShares: 6,
				Threshold: 4,
			},
		},
		{
			name:   "large secret gf32 n-80 t-50",
			secret: getRandomBytes(t, 300),
			metadata: secrets.Metadata{
				Field:     finitefield.GF32,
				NumShares: 80,
				Threshold: 50,
			},
		},
		{
			name:   "small secret g8 n-6 t-4",
			secret: []byte(smallSecret),
			metadata: secrets.Metadata{
				Field:     finitefield.GF8,
				NumShares: 6,
				Threshold: 4,
			},
		},
		{
			name:   "large secret g8 n-80 t-50",
			secret: getRandomBytes(t, 300),
			metadata: secrets.Metadata{
				Field:     finitefield.GF8,
				NumShares: 80,
				Threshold: 50,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			splitSecret, err := shamir.SplitSecret(tc.metadata, tc.secret)
			if err != nil {
				t.Fatalf("shamir.SplitSecret() err = %v, want nil", err)
			}
			recon, err := shamir.Reconstruct(splitSecret)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := recon, tc.secret; !bytes.Equal(got, want) {
				t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
			}
		})
	}
}

func buildTestVectors(t *testing.T, numShares, threshold int) []testCase {
	t.Helper()
	return []testCase{
		{
			name:     "GF32",
			secret:   getRandomBytes(t, 32),
			metadata: secrets.Metadata{Field: finitefield.GF32, NumShares: numShares, Threshold: threshold},
		},
		{
			name:     "GF8",
			secret:   getRandomBytes(t, 32),
			metadata: secrets.Metadata{Field: finitefield.GF8, NumShares: numShares, Threshold: threshold},
		},
	}
}

func TestReconstructWithoutAllShares(t *testing.T) {
	numShares := 6
	threshold := 4
	for _, tc := range buildTestVectors(t, numShares, threshold) {
		t.Run(tc.name, func(t *testing.T) {
			splitSecret, err := shamir.SplitSecret(tc.metadata, tc.secret)
			if err != nil {
				t.Fatal(err)
			}
			splitSecret.Shares = removeAtIndex(splitSecret.Shares, 5)
			splitSecret.Shares = removeAtIndex(splitSecret.Shares, 0)
			recon, err := shamir.Reconstruct(splitSecret)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := recon, tc.secret; !bytes.Equal(got, want) {
				t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
			}
			// swapping the order shouldn't matter.
			swap(splitSecret.Shares, 0, 2)
			if got, want := recon, tc.secret; !bytes.Equal(got, want) {
				t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
			}
		})
	}
}

func TestReconstructWithAlteredValueUnderThresholdFails(t *testing.T) {
	numShares := 3
	threshold := 2
	for _, tc := range buildTestVectors(t, numShares, threshold) {
		t.Run(tc.name, func(t *testing.T) {
			splitSecret, err := shamir.SplitSecret(tc.metadata, tc.secret)
			if err != nil {
				t.Fatalf("shamir.SplitSecret() err = %v, want nil", err)
			}
			splitSecret.Shares[0].Value = getRandomBytes(t, len(splitSecret.Shares[0].Value))
			// reconstruct shouldn't return an error
			recon, err := shamir.Reconstruct(splitSecret)
			if err != nil {
				t.Fatalf("shamir.Reconstruct() err = %v, want nil", err)
			}
			if got, want := recon, tc.secret; bytes.Equal(got, want) {
				t.Errorf("reconsturcting altered value should fail")
			}
		})
	}
}

func TestReconstructWithAlteredValueAboveThresholdDoesNotAffectResult(t *testing.T) {
	numShares := 3
	threshold := 2
	for _, tc := range buildTestVectors(t, numShares, threshold) {
		t.Run(tc.name, func(t *testing.T) {
			splitSecret, err := shamir.SplitSecret(tc.metadata, tc.secret)
			if err != nil {
				t.Fatalf("shamir.SplitSecret() err = %v, want nil", err)
			}
			splitSecret.Shares[2].Value = getRandomBytes(t, len(splitSecret.Shares[0].Value))
			recon, err := shamir.Reconstruct(splitSecret)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := recon, tc.secret; !bytes.Equal(got, want) {
				t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
			}
		})
	}
}

func TestReconstructWithFewerSharesThanThresholdFails(t *testing.T) {
	numShares := 6
	threshold := 4
	for _, tc := range buildTestVectors(t, numShares, threshold) {
		t.Run(tc.name, func(t *testing.T) {
			splitSecret, err := shamir.SplitSecret(tc.metadata, tc.secret)
			if err != nil {
				t.Fatal(err)
			}
			splitSecret.Shares = removeAtIndex(splitSecret.Shares, 5)
			splitSecret.Shares = removeAtIndex(splitSecret.Shares, 1)
			splitSecret.Shares = removeAtIndex(splitSecret.Shares, 0)
			if _, err := shamir.Reconstruct(splitSecret); err == nil {
				t.Fatalf("Reconstruct() err = nil, want error")
			}
		})
	}
}

func TestReconstructFromStaticShares(t *testing.T) {
	for _, tc := range []testCase{
		{
			name:   "GF32",
			secret: []byte{0, 0, 0, byte(uint8(33))},
			metadata: secrets.Metadata{
				Field:     finitefield.GF32,
				NumShares: 5,
				Threshold: 3,
			},
			shares: []secrets.Share{
				{Value: []byte{112, 207, 118, 46, 110, 212, 170, 28}, X: 1},
				{Value: []byte{48, 160, 197, 172, 38, 235, 145, 204}, X: 2},
				{Value: []byte{63, 115, 238, 144, 40, 68, 183, 71}, X: 3},
				{Value: []byte{29, 72, 240, 207, 114, 224, 26, 141}, X: 4},
				{Value: []byte{74, 31, 204, 116, 6, 189, 187, 136}, X: 5},
			},
		},
		{
			name:   "GF8",
			secret: []byte("YELLOW_SUBMARINE"),
			metadata: secrets.Metadata{
				Field:     finitefield.GF8,
				NumShares: 5,
				Threshold: 3,
			},
			shares: []secrets.Share{
				{Value: []byte{0xca, 0x6a, 0x5e, 0xe5, 0x13, 0x14, 0x08, 0x88, 0xf0, 0xab, 0x3a, 0x3b, 0xee, 0x7b, 0xd0, 0xdc}, X: 0xd3},
				{Value: []byte{0xf9, 0xa1, 0xf9, 0xb9, 0x00, 0xe4, 0x9c, 0x39, 0xcc, 0xce, 0x1f, 0xd9, 0xab, 0x3c, 0xe5, 0x72}, X: 0x97},
				{Value: []byte{0xb8, 0x03, 0x95, 0x32, 0x0f, 0x82, 0xa9, 0xf8, 0x1b, 0x42, 0x71, 0x20, 0xdb, 0x04, 0xa2, 0x51}, X: 0x53},
				{Value: []byte{0x7b, 0xc9, 0x47, 0x5e, 0xf8, 0x67, 0xff, 0x7c, 0xbc, 0x91, 0xdd, 0xa9, 0x8b, 0xa2, 0x7e, 0x84}, X: 0xff},
				{Value: []byte{0x0b, 0x98, 0x6c, 0x4a, 0x32, 0x23, 0x11, 0xfe, 0x62, 0x5e, 0xcc, 0x5a, 0x47, 0x2a, 0x4e, 0x15}, X: 0x5d},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			split := secrets.Split{
				SecretLen: len(tc.secret),
				Metadata:  tc.metadata,
				Shares:    tc.shares,
			}
			recon, err := shamir.Reconstruct(split)
			if err != nil {
				t.Fatal(err)
			}
			if got := recon; !bytes.Equal(got, tc.secret) {
				t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(tc.secret))
			}
		})
	}
}

func TestReconstructFromStaticSharesWithoutAllShares(t *testing.T) {
	for _, tc := range []testCase{
		{
			name:   "GF32",
			secret: []byte{0, 0, 0, byte(uint8(33))},
			metadata: secrets.Metadata{
				Field:     finitefield.GF32,
				NumShares: 5,
				Threshold: 3,
			},
			shares: []secrets.Share{
				{Value: []byte{112, 207, 118, 46, 110, 212, 170, 28}, X: 1},
				{Value: []byte{63, 115, 238, 144, 40, 68, 183, 71}, X: 3},
				{Value: []byte{74, 31, 204, 116, 6, 189, 187, 136}, X: 5},
			},
		},
		{
			name:   "GF8",
			secret: []byte("YELLOW_SUBMARINE"),
			metadata: secrets.Metadata{
				Field:     finitefield.GF8,
				NumShares: 5,
				Threshold: 3,
			},
			shares: []secrets.Share{
				{Value: []byte{0xca, 0x6a, 0x5e, 0xe5, 0x13, 0x14, 0x08, 0x88, 0xf0, 0xab, 0x3a, 0x3b, 0xee, 0x7b, 0xd0, 0xdc}, X: 0xd3},
				{Value: []byte{0xf9, 0xa1, 0xf9, 0xb9, 0x00, 0xe4, 0x9c, 0x39, 0xcc, 0xce, 0x1f, 0xd9, 0xab, 0x3c, 0xe5, 0x72}, X: 0x97},
				{Value: []byte{0x7b, 0xc9, 0x47, 0x5e, 0xf8, 0x67, 0xff, 0x7c, 0xbc, 0x91, 0xdd, 0xa9, 0x8b, 0xa2, 0x7e, 0x84}, X: 0xff},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			split := secrets.Split{
				SecretLen: len(tc.secret),
				Metadata:  tc.metadata,
				Shares:    tc.shares,
			}
			recon, err := shamir.Reconstruct(split)
			if err != nil {
				t.Fatal(err)
			}
			if got := recon; !bytes.Equal(got, tc.secret) {
				t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(tc.secret))
			}
		})
	}
}
