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

package shamirgeneric_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/finitefield"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/field/gf32"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/shamirgeneric"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/secrets"
)

func getRandomBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatalf("Failed to read random bytes: %v", err)
	}
	return b
}

func createMetadata(threshold, numShares int) secrets.Metadata {
	return secrets.Metadata{
		Field:     finitefield.GF32,
		NumShares: numShares,
		Threshold: threshold,
	}
}

func TestSplitReconstructWorks(t *testing.T) {
	secret := []byte("abcdefghijklmnopqrstuvwxyz123456")
	split, err := shamirgeneric.SplitSecret(createMetadata(4, 6), secret, gf32.New())
	if err != nil {
		t.Fatalf("shamirgeneric.SplitSecret() err = %v, want nil", err)
	}
	recon, err := shamirgeneric.Reconstruct(split, gf32.New())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := []byte(recon), secret; !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestSplitReconstructLargeValues(t *testing.T) {
	secret := getRandomBytes(t, 300)
	split, err := shamirgeneric.SplitSecret(createMetadata(50, 80), secret, gf32.New())
	if err != nil {
		t.Fatal(err)
	}
	recon, err := shamirgeneric.Reconstruct(split, gf32.New())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := []byte(recon), secret; !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func removeAtIndex(s []secrets.Share, index int) []secrets.Share {
	return append(s[:index], s[index+1:]...)
}

func swap(s []secrets.Share, i int, j int) {
	s[i], s[j] = s[j], s[i]
}

func TestReconstructWithoutAllShares(t *testing.T) {
	secret := []byte("abcdefghijklmnopqrstuvwxyz123456")
	split, err := shamirgeneric.SplitSecret(createMetadata(4, 6), secret, gf32.New())
	if err != nil {
		t.Fatal(err)
	}
	split.Shares = removeAtIndex(split.Shares, 5)
	split.Shares = removeAtIndex(split.Shares, 0)
	recon, err := shamirgeneric.Reconstruct(split, gf32.New())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := []byte(recon), secret; !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
	}
	// swapping the order shouldn't matter.
	swap(split.Shares, 0, 2)
	if got, want := []byte(recon), secret; !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestReconstructWithAlteredValueBeforeThresholdFails(t *testing.T) {
	secret := getRandomBytes(t, 32)
	split, err := shamirgeneric.SplitSecret(createMetadata(2, 3), secret, gf32.New())
	if err != nil {
		t.Fatalf("shamirgeneric.SplitSecret() err = %v, want nil", err)
	}
	split.Shares[0].Value = getRandomBytes(t, len(split.Shares[0].Value))
	recon, err := shamirgeneric.Reconstruct(split, gf32.New())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := []byte(recon), secret; bytes.Equal(got, want) {
		t.Errorf("reconsturcting altered value should fail")
	}
}

func TestReconstructWithAlteredValueAfterThresholdDoesNotAffectResult(t *testing.T) {
	secret := getRandomBytes(t, 32)
	split, err := shamirgeneric.SplitSecret(createMetadata(2, 3), secret, gf32.New())
	if err != nil {
		t.Fatalf("shamirgeneric.SplitSecret() err = %v, want nil", err)
	}
	split.Shares[2].Value = getRandomBytes(t, len(split.Shares[0].Value))
	recon, err := shamirgeneric.Reconstruct(split, gf32.New())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := []byte(recon), secret; !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestWithLessSharesThanThresholdFails(t *testing.T) {
	secret := []byte("abcdefghijklmnopqrstuvwxyz123456")
	splitSecret, err := shamirgeneric.SplitSecret(createMetadata(4, 6), secret, gf32.New())
	if err != nil {
		t.Fatal(err)
	}
	splitSecret.Shares = removeAtIndex(splitSecret.Shares, 5)
	splitSecret.Shares = removeAtIndex(splitSecret.Shares, 1)
	splitSecret.Shares = removeAtIndex(splitSecret.Shares, 0)
	if _, err := shamirgeneric.Reconstruct(splitSecret, gf32.New()); err == nil {
		t.Fatalf("Reconstruct() err = nil, want error")
	}
}

func TestReconstructFromStaticShares(t *testing.T) {
	shares := []secrets.Share{
		{Value: []byte{112, 207, 118, 46, 110, 212, 170, 28}, X: 1},
		{Value: []byte{48, 160, 197, 172, 38, 235, 145, 204}, X: 2},
		{Value: []byte{63, 115, 238, 144, 40, 68, 183, 71}, X: 3},
		{Value: []byte{29, 72, 240, 207, 114, 224, 26, 141}, X: 4},
		{Value: []byte{74, 31, 204, 116, 6, 189, 187, 136}, X: 5},
	}
	want := []byte{0, 0, 0, byte(uint8(33))}
	split := secrets.Split{
		Shares: shares,
		Metadata: secrets.Metadata{
			Field:     finitefield.GF32,
			NumShares: len(shares),
			Threshold: 3,
		},
		SecretLen: len(want),
	}
	recon, err := shamirgeneric.Reconstruct(split, gf32.New())
	if err != nil {
		t.Fatal(err)
	}
	if got := []byte(recon); !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestReconstructFromStaticSharesWithLessThanN(t *testing.T) {
	shares := []secrets.Share{
		{Value: []byte{112, 207, 118, 46, 110, 212, 170, 28}, X: 1},
		{Value: []byte{29, 72, 240, 207, 114, 224, 26, 141}, X: 4},
		{Value: []byte{74, 31, 204, 116, 6, 189, 187, 136}, X: 5},
	}
	want := []byte{0, 0, 0, byte(uint8(33))}
	split := secrets.Split{
		Shares: shares,
		Metadata: secrets.Metadata{
			Field:     finitefield.GF32,
			NumShares: len(shares),
			Threshold: 3,
		},
		SecretLen: len(want),
	}
	recon, err := shamirgeneric.Reconstruct(split, gf32.New())
	if err != nil {
		t.Fatal(err)
	}
	if got := []byte(recon); !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}
