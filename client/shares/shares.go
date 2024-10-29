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

// Package shares contains functions for processing DEK shares.
package shares

import (
	"bytes"
	"fmt"

	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/finitefield"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/secrets"
	"github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/shamir"
	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	"github.com/google/tink/go/subtle/random"

	"crypto/sha256"
)

// DEKBytes is the size of the DEK in bytes.
const DEKBytes uint32 = 32

// DEK represents a byte array that serves as a Data Encryption Key.
type DEK [DEKBytes]byte

// NewDEK randomly generates and returns a DEK.
func NewDEK() DEK {
	var dek DEK
	copy(dek[:DEKBytes], random.GetRandomBytes(DEKBytes))

	return dek
}

// UnwrappedShare represents an unwrapped share and its associated external URI.
type UnwrappedShare struct {
	Share []byte
	URI   string
}

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

func convertToByteShares(shares []secrets.Share) [][]byte {
	byteShares := make([][]byte, 0, len(shares))
	for _, share := range shares {
		// Hashicorp/vault appends the X value to the end of each share.
		// We have to do this manually for backwards compatibility.
		shareWithX := append(share.Value, byte(share.X))
		byteShares = append(byteShares, shareWithX)
	}

	return byteShares
}

// SplitShares takes a DEK as `data`, and returns a slice of byte slices, each representing
// one of the n shares.
func SplitShares(data []byte, numShares, threshold int) ([][]byte, error) {
	// Validate data length is DEKBytes.
	if len(data) != int(DEKBytes) {
		return nil, fmt.Errorf("data has length %v, expected %v", len(data), DEKBytes)
	}

	md := secrets.Metadata{
		Field:     finitefield.GF8,
		NumShares: numShares,
		Threshold: threshold,
	}
	split, err := shamir.SplitSecret(md, data)
	if err != nil {
		return nil, fmt.Errorf("error splitting secret: %v", err)
	}

	// Validate the returned data.
	if split.SecretLen != int(DEKBytes) {
		return nil, fmt.Errorf("split indicates secret has length %v, expected %v", split.SecretLen, DEKBytes)
	}

	return convertToByteShares(split.Shares), nil
}

func convertToSecretShares(unwrappedShares []UnwrappedShare) []secrets.Share {
	secretShares := make([]secrets.Share, 0, len(unwrappedShares))
	for _, unwrapped := range unwrappedShares {
		share := unwrapped.Share

		// Split each share into the value and the X field (last byte).
		secretShare := secrets.Share{
			Value: share[:len(share)-1],
			X:     int(share[len(share)-1]),
		}

		secretShares = append(secretShares, secretShare)
	}

	return secretShares
}

// CombineShares takes a list of shares and reconstitutes the original data. Note that this does not
// guarantee the shares are correct (SSS will succeed at "reconstructing" data from
// even faulty shares), so integrity checks are done separately.
func CombineShares(shares []UnwrappedShare, numShares, threshold int) ([]byte, error) {
	secretShares := convertToSecretShares(shares)

	split := secrets.Split{
		SecretLen: int(DEKBytes),
		Metadata: secrets.Metadata{
			Field:     finitefield.GF8,
			NumShares: numShares,
			Threshold: threshold,
		},
		Shares: secretShares,
	}

	return shamir.Reconstruct(split)
}

// CreateDEKShares generates a DEK and - if applicable - splits it into shares.
func CreateDEKShares(dek DEK, keyCfg *configpb.KeyConfig) ([][]byte, error) {
	var shares [][]byte

	// Depending on the key splitting algorithm given in the KeyConfig, take
	// the DEK and split it, wrapping the resulting shares and writing them
	// back to the `Shares` field of `metadata`.
	switch keyCfg.KeySplittingAlgorithm.(type) {

	// Don't split the DEK.
	case *configpb.KeyConfig_NoSplit:
		if len(keyCfg.GetKekInfos()) != 1 {
			return nil, fmt.Errorf("invalid Encrypt configuration, number of KekInfos is %v but expected 1 for 'no split' option", len(keyCfg.GetKekInfos()))
		}

		shares = [][]byte{dek[:]}

	// Split DEK with Shamir's Secret Sharing.
	case *configpb.KeyConfig_Shamir:
		shamirConfig := keyCfg.GetShamir()
		shamirShares := int(shamirConfig.GetShares())
		shamirThreshold := int(shamirConfig.GetThreshold())

		// The number of KEK Infos should match the number of shares to generate
		if len(keyCfg.GetKekInfos()) != shamirShares {
			return nil, fmt.Errorf("invalid Encrypt configuration, number of KEK Infos does not match the number of shares to generate: found %v KEK Infos, %v shares", len(keyCfg.GetKekInfos()), shamirShares)
		}

		var err error
		shares, err = SplitShares(dek[:], shamirShares, shamirThreshold)
		if err != nil {
			return nil, fmt.Errorf("error splitting encryption key: %v", err)
		}

	default:
		return nil, fmt.Errorf("unknown key splitting algorithm")
	}

	return shares, nil
}

// CombineUnwrappedShares reconstitutes and returns the DEK from the provided shares.
func CombineUnwrappedShares(keyCfg *configpb.KeyConfig, unwrappedShares []UnwrappedShare) ([]byte, error) {
	// Reconstitute DEK.
	var combinedShares []byte

	switch keyCfg.KeySplittingAlgorithm.(type) {
	// DEK wasn't split, so combined shares is just the sole share.
	case *configpb.KeyConfig_NoSplit:
		if len(unwrappedShares) != 1 {
			return nil, fmt.Errorf("number of unwrapped shares is %v but expected 1 for 'no split' option", len(unwrappedShares))
		}

		combinedShares = unwrappedShares[0].Share

	// Reverse Shamir's Secret Sharing to reconstitute the whole DEK.
	case *configpb.KeyConfig_Shamir:
		if len(unwrappedShares) < int(keyCfg.GetShamir().GetThreshold()) {
			return nil, fmt.Errorf("only successfully unwrapped %v shares, which is fewer than threshold of %v", len(unwrappedShares), keyCfg.GetShamir().GetThreshold())
		}
		var err error
		combinedShares, err = CombineShares(unwrappedShares, int(keyCfg.GetShamir().GetShares()), int(keyCfg.GetShamir().GetThreshold()))
		if err != nil {
			return nil, fmt.Errorf("Error combining DEK shares: %v", err)
		}

	default:
		return nil, fmt.Errorf("Unknown key splitting algorithm")

	}

	if len(combinedShares) != int(DEKBytes) {
		return nil, fmt.Errorf("Reconstituted DEK has the wrong length")
	}

	return combinedShares, nil
}
