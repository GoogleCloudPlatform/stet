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
	"bytes"
	"testing"

	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
)

func TestMetadataSerialize(t *testing.T) {
	testShare := []byte("I am a wrapped share.")
	testHashedShare := HashShare(testShare)

	wrapped := &configpb.WrappedShare{
		Share: append(testShare, byte('E')),
		Hash:  testHashedShare,
	}

	testBlobID := "I am blob."

	shamirConfig := configpb.ShamirConfig{
		Threshold: 2,
		Shares:    3,
	}

	testKeyConfig := configpb.KeyConfig{
		KekInfos:              []*configpb.KekInfo{},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
	}

	testCases := []*configpb.Metadata{
		{
			Shares:    []*configpb.WrappedShare{wrapped},
			BlobId:    testBlobID,
			KeyConfig: &testKeyConfig,
		},
		{
			Shares:    []*configpb.WrappedShare{wrapped},
			KeyConfig: &testKeyConfig,
		},
		{
			Shares:    []*configpb.WrappedShare{wrapped, wrapped},
			BlobId:    testBlobID,
			KeyConfig: &testKeyConfig,
		},
	}

	for _, md := range testCases {
		if _, err := metadataToAAD(md); err != nil {
			t.Errorf("Serialization failed: %v", err)
		}
	}
}

func TestMetadataSerializeAvoidsCollisions(t *testing.T) {
	testShare := []byte("I am a wrapped share.")
	testHashedShare := HashShare(testShare)

	spacesHash := bytes.Repeat([]byte{' '}, 32)

	wrapped := &configpb.WrappedShare{
		Share: testShare,
		Hash:  testHashedShare,
	}

	// Pass empty KeyConfig objects as they are not included
	// in the serialization by-design.
	testCases := [][2]*configpb.Metadata{
		{
			&configpb.Metadata{
				Shares:    []*configpb.WrappedShare{wrapped},
				BlobId:    "foo",
				KeyConfig: &configpb.KeyConfig{},
			},
			&configpb.Metadata{
				Shares:    []*configpb.WrappedShare{wrapped},
				BlobId:    "bar",
				KeyConfig: &configpb.KeyConfig{},
			},
		},
		{
			&configpb.Metadata{
				Shares: []*configpb.WrappedShare{
					{
						Share: []byte(" "),
						Hash:  spacesHash,
					},
				},
				BlobId:    "",
				KeyConfig: &configpb.KeyConfig{},
			},
			&configpb.Metadata{
				Shares: []*configpb.WrappedShare{
					{
						Share: []byte(""),
						Hash:  spacesHash,
					},
				},
				BlobId:    " ",
				KeyConfig: &configpb.KeyConfig{},
			},
		},
	}

	for _, tc := range testCases {
		serialized0, err := metadataToAAD(tc[0])
		if err != nil {
			t.Fatalf("Error serializing metadata %v: %v", tc[0], err)
		}

		serialized1, err := metadataToAAD(tc[1])
		if err != nil {
			t.Fatalf("Error serializing metadata %v: %v", tc[1], err)
		}

		if bytes.Equal(serialized0, serialized1) {
			t.Errorf("Expected serializations to be unequal. \nmd0 = {%v}\nmd1 = {%v}", tc[0], tc[1])
		}
	}
}
