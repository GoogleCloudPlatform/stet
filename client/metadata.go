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

// Utility functions for metadata serialization operations.

package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
)

// metadataToAAD processes metadata to use as AAD for AEAD Encryption.
// The serialization scheme is as follows (given n := len(md.shares)):
//
//	len(md.shares[0].wrappedShare)      || md.shares[0].wrappedShare
//	|| len(md.shares[0].hash)           || md.shares[0].hash
//	...
//	|| len(md.shares[n-1].wrappedShare) || md.shares[n-1].wrappedShare
//	|| len(md.shares[n-1].hash)         || md.shares[n-1].hash
//	|| len(md.blobID)                   || md.blobID
//
// Note that KeyConfig is explicitly omitted from the serialization,
// as its presence is not important to the AAD.
func metadataToAAD(md *configpb.Metadata) ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, share := range md.GetShares() {
		// Serialize share.wrappedShare
		if err := binary.Write(buf, binary.LittleEndian, uint64(len(share.GetShare()))); err != nil {
			return nil, fmt.Errorf("unable to serialize length of wrapped share: %v", err)
		}

		if _, err := buf.Write(share.GetShare()); err != nil {
			return nil, fmt.Errorf("unable to serialize wrapped share: %v", err)
		}

		// Serialize share.hash
		if err := binary.Write(buf, binary.LittleEndian, uint64(sha256.Size)); err != nil {
			return nil, fmt.Errorf("unable to serialize length of hashed share: %v", err)
		}

		if _, err := buf.Write(share.GetHash()); err != nil {
			return nil, fmt.Errorf("unable to serialize hashed share: %v", err)
		}
	}

	// Serialize blobID.
	if err := binary.Write(buf, binary.LittleEndian, uint64(len([]byte(md.GetBlobId())))); err != nil {
		return nil, fmt.Errorf("unable to serialize length of blobID: %v", err)
	}

	if _, err := buf.WriteString(md.GetBlobId()); err != nil {
		return nil, fmt.Errorf("unable to serialize blobID: %v", md.GetBlobId())
	}

	return buf.Bytes(), nil
}
