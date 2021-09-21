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

// Utility functions for reading and writing STET-encrypted files.
//
// The v1 file format of a STET-encrypted file is a concatenation of
// a 16 byte STET header, a serialized configpb.Metadata proto, and
// the raw ciphertext bytes, with no padding.
//
// STET Header (16 bytes):
// - "STETENCRYPTED" magic string (13 bytes)
// - file format version (1 byte)
// - serialized metadata length (2 bytes)
//
// Metadata:
// - serialized proto with the length specified in the header
//
// Ciphertext:
// - raw encrypted bytes, extending to the end of the file

package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// STETMagic is the magic string for a STET encrypted file header ("STETENCRYPTED").
var STETMagic = [13]byte{'S', 'T', 'E', 'T', 'E', 'N', 'C', 'R', 'Y', 'P', 'T', 'E', 'D'}

// STETHeader is the file header for the encrypted STET file format.
type STETHeader struct {
	Magic       [13]byte // len([]byte(STETMagic)) == 13
	Version     uint8    // 1 byte
	MetadataLen uint16   // 2 bytes
}

// Reads a STET encrypted file header from `input`, returning a STETHeader.
func readHeader(input io.Reader) (*STETHeader, error) {
	var header STETHeader
	if err := binary.Read(input, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read STET encrypted header: %v", err)
	}

	if !bytes.Equal(header.Magic[:], STETMagic[:]) {
		return nil, fmt.Errorf("data is not a known STET encryption format")
	}

	return &header, nil
}

// Writes a STET encrypted file header with the given properties to `output`.
func writeHeader(output io.Writer, metadataLen int) error {
	header := STETHeader{
		Magic:       STETMagic,
		Version:     1,
		MetadataLen: uint16(metadataLen),
	}

	return binary.Write(output, binary.LittleEndian, header)
}
