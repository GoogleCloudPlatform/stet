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

// Utility functions for AEAD encryption and decryption.

package client

import (
	"bytes"
	"fmt"
	"io"

	"github.com/google/tink/go/streamingaead/subtle"
)

const (
	// Parameters for streaming AEAD, required by Tink's subtle API.
	aeadHKDFAlg            = "SHA256"
	aeadSegmentSize        = 1048576
	aeadFirstSegmentOffset = 0
	aeadChunkSize          = 128
)

// aeadEncrypt uses the provided key and AAD to encrypt the provided plaintext.
func aeadEncrypt(key DEK, plaintext, aad []byte) ([]byte, error) {
	cipher, err := subtle.NewAESGCMHKDF(key[:], aeadHKDFAlg, int(DEKBytes), aeadSegmentSize, aeadFirstSegmentOffset)
	if err != nil {
		return nil, fmt.Errorf("unable to create new cipher: %v", err)
	}

	ciphertextBuf := &bytes.Buffer{}
	writer, err := cipher.NewEncryptingWriter(ciphertextBuf, aad)
	if err != nil {
		return nil, fmt.Errorf("unable to create an encrypt writer: %v", err)
	}

	bytesWritten, err := writer.Write(plaintext)
	if err != nil {
		return nil, fmt.Errorf("unable to write to the encrypt writer: %v", err)
	}

	if bytesWritten != len(plaintext) {
		return nil, fmt.Errorf("did not write expected number of bytes. Got %d, want %d", bytesWritten, len(plaintext))
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("error closing writer: %v", err)
	}

	return ciphertextBuf.Bytes(), nil
}

// aeadDecrypt uses the provided key and AAD to decode ciphertext and return the resulting plaintext.
func aeadDecrypt(key DEK, ciphertext, aad []byte) ([]byte, error) {
	cipher, err := subtle.NewAESGCMHKDF(key[:], aeadHKDFAlg, int(DEKBytes), aeadSegmentSize, aeadFirstSegmentOffset)
	if err != nil {
		return nil, fmt.Errorf("unable to create new cipher: %v", err)
	}

	reader, err := cipher.NewDecryptingReader(bytes.NewBuffer(ciphertext), aad)
	if err != nil {
		return nil, fmt.Errorf("unable to create decrypt reader: %v", err)
	}

	var (
		chunk     = make([]byte, aeadChunkSize)
		eof       = false
		plaintext = []byte{}
	)
	for !eof {
		bytesRead, err := reader.Read(chunk)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("error reading chunk: %v", err)
		}

		eof = err == io.EOF
		plaintext = append(plaintext, chunk[:bytesRead]...)
	}

	return plaintext, nil
}
