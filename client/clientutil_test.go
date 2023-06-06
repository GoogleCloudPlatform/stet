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
	"crypto/sha256"
	"io"
	"testing"

	"github.com/GoogleCloudPlatform/stet/client/shares"
	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
)

func TestAeadEncryptAndAeadDecrypt(t *testing.T) {
	testDEK := shares.NewDEK()
	testPT := []byte("Plaintext for testing only.")
	testAAD := []byte("AAD for testing only.")

	encryptInput := bytes.NewReader(testPT)

	var ciphertext []byte
	encryptOutput := bytes.NewBuffer(ciphertext)

	if err := AeadEncrypt(testDEK, encryptInput, encryptOutput, testAAD); err != nil {
		t.Fatalf("AeadEncrypt failed with error %v", err)
	}

	decryptInput := encryptOutput

	var plaintext []byte
	decryptOutput := bytes.NewBuffer(plaintext)

	if err := AeadDecrypt(testDEK, decryptInput, decryptOutput, testAAD); err != nil {
		t.Fatalf("AeadDecrypt failed with error %v", err)
	}

	if !bytes.Equal(decryptOutput.Bytes(), testPT) {
		t.Errorf("AeadEncrypt and AeadDecrypt workflow does not restore original plaintext. Got %v, want %v", plaintext, testPT)
	}
}

func TestAeadDecryptFailsForInvalidCipherText(t *testing.T) {
	testDEK := shares.NewDEK()
	testCT := []byte("This is some random invalid ciphertext.")
	testAAD := []byte("AAD for testing only.")

	input := bytes.NewReader(testCT)

	var plaintext []byte
	output := bytes.NewBuffer(plaintext)

	if err := AeadDecrypt(testDEK, input, output, testAAD); err == nil { // if no error
		t.Error("aeadDecrypt expected to return error but did not.")
	}
}

func TestAeadDecryptFailsForNonmatchingAAD(t *testing.T) {
	testDEK := shares.NewDEK()
	testPT := []byte("Plaintext for testing only.")
	testEncryptAAD := []byte("AAD for encrypt testing only.")
	testDecryptAAD := []byte("AAD for decrypt testing only.")

	encryptInput := bytes.NewReader(testPT)

	var ciphertext []byte
	encryptOutput := bytes.NewBuffer(ciphertext)

	if err := AeadEncrypt(testDEK, encryptInput, encryptOutput, testEncryptAAD); err != nil {
		t.Fatalf("AeadEncrypt failed with error %v", err)
	}

	decryptInput := encryptOutput

	var plaintext []byte
	decryptOutput := bytes.NewBuffer(plaintext)

	if err := AeadDecrypt(testDEK, decryptInput, decryptOutput, testDecryptAAD); err == nil {
		t.Error("AeadDecrypt expected to return error due to mismatched AAD")
	}
}

func TestReadWriteHeaderSucceeds(t *testing.T) {
	var file bytes.Buffer

	if err := WriteSTETHeader(&file, 42); err != nil {
		t.Fatalf("writeHeader(file, 42) returned error: %v", err)
	}

	header, err := ReadSTETHeader(&file)
	if err != nil {
		t.Fatalf("readHeader(file) returned error: %v", err)
	}

	if !bytes.Equal(header.Magic[:], STETMagic[:]) {
		t.Fatalf("Header does not contain expected magic string: got %v, want %v", header.Magic, STETMagic)
	}

	if header.MetadataLen != 42 {
		t.Fatalf("Header had unexpected MetadataLen: got %v, want 42", header.MetadataLen)
	}
}

func TestWriteHeaderExplicitByteOrder(t *testing.T) {
	var header bytes.Buffer

	if err := WriteSTETHeader(&header, 0xABCD); err != nil {
		t.Fatalf("writeHeader(header, 0xABCD) returned error: %v", err)
	}

	var want []byte
	want = append(want, STETMagic[:]...)
	want = append(want, 0x01)                  // version number
	want = append(want, []byte{0xCD, 0xAB}...) // metadata length (little-endian)

	if !bytes.Equal(header.Bytes(), want) {
		t.Fatalf("writeHeader(header, 0xABCD) produced unexpected header: got %v, want %v", header.Bytes(), want)
	}
}

func TestReadHeaderAdvances16Bytes(t *testing.T) {
	var file bytes.Buffer

	if err := WriteSTETHeader(&file, 42); err != nil {
		t.Fatalf("writeHeader(file, 42) returned error: %v", err)
	}

	// Write more to the buffer so the reader can potentially read further.
	file.Write([]byte("I am a file hungry for more and more data."))

	reader := bytes.NewReader(file.Bytes())

	if _, err := ReadSTETHeader(reader); err != nil {
		t.Fatalf("readHeader(file) returned error: %v", err)
	}

	pos, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("reader.Seek(0, io.SeekCurrent) returned error: %v", err)
	}

	if pos != 16 {
		t.Fatalf("readHeader(file) got %d bytes, want 16 bytes", pos)
	}
}

func TestReadWriteHeaderFailsBadHeader(t *testing.T) {
	var file bytes.Buffer

	if err := WriteSTETHeader(&file, 42); err != nil {
		t.Fatalf("writeHeader(file, 42) returned error: %v", err)
	}

	// Seek forward one byte, which should mess up the header read.
	file.ReadByte()

	if _, err := ReadSTETHeader(&file); err == nil {
		t.Fatalf("readHeader(file) = %v, want invalid header error", err)
	}
}

func TestReadWriteHeaderFailsBadMagicString(t *testing.T) {
	var file bytes.Buffer

	if err := WriteSTETHeader(&file, 42); err != nil {
		t.Fatalf("writeHeader(file, 42) returned error: %v", err)
	}

	// Replace the first byte of the magic string with a null byte.
	header := file.Bytes()
	header[0] = 0x00
	headerBuf := bytes.NewBuffer(header)

	if _, err := ReadSTETHeader(headerBuf); err == nil {
		t.Fatalf("readHeader(file) = %v, want bad magic string error", err)
	}
}

func TestMetadataSerialize(t *testing.T) {
	testShare := []byte("I am a wrapped share.")
	testHashedShare := sha256.Sum256(testShare)

	wrapped := &configpb.WrappedShare{
		Share: append(testShare, byte('E')),
		Hash:  testHashedShare[:],
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
		if _, err := MetadataToAAD(md); err != nil {
			t.Errorf("Serialization failed: %v", err)
		}
	}
}

func TestMetadataSerializeAvoidsCollisions(t *testing.T) {
	testShare := []byte("I am a wrapped share.")
	testHashedShare := sha256.Sum256(testShare)

	spacesHash := bytes.Repeat([]byte{' '}, 32)

	wrapped := &configpb.WrappedShare{
		Share: testShare,
		Hash:  testHashedShare[:],
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
		serialized0, err := MetadataToAAD(tc[0])
		if err != nil {
			t.Fatalf("Error serializing metadata %v: %v", tc[0], err)
		}

		serialized1, err := MetadataToAAD(tc[1])
		if err != nil {
			t.Fatalf("Error serializing metadata %v: %v", tc[1], err)
		}

		if bytes.Equal(serialized0, serialized1) {
			t.Errorf("Expected serializations to be unequal. \nmd0 = {%v}\nmd1 = {%v}", tc[0], tc[1])
		}
	}
}
