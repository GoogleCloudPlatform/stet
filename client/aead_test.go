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
)

func TestAeadEncryptAndAeadDecrypt(t *testing.T) {
	testDEK := NewDEK()
	testPT := []byte("Plaintext for testing only.")
	testAAD := []byte("AAD for testing only.")

	encryptInput := bytes.NewReader(testPT)

	var ciphertext []byte
	encryptOutput := bytes.NewBuffer(ciphertext)

	if err := aeadEncrypt(testDEK, encryptInput, encryptOutput, testAAD); err != nil {
		t.Fatalf("AeadEncrypt failed with error %v", err)
	}

	decryptInput := encryptOutput

	var plaintext []byte
	decryptOutput := bytes.NewBuffer(plaintext)

	if err := aeadDecrypt(testDEK, decryptInput, decryptOutput, testAAD); err != nil {
		t.Fatalf("AeadDecrypt failed with error %v", err)
	}

	if !bytes.Equal(decryptOutput.Bytes(), testPT) {
		t.Errorf("AeadEncrypt and AeadDecrypt workflow does not restore original plaintext. Got %v, want %v", plaintext, testPT)
	}
}

func TestAeadDecryptFailsForInvalidCipherText(t *testing.T) {
	testDEK := NewDEK()
	testCT := []byte("This is some random invalid ciphertext.")
	testAAD := []byte("AAD for testing only.")

	input := bytes.NewReader(testCT)

	var plaintext []byte
	output := bytes.NewBuffer(plaintext)

	if err := aeadDecrypt(testDEK, input, output, testAAD); err == nil { // if no error
		t.Error("aeadDecrypt expected to return error but did not.")
	}
}

func TestAeadDecryptFailsForNonmatchingAAD(t *testing.T) {
	testDEK := NewDEK()
	testPT := []byte("Plaintext for testing only.")
	testEncryptAAD := []byte("AAD for encrypt testing only.")
	testDecryptAAD := []byte("AAD for decrypt testing only.")

	encryptInput := bytes.NewReader(testPT)

	var ciphertext []byte
	encryptOutput := bytes.NewBuffer(ciphertext)

	if err := aeadEncrypt(testDEK, encryptInput, encryptOutput, testEncryptAAD); err != nil {
		t.Fatalf("AeadEncrypt failed with error %v", err)
	}

	decryptInput := encryptOutput

	var plaintext []byte
	decryptOutput := bytes.NewBuffer(plaintext)

	if err := aeadDecrypt(testDEK, decryptInput, decryptOutput, testDecryptAAD); err == nil {
		t.Error("AeadDecrypt expected to return error due to mismatched AAD")
	}
}
