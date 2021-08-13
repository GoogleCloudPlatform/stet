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

	ciphertext, err := aeadEncrypt(testDEK, testPT, testAAD)
	if err != nil {
		t.Fatalf("AeadEncrypt failed with error %v", err)
	}

	plaintext, err := aeadDecrypt(testDEK, ciphertext, testAAD)
	if err != nil {
		t.Fatalf("AeadDecrypt failed with error %v", err)
	}

	if !bytes.Equal(plaintext, testPT) {
		t.Errorf("AeadEncrypt and AeadDecrypt workflow does not restore original plaintext. Got %v, want %v", plaintext, testPT)
	}
}

func TestAeadDecryptFailsForInvalidCipherText(t *testing.T) {
	testDEK := NewDEK()
	testCT := []byte("This is some random invalid ciphertext.")
	testAAD := []byte("AAD for testing only.")

	_, err := aeadDecrypt(testDEK, testCT, testAAD)
	if err == nil { // if no error
		t.Error("aeadDecrypt expected to return error but did not.")
	}
}

func TestAeadDecryptFailsForNonmatchingAAD(t *testing.T) {
	testDEK := NewDEK()
	testPT := []byte("Plaintext for testing only.")
	testEncryptAAD := []byte("AAD for encrypt testing only.")
	testDecryptAAD := []byte("AAD for decrypt testing only.")

	ciphertext, err := aeadEncrypt(testDEK, testPT, testEncryptAAD)
	if err != nil {
		t.Fatalf("AeadEncrypt failed with error %v", err)
	}

	_, err = aeadDecrypt(testDEK, ciphertext, testDecryptAAD)
	if err == nil {
		t.Error("AeadDecrypt expected to return error due to mismatched AAD")
	}
}
