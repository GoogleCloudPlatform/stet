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

package transportshim

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestShimSend(t *testing.T) {
	shim := NewTransportShim()
	fromServerMsg := "Server To Client Test Msg"

	go func() {
		_, err := shim.Write([]byte(fromServerMsg))
		if err != nil {
			t.Log("Expected Write to channel to succeed")
		}
	}()

	// DrainSendBuf will block until data becomes available
	if string(shim.DrainSendBuf()) != fromServerMsg {
		t.Fatalf("Expected server msg to match")
	}
}

// Test writing a large number of bytes to `sendBuf` in chunks and reading
// reading them off via DrainSendBuf, making use of the length suggestion.
func TestShimLargeWrite(t *testing.T) {
	// 2^15 bytes is around the size of a full vTPM attestation.
	attestationLen := 32768

	// Simulate each record having an overhead of 12 bytes.
	overhead := 12
	sliceLen := 8192

	shim := NewTransportShim()
	want := make([]byte, attestationLen)
	rand.Read(want)

	go func() {
		for i := 0; i < 4; i++ {
			// Simulate the TLS implementation writing to the shim by prepending
			// a 12 byte empty "header" to each call to shim.Write(). This is a
			// substitute for actually instantiating a crypto/tls instance and
			// writing to it.
			header := make([]byte, overhead)
			write := want[i*sliceLen : (i+1)*sliceLen]
			if _, err := shim.Write(append(header, write...)); err != nil {
				t.Log("Expected Write to channel to succeed")
			}
		}
	}()

	res := shim.DrainSendBuf()
	var got []byte
	recordLen := sliceLen + overhead

	// Take the "headers" off of the "records" read back.
	for i := 0; i < 4; i++ {
		got = append(got, res[i*recordLen+overhead:(i+1)*recordLen]...)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("Received data did not match written data: got %v, want %v", got, want)
	}
}

func TestShimReceive(t *testing.T) {
	shim := NewTransportShim()

	fromClientMsg := "Client to Server Test Msg"

	shim.QueueReceiveBuf([]byte(fromClientMsg))

	dataFromClient := make([]byte, len(fromClientMsg))

	// will block until data is available
	_, err := shim.Read(dataFromClient)

	if err != nil {
		t.Fatalf("Expected Write to channel to succeed")
	}

	if fromClientMsg != string(dataFromClient) {
		t.Fatalf("Expected server msg to match")
	}

}

// Test enqueuing bytes into receiveBuf and Read()-ing them off in chunks.
func TestShimLargeReceive(t *testing.T) {
	shim := NewTransportShim()
	want := make([]byte, 32768)
	rand.Read(want)

	shim.QueueReceiveBuf(want)

	var got []byte

	for i := 0; i < 4; i++ {
		buf := make([]byte, 8192)

		if _, err := shim.Read(buf); err != nil {
			t.Fatalf("Failed to Read() from transport shim: %v", err.Error())
		}

		got = append(got, buf...)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("Queued data did not match received data: got %v, want %v", got, want)
	}
}
